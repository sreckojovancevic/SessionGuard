using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using SessionGuard.Core.Authz;
using SessionGuard.Core.Http;
using SessionGuard.Core.Pki;
using SessionGuard.Core.Vault;

namespace SessionGuard.Core.Proxy;

public sealed record ProxyOptions(
    int ListenPort,
    IReadOnlyCollection<string> ProtectedHosts,
    RemoteCertificateValidationCallback? UpstreamValidation = null);

public sealed class ProxyEvent
{
    public required string Kind { get; init; }
    public string? Host { get; init; }
    public string? Detail { get; init; }
    public override string ToString() =>
        $"{Kind,-22} {Host,-24} {Detail}";
}

/// <summary>
/// The interception proxy.
///
/// Hosts that are not protected get an untouched CONNECT tunnel. Protected
/// hosts are TLS-terminated so that, per request:
///   - guarded cookie names the client sent are dropped;
///   - the vault's cookies are attached only if this caller is authorized now;
///   - Set-Cookie in the reply is captured into the vault and removed, so the
///     browser profile never stores the session.
///
/// Authorization gates the cookie, never the connection. An unauthorized
/// caller still reaches the site and simply gets no session — which is what
/// makes 401 the observable outcome instead of a dead network.
/// </summary>
public sealed class ProxyEngine : IAsyncDisposable
{
    private static ReadOnlySpan<byte> CookieHeader => "Cookie"u8;
    private static ReadOnlySpan<byte> SetCookieHeader => "Set-Cookie"u8;
    private static ReadOnlySpan<byte> ConnectionHeader => "Connection"u8;

    private static readonly byte[] ConnectEstablished =
        "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
    private static readonly byte[] BadRequest =
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"u8.ToArray();
    private static readonly byte[] BadGateway =
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"u8.ToArray();

    private readonly ProxyOptions _options;
    private readonly SessionVault _vault;
    private readonly PeerAuthorizer _authorizer;
    private readonly CertificateAuthority _ca;
    private readonly ProtectedHostSet _protected;
    private readonly TcpListener _listener;
    private readonly InterceptionCache _uninterceptable;

    /// <summary>host\name of cookies the browser has been asked to delete.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _evicted = new();

    /// <summary>host\name of every cookie this engine has seen a Set-Cookie for.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _seen = new();

    /// <summary>host\name already reported as never captured, so it is said once.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _reportedUnseen = new();

    /// <summary>
    /// Cookies a protected host receives that this engine never issued and never
    /// captured — the browser has them from before the guard was watching.
    /// </summary>
    public IReadOnlyCollection<string> NeverCaptured => _reportedUnseen.Keys.ToArray();
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public ProxyEngine(ProxyOptions options, SessionVault vault,
                       PeerAuthorizer authorizer, CertificateAuthority ca)
    {
        _options = options;
        _vault = vault;
        _authorizer = authorizer;
        _ca = ca;
        _protected = new ProtectedHostSet(options.ProtectedHosts);
        _uninterceptable = new InterceptionCache();
        _listener = new TcpListener(IPAddress.Loopback, options.ListenPort);
    }

    public event Action<ProxyEvent>? Observed;

    /// <summary>Protected hosts currently being passed through unprotected.</summary>
    public InterceptionCache Skipped => _uninterceptable;
    public int ListenPort { get; private set; }
    public bool IsRunning => _acceptLoop is not null;

    private void Emit(string kind, string? host = null, string? detail = null) =>
        Observed?.Invoke(new ProxyEvent { Kind = kind, Host = host, Detail = detail });

    public void Start()
    {
        if (_acceptLoop is not null) return;
        _cts = new CancellationTokenSource();
        _listener.Start();
        ListenPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        Emit("listening", detail: $"127.0.0.1:{ListenPort}");
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is null) return;
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { }
        }
        _acceptLoop = null;
        _cts.Dispose();
        _cts = null;
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { break; }

            _ = Task.Run(async () =>
            {
                try { await HandleAsync(client, token).ConfigureAwait(false); }
                catch (Exception ex) { Emit("connection_error", detail: ex.GetType().Name); }
                finally { client.Dispose(); }
            }, CancellationToken.None);
        }
    }

    // ------------------------------------------------------------ handling

    private async Task HandleAsync(TcpClient client, CancellationToken token)
    {
        var clientEndpoint = (IPEndPoint)client.Client.RemoteEndPoint!;
        await using var clientStream = client.GetStream();

        using var first = await HttpReader.ReadAsync(clientStream, false, false, token)
                                          .ConfigureAwait(false);
        if (first is null) return;

        if (!first.MethodIs("CONNECT"u8))
        {
            // Plain HTTP through a system proxy is an absolute-URI request.
            // Answering nothing here would black-hole all non-TLS traffic.
            await ForwardPlainAsync(first, clientStream, token).ConfigureAwait(false);
            return;
        }

        if (!TryParseAuthority(first.Head.StartLine, out string host, out int port))
        {
            await WriteAsync(clientStream, BadRequest, token).ConfigureAwait(false);
            return;
        }

        await WriteAsync(clientStream, ConnectEstablished, token).ConfigureAwait(false);

        if (!_protected.Matches(host))
        {
            Emit("tunnel", host);
            await TunnelAsync(clientStream, host, port, token).ConfigureAwait(false);
            return;
        }

        if (_uninterceptable.ShouldBypass(host))
        {
            // Known not to work — do not spend a failed request rediscovering it.
            Emit("tunnel_unprotected", host, "previously found uninterceptable");
            await TunnelAsync(clientStream, host, port, token).ConfigureAwait(false);
            return;
        }

        Emit("intercept", host, $"CONNECT {port}");
        await InterceptAsync(clientStream, host, port, clientEndpoint, token)
            .ConfigureAwait(false);
    }

    private static bool TryParseAuthority(ReadOnlySpan<byte> startLine,
                                          out string host, out int port)
    {
        host = string.Empty;
        port = 443;
        int sp1 = startLine.IndexOf((byte)' ');
        if (sp1 < 0) return false;
        var rest = startLine.Slice(sp1 + 1);
        int sp2 = rest.IndexOf((byte)' ');
        var authority = sp2 < 0 ? rest : rest.Slice(0, sp2);
        if (authority.IsEmpty) return false;

        int colon = authority.LastIndexOf((byte)':');
        if (colon > 0)
        {
            host = Encoding.ASCII.GetString(authority.Slice(0, colon));
            port = 0;
            foreach (byte b in authority.Slice(colon + 1))
            {
                if (b < '0' || b > '9') return false;
                port = port * 10 + (b - '0');
            }
            if (port == 0) return false;
        }
        else
        {
            host = Encoding.ASCII.GetString(authority);
        }
        return host.Length > 0;
    }

    private static async Task WriteAsync(Stream s, ReadOnlyMemory<byte> data,
                                         CancellationToken token)
    {
        await s.WriteAsync(data, token).ConfigureAwait(false);
        await s.FlushAsync(token).ConfigureAwait(false);
    }

    /// <summary>Byte-for-byte relay, shutting both directions when either ends.</summary>
    private async Task TunnelAsync(Stream clientStream, string host, int port,
                                   CancellationToken token)
    {
        using var remote = new TcpClient();
        try { await remote.ConnectAsync(host, port, token).ConfigureAwait(false); }
        catch { return; }

        await using var remoteStream = remote.GetStream();
        using var link = CancellationTokenSource.CreateLinkedTokenSource(token);

        async Task Pump(Stream from, Stream to)
        {
            try { await from.CopyToAsync(to, 81920, link.Token).ConfigureAwait(false); }
            catch { }
            finally { link.Cancel(); }   // one side closing tears down the other
        }

        var a = Pump(clientStream, remoteStream);
        var b = Pump(remoteStream, clientStream);
        await Task.WhenAll(a, b).ConfigureAwait(false);
    }

    private async Task ForwardPlainAsync(HttpMessage request, Stream clientStream,
                                         CancellationToken token)
    {
        // Not a protected path: no interception, just relay so the system proxy
        // does not break plain HTTP.
        if (!TryParseHostHeader(request, out string host, out int port))
        {
            await WriteAsync(clientStream, BadRequest, token).ConfigureAwait(false);
            return;
        }
        using var remote = new TcpClient();
        try { await remote.ConnectAsync(host, port, token).ConfigureAwait(false); }
        catch
        {
            await WriteAsync(clientStream, BadGateway, token).ConfigureAwait(false);
            return;
        }
        await using var remoteStream = remote.GetStream();
        byte[] wire = request.Serialize(out int len);
        try { await WriteAsync(remoteStream, wire.AsMemory(0, len), token).ConfigureAwait(false); }
        finally { ArrayPool<byte>.Shared.Return(wire); }

        using var response = await HttpReader.ReadAsync(remoteStream, true, false, token)
                                             .ConfigureAwait(false);
        if (response is null) return;
        byte[] outWire = response.Serialize(out int outLen);
        try { await WriteAsync(clientStream, outWire.AsMemory(0, outLen), token).ConfigureAwait(false); }
        finally { ArrayPool<byte>.Shared.Return(outWire); }
    }

    private static bool TryParseHostHeader(HttpMessage msg, out string host, out int port)
    {
        host = string.Empty;
        port = 80;
        if (!msg.Head.TryGetValue("Host"u8, out int s, out int l)) return false;
        var v = msg.Head.Span.Slice(s, l);
        int colon = v.LastIndexOf((byte)':');
        if (colon > 0)
        {
            host = Encoding.ASCII.GetString(v.Slice(0, colon));
            port = 0;
            foreach (byte b in v.Slice(colon + 1))
            {
                if (b < '0' || b > '9') return false;
                port = port * 10 + (b - '0');
            }
        }
        else host = Encoding.ASCII.GetString(v);
        return host.Length > 0;
    }

    // -------------------------------------------------------- interception

    /// <summary>
    /// Terminate TLS with the browser and relay HTTP for a protected host.
    ///
    /// Upstream is established FIRST, deliberately. Interception and protection
    /// are the same act: once the browser has completed a TLS handshake against
    /// our leaf certificate there is no way back to a plain tunnel on that
    /// connection, so discovering upstream trouble afterwards means a failed
    /// request the user sees.
    ///
    /// Doing upstream first — and reading nothing from the client until it is
    /// settled — leaves the browser's ClientHello untouched in the socket
    /// buffer. A host that turns out to refuse HTTP/1.1 can then be relayed
    /// blind from its very first byte, and the browser never learns that
    /// anything was reconsidered.
    /// </summary>
    private async Task InterceptAsync(Stream clientStream, string host, int port,
                                      IPEndPoint clientEndpoint, CancellationToken token)
    {
        var remote = new TcpClient();
        SslStream? sslRemote = null;
        try
        {
            try
            {
                await remote.ConnectAsync(host, port, token).ConfigureAwait(false);

                // Upstream validation stays ON. Terminating the browser's TLS
                // and then trusting any certificate would put a MITM hole
                // exactly where the session is most exposed.
                sslRemote = new SslStream(remote.GetStream(), false,
                    _options.UpstreamValidation ??
                    ((_, _, _, errors) => errors == SslPolicyErrors.None));

                await sslRemote.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    // This proxy speaks HTTP/1.1 only; say so, and find out now
                    // rather than after committing to the browser.
                    ApplicationProtocols = new() { SslApplicationProtocol.Http11 },
                }, token).ConfigureAwait(false);

                var chosen = sslRemote.NegotiatedApplicationProtocol;
                Emit("upstream_tls", host,
                    $"protocol={sslRemote.SslProtocol}; alpn={(chosen == default ? "none" : chosen.ToString())}");
                if (chosen != default && chosen != SslApplicationProtocol.Http11)
                    throw new AuthenticationException(
                        $"upstream selected {chosen}, which this proxy cannot parse");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Fall back to a blind tunnel. Nothing has been read from the
                // client yet, so this costs no failed request.
                string reason = ex is AuthenticationException
                    ? "requires HTTP/2 or refused our TLS"
                    : $"{ex.GetType().Name}: {Describe(ex)}";
                _uninterceptable.Mark(host, reason);
                Emit("interception_unavailable", host, reason + " — passing through UNPROTECTED");

                if (sslRemote is not null)
                {
                    await sslRemote.DisposeAsync().ConfigureAwait(false);
                    sslRemote = null;
                }
                remote.Dispose();
                remote = new TcpClient();

                await TunnelAsync(clientStream, host, port, token).ConfigureAwait(false);
                return;
            }

            var leaf = _ca.LeafFor(host);
            var sslClient = new SslStream(clientStream, leaveInnerStreamOpen: false);
            try
            {
                await sslClient.AuthenticateAsServerAsync(
                    leaf, clientCertificateRequired: false,
                    enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                    checkCertificateRevocation: false).ConfigureAwait(false);
                Emit("client_tls", host, $"protocol={sslClient.SslProtocol}");

                await PumpHttpAsync(sslClient, sslRemote!, host, clientEndpoint, token)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Emit("client_tls_failed", host, $"{ex.GetType().Name}: {Describe(ex)}");
            }
            finally
            {
                await sslClient.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            if (sslRemote is not null) await sslRemote.DisposeAsync().ConfigureAwait(false);
            remote.Dispose();
        }
    }

    private async Task PumpHttpAsync(SslStream client, SslStream remote, string host,
                                     IPEndPoint clientEndpoint, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            using var request = await HttpReader.ReadAsync(client, false, false, token)
                                                .ConfigureAwait(false);
            if (request is null) return;

            bool isHead = request.MethodIs("HEAD"u8);
            bool authorized = _authorizer.Authorize(clientEndpoint, ListenPort, out string reason);
            string path = RequestPath(request);
            string method = RequestMethod(request);
            Emit("request", host,
                $"{method} {path}; authorized={authorized}; reason={reason}");

            var browserHeld = new List<string>();
            ApplyOutbound(request, host, path, authorized, reason, browserHeld);

            byte[] reqWire = request.Serialize(out int reqLen);
            try { await WriteAsync(remote, reqWire.AsMemory(0, reqLen), token).ConfigureAwait(false); }
            finally
            {
                CryptographicOperations.ZeroMemory(reqWire.AsSpan(0, reqLen));
                ArrayPool<byte>.Shared.Return(reqWire);
            }

            using var response = await HttpReader.ReadAsync(remote, true, isHead, token)
                                                 .ConfigureAwait(false);
            if (response is null) return;

            Emit("response", host,
                $"{ResponseStatus(response)}; closeDelimited={response.CloseDelimited}");
            ApplyInbound(response, host, browserHeld);

            byte[] resWire = response.Serialize(out int resLen);
            try { await WriteAsync(client, resWire.AsMemory(0, resLen), token).ConfigureAwait(false); }
            finally
            {
                CryptographicOperations.ZeroMemory(resWire.AsSpan(0, resLen));
                ArrayPool<byte>.Shared.Return(resWire);
            }

            if (response.CloseDelimited || WantsClose(request) || WantsClose(response)) return;
        }
    }

    /// <summary>Innermost message: the outer one is usually just "a call failed".</summary>
    private static string Describe(Exception ex)
    {
        var inner = ex;
        while (inner.InnerException is not null) inner = inner.InnerException;
        string m = inner.Message.Replace('\n', ' ').Replace('\r', ' ');
        return m.Length > 160 ? m[..160] : m;
    }

    private static bool WantsClose(HttpMessage msg)
    {
        if (!msg.Head.TryGetValue(ConnectionHeader, out int s, out int l)) return false;
        return CookieBytes.EqualsAsciiIgnoreCase(msg.Head.Span.Slice(s, l), "close"u8);
    }

    // -------------------------------------------------------------- policy

    /// <summary>
    /// Non-async so it can work on spans. Rebuilds the Cookie header keeping the
    /// site's unguarded cookies and dropping any guarded name the client sent,
    /// then attaches the vault's cookies when authorized.
    /// </summary>
    /// <summary>HTTP method without exposing a request target or body.</summary>
    private static string RequestMethod(HttpMessage request)
    {
        var sl = request.Head.StartLine;
        int sp = sl.IndexOf((byte)' ');
        return sp > 0 ? Encoding.ASCII.GetString(sl[..sp]) : "?";
    }

    /// <summary>HTTP response status line without exposing headers or body.</summary>
    private static string ResponseStatus(HttpMessage response)
    {
        var sl = response.Head.StartLine;
        string text = Encoding.ASCII.GetString(sl);
        int first = text.IndexOf(' ');
        if (first < 0) return text;
        int second = text.IndexOf(' ', first + 1);
        return second < 0 ? text[first..] : text[(first + 1)..second];
    }

    /// <summary>Target path of a request, used for cookie Path matching.</summary>
    private static string RequestPath(HttpMessage request)
    {
        var sl = request.Head.StartLine;
        int sp1 = sl.IndexOf((byte)' ');
        if (sp1 < 0) return "/";
        var rest = sl.Slice(sp1 + 1);
        int sp2 = rest.IndexOf((byte)' ');
        var target = sp2 < 0 ? rest : rest.Slice(0, sp2);
        int q = target.IndexOf((byte)'?');
        if (q >= 0) target = target.Slice(0, q);
        return target.IsEmpty ? "/" : Encoding.ASCII.GetString(target);
    }

    private void ApplyOutbound(HttpMessage request, string host, string path,
                               bool authorized, string reason,
                               List<string> browserHeld)
    {
        var kept = new List<byte[]>();
        if (request.Head.TryGetValue(CookieHeader, out int cs, out int cl))
        {
            var value = request.Head.Span.Slice(cs, cl);
            var vault = _vault;
            string h = host;
            var dropped = new List<string>();
            var passed = new List<string>();
            var unseen = new List<string>();

            CookieBytes.ForEachRequestCookie(value, (name, val) =>
            {
                if (vault.IsGuarded(h, name))
                {
                    dropped.Add(Encoding.ASCII.GetString(name));
                    return;
                }
                var pair = new byte[name.Length + 1 + val.Length];
                name.CopyTo(pair);
                pair[name.Length] = (byte)'=';
                val.CopyTo(pair.AsSpan(name.Length + 1));
                kept.Add(pair);
                string kn = Encoding.ASCII.GetString(name);
                passed.Add(kn);

                // A cookie on a protected host that this engine has never seen a
                // Set-Cookie for. The browser did not get it through the guard,
                // so it was never a candidate for the vault — it has simply been
                // in the profile all along.
                //
                // The usual cause is signing in before the browser was actually
                // routed through the proxy: the whole login lands in the profile,
                // the guard then works perfectly on everything else, and the one
                // credential that matters is the one it never saw. The vault
                // looks healthy, the site works, and nothing is protected.
                if (!_seen.ContainsKey(h + "\n" + kn))
                    unseen.Add(kn);
            });

            if (passed.Count > 0)
                Emit("client_cookies", host, "passed=" + string.Join(",", passed));
            if (dropped.Count > 0)
            {
                Emit("stripped_client_cookie", host, string.Join(",", dropped));
                // The browser sending a guarded name means it still has its own
                // copy on disk. Stripping it here keeps the request correct but
                // leaves that copy exactly where an infostealer looks.
                browserHeld.AddRange(dropped);
            }

            var fresh = unseen.Where(n => _reportedUnseen.TryAdd(host + ":" + n, 0)).ToArray();
            if (fresh.Length > 0)
                Emit("never_captured", host,
                     string.Join(",", fresh) + " — the browser had these before the " +
                     "guard saw them, so they are NOT protected. If any is a session " +
                     "cookie, sign out and sign in again with the guard running.");
        }

        request.Head.RemoveAll(CookieHeader);

        byte[] vaultBuf = Array.Empty<byte>();
        int vaultLen = 0;
        bool haveVault = authorized &&
                         _vault.TryBuildCookieHeader(host, path, out vaultBuf, out vaultLen);

        try
        {
            int total = vaultLen;
            foreach (var p in kept) total += p.Length + 2;
            if (total == 0)
            {
                if (!authorized && _vault.CountForPath(host, path) > 0)
                    Emit("injection_denied", host, reason);
                return;
            }

            byte[] header = ArrayPool<byte>.Shared.Rent(total);
            try
            {
                int pos = 0;
                foreach (var p in kept)
                {
                    if (pos > 0) { header[pos++] = (byte)';'; header[pos++] = (byte)' '; }
                    p.CopyTo(header.AsSpan(pos));
                    pos += p.Length;
                }
                if (haveVault)
                {
                    if (pos > 0) { header[pos++] = (byte)';'; header[pos++] = (byte)' '; }
                    vaultBuf.AsSpan(0, vaultLen).CopyTo(header.AsSpan(pos));
                    pos += vaultLen;
                }
                request.Head.Append(CookieHeader, header.AsSpan(0, pos));

                if (haveVault)
                    Emit("injected", host, $"{_vault.CountForPath(host, path)} cookie(s) for {path}");
                else if (_vault.CountForPath(host, path) > 0)
                    Emit("injection_denied", host, reason);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(header.AsSpan(0, total));
                ArrayPool<byte>.Shared.Return(header);
            }
        }
        finally
        {
            if (haveVault) SessionVault.ReturnCookieHeader(vaultBuf, vaultLen);
            foreach (var p in kept) CryptographicOperations.ZeroMemory(p);
        }
    }

    /// <summary>
    /// Captures Set-Cookie into the vault and removes those it captured.
    ///
    /// A Set-Cookie with Max-Age=0 or a past Expires is the server revoking the
    /// cookie — a sign-out. That must delete the vault entry, not store an empty
    /// value that then gets replayed forever.
    ///
    /// <para><b>Script-readable cookies are left to the browser.</b> Taking a
    /// cookie away from the browser is invisible to the server but not to the
    /// page: any cookie without <c>HttpOnly</c> may be read, and often rewritten,
    /// by the site's own JavaScript. Anti-automation tokens are the common case —
    /// a script reads the token from <c>document.cookie</c>, signs the next
    /// request with it, and gets an empty string because the vault holds it. The
    /// server then sees a stream of badly signed requests, which is
    /// indistinguishable from an attack and answered like one.</para>
    ///
    /// <para>Nothing is lost by leaving them. A cookie the page can read is one
    /// that any script on that page can already exfiltrate, so vaulting it never
    /// closed the hole it appeared to close — it only broke the site. The
    /// property this project claims is about credentials the browser holds and
    /// script cannot touch, and <c>HttpOnly</c> is exactly the server's own
    /// marking of which ones those are.</para>
    /// </summary>
    private void ApplyInbound(HttpMessage response, string host,
                              IReadOnlyList<string>? browserHeld = null)
    {
        var head = response.Head;
        var captured = new List<string>();
        var revoked = new List<string>();
        var scriptReadable = new List<string>();
        var passThrough = new List<byte[]>();   // not vaulted, kept verbatim

        // Walk header lines; there may be several Set-Cookie headers.
        for (int i = 1; head.TryGetLine(i, out int ls, out int ll); i++)
        {
            var line = head.Span.Slice(ls, ll);
            int colon = line.IndexOf((byte)':');
            if (colon < 0) continue;
            if (!CookieBytes.EqualsAsciiIgnoreCase(line.Slice(0, colon), SetCookieHeader))
                continue;

            var value = line.Slice(colon + 1);
            int vs = 0;
            while (vs < value.Length && (value[vs] == ' ' || value[vs] == '\t')) vs++;
            value = value.Slice(vs);

            if (!CookieBytes.TryParseSetCookie(value, out Range nr, out Range vr)) continue;

            var name = value[nr];
            var attrs = CookieBytes.ParseAttributes(value);

            // Seen means "this engine watched the server issue it", whatever was
            // then decided about it — vaulted, left to the browser as
            // script-readable, or refused for its scope. All three are informed
            // outcomes. What matters for the warning below is the fourth case:
            // a cookie that was already in the profile and never passed here at
            // all, which no decision was ever made about.
            _seen.TryAdd(host + "\n" + Encoding.ASCII.GetString(name), 0);

            // Already-guarded names stay guarded even if this particular header
            // omits HttpOnly, so that a sign-out still reaches the vault: a
            // server is free to send different attributes when deleting.
            if (!attrs.HttpOnly && !_vault.IsGuarded(host, name))
            {
                passThrough.Add(value.ToArray());
                scriptReadable.Add(Encoding.ASCII.GetString(name));
                continue;
            }

            if (attrs.IsDeletion)
            {
                if (_vault.Remove(host, name, attrs.Domain))
                    revoked.Add(Encoding.ASCII.GetString(name));
                // The deletion header itself is dropped with the rest: the
                // browser holds no copy to delete.
                captured.Add(Encoding.ASCII.GetString(name));
            }
            else if (_vault.Store(host, name, value[vr], attrs.Domain, attrs.Path))
            {
                captured.Add(Encoding.ASCII.GetString(name));
            }
            else
            {
                // Refused scope. RemoveAll below strips every Set-Cookie, so the
                // line has to be carried over explicitly — otherwise refusing to
                // vault a cookie would silently destroy it instead of leaving it
                // to the browser.
                passThrough.Add(value.ToArray());
                Emit("scope_refused", host, Encoding.ASCII.GetString(name));
            }
        }

        if (scriptReadable.Count > 0)
            Emit("left_to_browser", host, string.Join(",", scriptReadable) + " (no HttpOnly)");

        // Only rewrite the header block if something was actually taken. When
        // every cookie passes through, the response must leave exactly as it
        // arrived — reordering headers for no reason is a difference the site
        // can observe and this proxy has no business creating.
        if (captured.Count > 0)
        {
            head.RemoveAll(SetCookieHeader);
            foreach (var raw in passThrough) head.Append(SetCookieHeader, raw);
            if (revoked.Count > 0) Emit("revoked", host, string.Join(",", revoked));
            var stored = captured.Except(revoked).ToArray();
            if (stored.Length > 0) Emit("vaulted", host, string.Join(",", stored));
        }

        if (browserHeld is { Count: > 0 }) EvictFromBrowser(response, host, browserHeld);
    }

    /// <summary>
    /// Asks the browser to delete its own copy of a cookie the vault now holds.
    ///
    /// <para>Capturing a cookie from <c>Set-Cookie</c> stops it ever reaching the
    /// browser — but only for cookies issued while the guard was running. One the
    /// browser already had, from before the guard was ever turned on, stays in
    /// the profile. Requests still go out with the vault's copy, because the
    /// browser's is stripped, so everything works and looks protected while
    /// <c>sessionid</c> sits on disk exactly where an infostealer reads it.</para>
    ///
    /// <para>The remedy is the mechanism the site itself would use: a
    /// <c>Set-Cookie</c> with <c>Max-Age=0</c>, addressed to the same name,
    /// domain and path the vault recorded. The scope has to match — a browser
    /// matches a deletion on all three, so a wrong domain does not delete the
    /// cookie, it creates a second empty one beside it.</para>
    ///
    /// <para>That failure is contained by accident of design: outbound stripping
    /// works by name, so a stray empty cookie of the same name is removed from
    /// the request as well and never reaches the site.</para>
    ///
    /// <para>Asked once per name per run. If the browser keeps sending it well
    /// afterwards the deletion did not take, and that is said rather than
    /// retried forever — an eviction that silently fails is the same silent hole
    /// this exists to close.</para>
    /// </summary>
    private void EvictFromBrowser(HttpMessage response, string host,
                                  IReadOnlyList<string> names)
    {
        var asked = new List<string>();
        var stubborn = new List<string>();

        foreach (string name in names)
        {
            string key = host + "\n" + name;
            var now = DateTime.UtcNow;

            if (_evicted.TryGetValue(key, out DateTime when))
            {
                // Still arriving a while after we asked: the browser did not
                // honour it, and repeating will not change that.
                if (now - when > TimeSpan.FromSeconds(30) &&
                    _evicted.TryUpdate(key, DateTime.MaxValue, when))
                    stubborn.Add(name);
                continue;
            }
            if (!_evicted.TryAdd(key, now)) continue;

            if (!_vault.TryGetScope(host, name, out string domain,
                                    out bool hostOnly, out string path))
                continue;

            // Both shapes, deliberately. A request header carries only names —
            // RFC 6265 sends no domain or path with them — so there is no way to
            // learn how the browser's own copy is scoped. A host-only cookie and
            // a domain cookie of the same name are different cookies and each
            // needs its own deletion, and the browser's copy may well predate
            // the vault's and be scoped differently.
            //
            // Sending both is safe here for a reason particular to this proxy:
            // if one of them lands where no cookie exists it creates an empty
            // one, and outbound stripping works by name, so that stray is
            // removed from the next request and never reaches the site.
            // Unconditionally both, including when the vault's own entry is
            // host-only: what the vault recorded describes the cookie the
            // *server* issued, and the copy still in the browser may be older
            // and shaped differently. Measured, not assumed — a host-only
            // deletion leaves a domain cookie of the same name untouched and
            // vice versa, in every client tested.
            Send($"{name}=; Max-Age=0; Path={path}; Secure; HttpOnly");
            Send($"{name}=; Max-Age=0; Path={path}; Domain={domain}; Secure; HttpOnly");
            if (!hostOnly && !domain.StartsWith('.'))
                Send($"{name}=; Max-Age=0; Path={path}; Domain=.{domain}; Secure; HttpOnly");
            if (path != "/")
            {
                Send($"{name}=; Max-Age=0; Path=/; Secure; HttpOnly");
                Send($"{name}=; Max-Age=0; Path=/; Domain={domain}; Secure; HttpOnly");
            }

            asked.Add(name);

            void Send(string attrs) =>
                response.Head.Append(SetCookieHeader, Encoding.ASCII.GetBytes(attrs));
        }

        if (asked.Count > 0)
            Emit("evict_from_browser", host,
                 string.Join(",", asked) + " — the vault holds these; asking the " +
                 "browser to drop its own copy");
        if (stubborn.Count > 0)
            Emit("eviction_ignored", host,
                 string.Join(",", stubborn) + " — still in the browser profile " +
                 "after the deletion was sent; these remain readable from disk");
    }
}
