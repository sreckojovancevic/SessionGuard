using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SessionGuard.E2E;

/// <summary>
/// A service that has never heard of SessionGuard: it hands out bearer session
/// cookies and accepts them back from whoever presents them. Everything the
/// guard does is done without its cooperation.
/// </summary>
public sealed class MockService : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2 _leaf;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, string> _sessions = new();
    private Task? _loop;

    public X509Certificate2 RootCertificate { get; }
    public int Port { get; }
    public string Host { get; }

    public MockService(params string[] hosts)
    {
        Host = hosts[0];
        (RootCertificate, _leaf) = MakeChain(hosts);
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    public void Start() => _loop = Task.Run(AcceptAsync);

    private static (X509Certificate2 root, X509Certificate2 leaf) MakeChain(string[] hosts)
    {
        string host = hosts[0];
        using var caKey = RSA.Create(2048);
        // Unique subject per instance: several roots sharing one subject name
        // make chain building pick the wrong one, and the signature check then
        // fails with a generic "certificate rejected".
        var caReq = new CertificateRequest($"CN=Mock Service Root for {host}", caKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        caReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        using var caTmp = caReq.CreateSelfSigned(now.AddDays(-1), now.AddYears(2));
        var ca = new X509Certificate2(caTmp.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.Exportable);

        using var leafKey = RSA.Create(2048);
        var req = new CertificateRequest($"CN={host}", leafKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (var h in hosts) san.AddDnsName(h);
        req.CertificateExtensions.Add(san.Build());

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        using var signed = req.Create(ca, now.AddDays(-1), now.AddDays(200), serial);
        using var withKey = signed.CopyWithPrivateKey(leafKey);
        var leaf = new X509Certificate2(withKey.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.Exportable);

        var rootPublic = new X509Certificate2(ca.Export(X509ContentType.Cert));
        return (rootPublic, leaf);
    }

    private async Task AcceptAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
            catch { break; }
            _ = Task.Run(() => ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            await using var net = client.GetStream();
            var ssl = new SslStream(net, false);
            try
            {
                await ssl.AuthenticateAsServerAsync(_leaf, false,
                    System.Security.Authentication.SslProtocols.Tls12 |
                    System.Security.Authentication.SslProtocols.Tls13, false);

                while (true)
                {
                    var req = await ReadRequestAsync(ssl);
                    if (req is null) break;
                    var (method, path, cookies) = req.Value;
                    byte[] reply = Route(method, path, cookies);
                    await ssl.WriteAsync(reply);
                    await ssl.FlushAsync();
                }
            }
            catch { }
            finally { await ssl.DisposeAsync(); }
        }
    }

    public int LastBodyLength { get; private set; }
    public bool LastBodyHadMarker { get; private set; }
    public const string BodyMarker = "Cookie: stolen=1";

    private async Task<(string method, string path, string cookies)?>
        ReadRequestAsync(Stream s)
    {
        var buf = new byte[16384];
        int have = 0;
        int headEnd = -1;
        while (headEnd < 0)
        {
            int n = await s.ReadAsync(buf.AsMemory(have));
            if (n == 0) return null;
            have += n;
            for (int i = 0; i + 3 < have; i++)
                if (buf[i] == 13 && buf[i + 1] == 10 && buf[i + 2] == 13 && buf[i + 3] == 10)
                { headEnd = i; break; }
            if (have == buf.Length) return null;
        }

        string head = Encoding.ASCII.GetString(buf, 0, headEnd);
        var lines = head.Split("\r\n");
        var start = lines[0].Split(' ');
        string method = start[0], path = start.Length > 1 ? start[1] : "/";
        string cookies = "";
        int contentLength = 0;
        foreach (var line in lines.Skip(1))
        {
            int c = line.IndexOf(':');
            if (c < 0) continue;
            string name = line[..c].Trim(), value = line[(c + 1)..].Trim();
            if (name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) cookies = value;
            else if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                int.TryParse(value, out contentLength);
        }

        var body = new MemoryStream();
        int bodyHave = have - (headEnd + 4);
        if (bodyHave > 0) body.Write(buf, headEnd + 4, Math.Min(bodyHave, contentLength));
        while (bodyHave < contentLength)
        {
            int n = await s.ReadAsync(buf.AsMemory(0, Math.Min(buf.Length, contentLength - bodyHave)));
            if (n == 0) break;
            body.Write(buf, 0, n);
            bodyHave += n;
        }
        LastBodyLength = (int)body.Length;
        LastBodyHadMarker = Encoding.UTF8.GetString(body.ToArray()).Contains(BodyMarker);
        return (method, path, cookies);
    }

    private byte[] Route(string method, string path, string cookies)
    {
        string? sid = null;
        foreach (var part in cookies.Split(';'))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 && kv[0].Trim() == "sessionid") sid = kv[1].Trim();
        }

        if (method == "POST" && path == "/login")
        {
            string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            _sessions[id] = "srecko";
            return Build(200, "{\"ok\":true,\"user\":\"srecko\"}", new[]
            {
                $"sessionid={id}; Path=/; HttpOnly; Secure; SameSite=Lax",
                $"csrf={Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}; Path=/; Secure",
            });
        }

        if (path == "/me")
        {
            if (sid is not null && _sessions.TryRemove(sid, out string? user))
            {
                // Rolling session: each use retires the old value, so a copy
                // taken a moment ago is already dead.
                string next = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
                _sessions[next] = user;
                return Build(200, $"{{\"user\":\"{user}\"}}", new[]
                {
                    $"sessionid={next}; Path=/; HttpOnly; Secure; SameSite=Lax",
                });
            }
            return Build(401, "{\"error\":\"no valid session\"}", Array.Empty<string>());
        }

        if (path == "/domainlogin")
        {
            // The shape a multi-subdomain site actually uses.
            string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            return Build(200, "{\"ok\":true}", new[]
            {
                $"sid={id}; Domain=.sg.test; Path=/; HttpOnly; Secure",
                $"local={id}; Path=/; HttpOnly; Secure",
            });
        }

        if (path == "/badscope")
        {
            // A host claiming a scope it has no business claiming.
            return Build(200, "{\"ok\":true}", new[]
            {
                "evil=1; Domain=elsewhere.test; Path=/",
            });
        }

        if (path == "/logout")
        {
            if (sid is not null) _sessions.TryRemove(sid, out _);
            return Build(200, "{\"ok\":true}", new[]
            {
                "sessionid=; Path=/; Max-Age=0; HttpOnly; Secure",
            });
        }

        if (path == "/adminsetup")
        {
            return Build(200, "{\"ok\":true}", new[]
            {
                $"adm={Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}; Path=/admin; Secure",
            });
        }

        if (path == "/cookies" || path == "/admin/cookies")
        {
            var names = cookies.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(c => c.Split('=', 2)[0].Trim())
                .Where(n => n.Length > 0)
                .OrderBy(n => n, StringComparer.Ordinal);
            return Build(200, "{\"names\":\"" + string.Join(",", names) + "\"}",
                         Array.Empty<string>());
        }

        if (path == "/echo")
        {
            // Reports what actually arrived, so the test can prove that header
            // editing never reached into the request body.
            return Build(200,
                $"{{\"len\":{LastBodyLength},\"marker\":{(LastBodyHadMarker ? "true" : "false")}}}",
                Array.Empty<string>());
        }

        if (path == "/bulk")
        {
            // Chunked reply larger than any single socket read, to exercise framing.
            var sb = new StringBuilder();
            for (int i = 0; i < 4000; i++) sb.Append($"line {i:D5} ....................\n");
            return BuildChunked(sb.ToString());
        }

        return Build(404, "{\"error\":\"not found\"}", Array.Empty<string>());
    }

    private static byte[] Build(int status, string body, string[] setCookies)
    {
        var sb = new StringBuilder();
        sb.Append($"HTTP/1.1 {status} {(status == 200 ? "OK" : status == 401 ? "Unauthorized" : "Not Found")}\r\n");
        sb.Append("Content-Type: application/json\r\n");
        foreach (var c in setCookies) sb.Append($"Set-Cookie: {c}\r\n");
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        sb.Append($"Content-Length: {bodyBytes.Length}\r\n\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString()).Concat(bodyBytes).ToArray();
    }

    private static byte[] BuildChunked(string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var ms = new MemoryStream();
        void W(string s) { var b = Encoding.ASCII.GetBytes(s); ms.Write(b, 0, b.Length); }
        W("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n");
        const int chunk = 4096;
        for (int off = 0; off < bytes.Length; off += chunk)
        {
            int n = Math.Min(chunk, bytes.Length - off);
            W($"{n:x}\r\n");
            ms.Write(bytes, off, n);
            W("\r\n");
        }
        W("0\r\n\r\n");
        return ms.ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        if (_loop is not null) { try { await _loop; } catch { } }
        _cts.Dispose();
    }
}
