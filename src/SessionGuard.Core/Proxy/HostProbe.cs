using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace SessionGuard.Core.Proxy;

/// <summary>
/// What one TLS connection to a candidate host reveals.
///
/// Deliberately phrased as observations. "HTTP/1.1 accepted" is something that
/// was checked; "this site will work" is not, and the difference matters —
/// see <see cref="Caveat"/>.
/// </summary>
public sealed record ProbeResult(
    string Host,
    bool Resolved,
    bool Connected,
    bool CertificateAccepted,
    bool Http11Accepted,
    string Detail)
{
    public bool CanIntercept => Connected && CertificateAccepted && Http11Accepted;

    public string Summary => !Resolved ? $"{Host} — name does not resolve"
        : !Connected ? $"{Host} — cannot connect ({Detail})"
        : !Http11Accepted ? $"{Host} — requires HTTP/2, cannot be protected yet"
        : !CertificateAccepted ? $"{Host} — certificate not accepted ({Detail})"
        : $"{Host} — HTTP/1.1 accepted";

    /// <summary>
    /// What the probe cannot see. Worth showing next to a positive result so it
    /// is not read as a guarantee.
    /// </summary>
    public const string Caveat =
        "A positive result covers this hostname only. It cannot tell you about " +
        "subdomains reached later, about certificate pinning (which the client " +
        "enforces, so a handshake reveals nothing), or about a site that keeps " +
        "its session in localStorage rather than cookies.";
}

/// <summary>
/// Checks a host before it is added to the protected list, so a site that
/// cannot be intercepted is reported instead of silently breaking later.
/// </summary>
public static class HostProbe
{
    public static async Task<ProbeResult> RunAsync(
        string host, int port = 443,
        RemoteCertificateValidationCallback? validation = null,
        TimeSpan? timeout = null,
        CancellationToken token = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(8));

        bool certAccepted = false;
        using var tcp = new TcpClient();

        try
        {
            await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            bool resolved = ex.SocketErrorCode != SocketError.HostNotFound;
            return new ProbeResult(host, resolved, false, false, false, ex.SocketErrorCode.ToString());
        }
        catch (OperationCanceledException)
        {
            return new ProbeResult(host, true, false, false, false, "timed out");
        }
        catch (Exception ex)
        {
            return new ProbeResult(host, true, false, false, false, ex.GetType().Name);
        }

        var ssl = new SslStream(tcp.GetStream(), false, (s, cert, chain, errors) =>
        {
            // Record what the real check would say, but do not fail the probe on
            // it: the point here is the protocol answer. A certificate problem is
            // reported separately, since the proxy validates upstream and would
            // otherwise surface it later as if it were a bug in SessionGuard.
            certAccepted = validation?.Invoke(s, cert, chain, errors)
                           ?? errors == SslPolicyErrors.None;
            return true;
        });

        try
        {
            // Offer HTTP/1.1 and nothing else. A host that insists on HTTP/2
            // refuses the handshake here rather than mid-browse.
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = new() { SslApplicationProtocol.Http11 },
            }, cts.Token).ConfigureAwait(false);

            // Empty means the peer sent no ALPN extension, which conventionally
            // means HTTP/1.1 — that is fine.
            var chosen = ssl.NegotiatedApplicationProtocol;
            bool ok = chosen == default || chosen == SslApplicationProtocol.Http11;

            return new ProbeResult(host, true, true, certAccepted, ok,
                ok ? "http/1.1" : chosen.ToString());
        }
        catch (AuthenticationException ex)
        {
            // The usual shape of "this host will not speak HTTP/1.1".
            return new ProbeResult(host, true, true, certAccepted, false, Innermost(ex));
        }
        catch (OperationCanceledException)
        {
            return new ProbeResult(host, true, true, certAccepted, false, "timed out");
        }
        catch (Exception ex)
        {
            return new ProbeResult(host, true, true, certAccepted, false, Innermost(ex));
        }
        finally
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static string Innermost(Exception ex)
    {
        var e = ex;
        while (e.InnerException is not null) e = e.InnerException;
        string m = e.Message.Replace('\n', ' ').Replace('\r', ' ');
        return m.Length > 120 ? m[..120] : m;
    }
}
