using System;
using System.Collections.Generic;
using System.Linq;

namespace SessionGuard.Core.Http;

/// <summary>
/// Host and cookie-domain matching, kept in one place because two different
/// questions are easy to conflate:
///
///   which hosts do we intercept?   answered by the user's list, which may
///                                  contain "*.example.com" patterns
///
///   where may a cookie be sent?    answered by RFC 6265 domain-match against
///                                  the cookie's own Domain attribute
///
/// A site like TikTok spans many subdomains, so a vault keyed strictly by the
/// host that happened to set the cookie loses the session the moment the page
/// talks to a different one.
/// </summary>
public static class DomainRules
{
    /// <summary>
    /// RFC 6265 §5.1.3. True when a cookie scoped to <paramref name="domain"/>
    /// may be sent to <paramref name="host"/>.
    /// </summary>
    public static bool DomainMatches(string host, string domain)
    {
        if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(domain)) return false;
        host = host.TrimEnd('.').ToLowerInvariant();
        domain = domain.TrimStart('.').TrimEnd('.').ToLowerInvariant();

        if (host == domain) return true;
        if (System.Net.IPAddress.TryParse(host, out _)) return false;  // IPs: exact only
        return host.EndsWith("." + domain, StringComparison.Ordinal);
    }

    /// <summary>
    /// Whether a response from <paramref name="setterHost"/> is allowed to scope
    /// a cookie to <paramref name="domain"/>.
    ///
    /// Without this check any protected host could claim a cookie for a domain
    /// it has nothing to do with, and the vault would then attach it to every
    /// sibling host. The rule is the same one browsers apply: the attribute has
    /// to domain-match the host that sent it.
    /// </summary>
    public static bool MayScopeTo(string setterHost, string domain, out string reason)
    {
        string d = (domain ?? "").TrimStart('.').TrimEnd('.').ToLowerInvariant();
        if (d.Length == 0)
        {
            reason = "empty domain";
            return false;
        }
        if (System.Net.IPAddress.TryParse(d, out _))
        {
            reason = "domain attribute on an IP address";
            return false;
        }
        // A crude public-suffix guard: no full PSL here, but a single-label
        // domain ("com", "rs") must never be accepted.
        if (d.Count(c => c == '.') < 1)
        {
            reason = $"'{d}' is a top-level label";
            return false;
        }
        if (!DomainMatches(setterHost, d))
        {
            reason = $"'{setterHost}' may not set cookies for '{d}'";
            return false;
        }
        reason = "ok";
        return true;
    }
}

/// <summary>
/// The set of hosts to intercept. Entries are either exact hostnames or
/// "*.suffix" patterns; a pattern also covers the bare suffix itself, since
/// listing "*.example.com" and then finding example.com unprotected is not what
/// anyone means by it.
/// </summary>
public sealed class ProtectedHostSet
{
    private readonly HashSet<string> _exact = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _suffixes = new();

    public ProtectedHostSet(IEnumerable<string> entries)
    {
        foreach (var raw in entries)
        {
            string e = (raw ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (e.Length == 0) continue;
            if (e.StartsWith("*.", StringComparison.Ordinal))
            {
                string suffix = e[2..];
                if (suffix.Length > 0) _suffixes.Add(suffix);
            }
            else _exact.Add(e);
        }
    }

    public bool IsEmpty => _exact.Count == 0 && _suffixes.Count == 0;

    public IReadOnlyCollection<string> Entries =>
        _exact.Concat(_suffixes.Select(s => "*." + s)).ToArray();

    public bool Matches(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        string h = host.TrimEnd('.').ToLowerInvariant();
        if (_exact.Contains(h)) return true;
        foreach (var suffix in _suffixes)
            if (h == suffix || h.EndsWith("." + suffix, StringComparison.Ordinal))
                return true;
        return false;
    }
}
