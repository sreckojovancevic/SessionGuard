using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SessionGuard.Core.Http;

namespace SessionGuard.Core.Vault;

/// <summary>
/// Sealed store of session cookies, scoped the way cookies actually are.
///
/// Keying strictly by the host that sent Set-Cookie breaks any site spread over
/// subdomains: a session established on www.example.com is never attached to
/// api.example.com, even though the browser would send it, because the cookie
/// carries Domain=.example.com. Entries are therefore keyed by the cookie's own
/// scope — its Domain attribute when present, otherwise the exact host as a
/// host-only cookie — and looked up by domain-match.
///
/// Still not a browser cookie jar: SameSite and Secure are not modelled, and
/// there is no public-suffix list beyond a single-label guard. Names, domains
/// and paths are not secret and are held as strings; values never are.
/// </summary>
public sealed class SessionVault
{
    private sealed record Entry(byte[] Blob, string Domain, bool HostOnly, string? Path);

    private readonly ISecretSealer _sealer;

    // key: "domain\nname" — one entry per (scope, name), as cookies allow the
    // same name at different scopes.
    private readonly ConcurrentDictionary<string, Entry> _entries =
        new(StringComparer.OrdinalIgnoreCase);

    public SessionVault(ISecretSealer sealer) => _sealer = sealer;

    public ISecretSealer Sealer => _sealer;

    /// <summary>Times a stored cookie value was replaced — the refresh counter.</summary>
    public int RefreshCount { get; private set; }

    /// <summary>Times a stored cookie was dropped because the server expired it.</summary>
    public int RevokeCount { get; private set; }

    /// <summary>Raised when a Set-Cookie tries to claim a scope it may not have.</summary>
    public event Action<string>? ScopeRejected;

    private static string Key(string domain, string name) => domain + "\n" + name;

    // ---------------------------------------------------------------- write

    /// <summary>
    /// Stores a cookie observed on <paramref name="setterHost"/>.
    /// Returns false when the Domain attribute is not one that host may claim.
    /// </summary>
    public bool Store(string setterHost, ReadOnlySpan<byte> name, ReadOnlySpan<byte> value,
                      string? domainAttribute = null, string? path = null)
    {
        string host = setterHost.TrimEnd('.').ToLowerInvariant();
        string domain;
        bool hostOnly;

        if (string.IsNullOrEmpty(domainAttribute))
        {
            domain = host;
            hostOnly = true;
        }
        else
        {
            if (!DomainRules.MayScopeTo(host, domainAttribute, out string why))
            {
                ScopeRejected?.Invoke($"{Encoding.ASCII.GetString(name)}: {why}");
                return false;
            }
            domain = domainAttribute.TrimStart('.').TrimEnd('.').ToLowerInvariant();
            hostOnly = false;
        }

        string key = Key(domain, Encoding.ASCII.GetString(name));
        if (_entries.ContainsKey(key)) RefreshCount++;
        _entries[key] = new Entry(_sealer.Seal(value), domain, hostOnly, path);
        return true;
    }

    /// <summary>
    /// Drops a cookie the server has expired. Without this a Max-Age=0 reply
    /// would be stored as an empty value and replayed forever, so signing out
    /// would never take effect.
    /// </summary>
    public bool Remove(string setterHost, ReadOnlySpan<byte> name, string? domainAttribute = null)
    {
        string host = setterHost.TrimEnd('.').ToLowerInvariant();
        string domain = string.IsNullOrEmpty(domainAttribute)
            ? host
            : domainAttribute.TrimStart('.').TrimEnd('.').ToLowerInvariant();

        string cookieName = Encoding.ASCII.GetString(name);
        string suffix = "\n" + cookieName;
        bool removed = false;

        // Drop the scope the server named, and any other scope with the same
        // name that already covers this host: servers are not always consistent
        // about the Domain attribute when expiring a cookie they set.
        foreach (var kv in _entries.ToArray())
        {
            if (!kv.Key.EndsWith(suffix, StringComparison.Ordinal)) continue;
            bool sameScope = kv.Value.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase);
            if (!sameScope && !Applies(kv.Value, host)) continue;

            if (_entries.TryRemove(kv.Key, out var gone))
            {
                CryptographicOperations.ZeroMemory(gone.Blob);
                RevokeCount++;
                removed = true;
            }
        }
        return removed;
    }

    public void Clear() => _entries.Clear();

    /// <summary>Drops everything scoped to, or under, this host.</summary>
    public bool Revoke(string host)
    {
        bool any = false;
        foreach (var kv in _entries.ToArray())
        {
            if (!Applies(kv.Value, host) &&
                !DomainRules.DomainMatches(kv.Value.Domain, host)) continue;
            if (_entries.TryRemove(kv.Key, out var gone))
            {
                CryptographicOperations.ZeroMemory(gone.Blob);
                any = true;
            }
        }
        return any;
    }

    // ----------------------------------------------------------------- read

    private static bool Applies(Entry e, string host) =>
        e.HostOnly
            ? string.Equals(e.Domain, host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)
            : DomainRules.DomainMatches(host, e.Domain);

    private IEnumerable<KeyValuePair<string, Entry>> For(string host, string? path = null) =>
        _entries.Where(kv => Applies(kv.Value, host) &&
                             (path is null || CookieBytes.PathMatches(kv.Value.Path, path)));

    public int Count(string host) => For(host).Count();

    public int CountForPath(string host, string path) => For(host, path).Count();

    public IReadOnlyCollection<string> Names(string host) =>
        For(host).Select(kv => kv.Key[(kv.Key.IndexOf('\n') + 1)..]).Distinct().ToArray();

    /// <summary>Scopes currently held, for display.</summary>
    public IReadOnlyCollection<string> Scopes =>
        _entries.Values.Select(e => e.HostOnly ? e.Domain : "." + e.Domain)
                       .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    public IReadOnlyCollection<string> Hosts => Scopes;

    public IReadOnlyCollection<string> NamesInScope(string scope) =>
        _entries.Where(kv => string.Equals(
                    kv.Value.HostOnly ? kv.Value.Domain : "." + kv.Value.Domain,
                    scope, StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Key[(kv.Key.IndexOf('\n') + 1)..])
                .ToArray();

    /// <summary>
    /// Builds the "n1=v1; n2=v2" body of a Cookie header into a rented buffer,
    /// including only cookies whose scope and Path apply to this request.
    /// The caller must wipe and return it via <see cref="ReturnCookieHeader"/>.
    /// </summary>
    public bool TryBuildCookieHeader(string host, string requestPath,
                                     out byte[] buffer, out int length)
    {
        buffer = Array.Empty<byte>();
        length = 0;

        var applicable = For(host, requestPath).ToArray();
        if (applicable.Length == 0) return false;

        int budget = applicable.Sum(kv =>
            kv.Key.Length + 2 + _sealer.MaxPlaintextLength(kv.Value.Blob) + 2);

        buffer = ArrayPool<byte>.Shared.Rent(budget);
        int pos = 0;
        try
        {
            foreach (var kv in applicable)
            {
                string name = kv.Key[(kv.Key.IndexOf('\n') + 1)..];
                if (pos > 0)
                {
                    buffer[pos++] = (byte)';';
                    buffer[pos++] = (byte)' ';
                }
                pos += Encoding.ASCII.GetBytes(name, buffer.AsSpan(pos));
                buffer[pos++] = (byte)'=';
                pos += _sealer.Unseal(kv.Value.Blob, buffer.AsSpan(pos));
            }
            length = pos;
            return true;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, Math.Max(0, pos)));
            ArrayPool<byte>.Shared.Return(buffer);
            buffer = Array.Empty<byte>();
            throw;
        }
    }

    /// <summary>True when this name is one the vault would attach for this host.</summary>
    public bool IsGuarded(string host, ReadOnlySpan<byte> name)
    {
        string n = Encoding.ASCII.GetString(name);
        return For(host).Any(kv =>
            string.Equals(kv.Key[(kv.Key.IndexOf('\n') + 1)..], n, StringComparison.Ordinal));
    }

    public static void ReturnCookieHeader(byte[] buffer, int length)
    {
        if (buffer.Length == 0) return;
        CryptographicOperations.ZeroMemory(buffer.AsSpan(0, length));
        ArrayPool<byte>.Shared.Return(buffer);
    }
}
