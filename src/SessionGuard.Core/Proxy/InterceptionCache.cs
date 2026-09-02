using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace SessionGuard.Core.Proxy;

/// <summary>Why a protected host ended up being passed through unprotected.</summary>
public sealed record SkippedHost(string Host, string Reason, DateTimeOffset Since)
{
    public override string ToString() => $"{Host} — {Reason}";
}

/// <summary>
/// Hosts that match the protected list but cannot actually be intercepted.
///
/// The usual cause is a host that will not speak HTTP/1.1. A wildcard entry like
/// "*.example.com" covers subdomains nobody enumerated, and one of them may be
/// HTTP/2 only; that is only discovered when the browser first goes there.
///
/// Entries expire, because a site may fix its configuration and because a single
/// failure may have been transient. Nothing here is silent: the proxy reports
/// every entry, since a quiet skip is a quiet hole in the protection.
/// </summary>
public sealed class InterceptionCache
{
    private readonly ConcurrentDictionary<string, SkippedHost> _skipped =
        new(StringComparer.OrdinalIgnoreCase);

    public InterceptionCache(TimeSpan? ttl = null) =>
        Ttl = ttl ?? TimeSpan.FromHours(1);

    public TimeSpan Ttl { get; }

    public bool ShouldBypass(string host)
    {
        if (!_skipped.TryGetValue(host, out var entry)) return false;
        if (DateTimeOffset.UtcNow - entry.Since <= Ttl) return true;
        _skipped.TryRemove(host, out _);
        return false;
    }

    public void Mark(string host, string reason) =>
        _skipped[host] = new SkippedHost(host, reason, DateTimeOffset.UtcNow);

    public bool Clear(string host) => _skipped.TryRemove(host, out _);

    public void ClearAll() => _skipped.Clear();

    /// <summary>Current entries, expired ones dropped.</summary>
    public IReadOnlyCollection<SkippedHost> Current
    {
        get
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kv in _skipped.ToArray())
                if (now - kv.Value.Since > Ttl)
                    _skipped.TryRemove(kv.Key, out _);
            return _skipped.Values.OrderBy(v => v.Host, StringComparer.Ordinal).ToArray();
        }
    }
}
