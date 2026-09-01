using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;

namespace SessionGuard.Windows;

/// <summary>
/// The list of hosts to intercept, kept in %LOCALAPPDATA% so it can be changed
/// without rebuilding.
///
/// Having it as a const array in the source was a real usability bug: the app
/// shipped pointing at a placeholder host, so the vault stayed empty no matter
/// what the user did, and the only fix was to recompile.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectedHostStore
{
    public const string PlaceholderHost = "api.example.test";

    private const string Template = """
        # SessionGuard — hosts to protect, one per line.
        #
        # Only hosts listed here are intercepted. Everything else is passed
        # through as an untouched TLS tunnel, so nothing else can break.
        #
        # Use the exact hostname the browser connects to, without scheme or path:
        #   example.com
        #   www.example.com
        #
        # A leading *. covers every subdomain and the bare domain itself:
        #   *.tiktok.com     covers tiktok.com, www.tiktok.com, webcast.tiktok.com
        # A plain entry is exact: tiktok.com does NOT cover www.tiktok.com.
        # Sites that pin certificates, or that keep their token in localStorage
        # instead of a cookie, cannot be protected this way.

        """;

    private readonly string _path;

    public ProtectedHostStore(string? directory = null)
    {
        string dir = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SessionGuard");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "protected-hosts.txt");
        if (!File.Exists(_path)) File.WriteAllText(_path, Template);
    }

    public string Path_ => _path;

    public IReadOnlyList<string> Load()
    {
        try
        {
            return File.ReadAllLines(_path)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith('#'))
                .Select(Normalize)
                .Where(l => l.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
    }

    public void Save(IEnumerable<string> hosts)
    {
        var cleaned = hosts
            .Select(Normalize)
            .Where(h => h.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        File.WriteAllText(_path, Template + string.Join(Environment.NewLine, cleaned) +
                                 Environment.NewLine);
    }

    /// <summary>Accepts what people actually paste: URLs, ports, trailing slashes.</summary>
    public static string Normalize(string raw)
    {
        string h = raw.Trim();
        if (h.Length == 0) return "";

        // Keep a wildcard prefix through the URL clean-up below.
        bool wildcard = h.StartsWith("*.", StringComparison.Ordinal);
        if (wildcard) h = h[2..];
        int scheme = h.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) h = h[(scheme + 3)..];
        int slash = h.IndexOf('/');
        if (slash >= 0) h = h[..slash];
        int colon = h.LastIndexOf(':');
        if (colon > 0 && int.TryParse(h[(colon + 1)..], out _)) h = h[..colon];
        h = h.Trim().TrimEnd('.').ToLowerInvariant();
        return h.Length == 0 ? "" : (wildcard ? "*." + h : h);
    }
}
