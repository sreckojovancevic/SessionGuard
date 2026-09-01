using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

namespace SessionGuard.Windows;

/// <summary>
/// Points WinINET at the guard and — the part that actually matters — puts the
/// user's own settings back afterwards.
///
/// Two failures were worth designing around:
///
///   losing the user's config   Restoring by deleting ProxyServer wipes a
///                              corporate proxy for good. The previous values
///                              are captured before the first change and are
///                              what gets written back.
///
///   dying without cleaning up  ProcessExit does not run on TaskKill /F, on a
///                              stack overflow, or on power loss, and a stale
///                              setting pointing at a dead port leaves the
///                              machine with no internet and no explanation.
///                              The saved state is therefore written to disk
///                              *before* the registry is touched, and reconciled
///                              at the next startup.
///
/// Note this is WinINET: Chrome and Edge follow it, Firefox does not by default.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SystemProxySwitch
{
    private const string RegPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    private readonly string _markerPath;

    public SystemProxySwitch(string? directory = null)
    {
        string dir = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SessionGuard");
        Directory.CreateDirectory(dir);
        _markerPath = Path.Combine(dir, "proxy-state.json");
    }

    private sealed record SavedState(
        int? ProxyEnable, string? ProxyServer, string? ProxyOverride,
        string AppliedProxy, DateTimeOffset AppliedAt);

    public bool IsApplied => File.Exists(_markerPath);
    public string MarkerPath => _markerPath;

    /// <summary>
    /// Called at startup. If a marker survived a crash, the user's settings are
    /// restored before anything else happens.
    /// </summary>
    public bool RecoverIfStale()
    {
        if (!File.Exists(_markerPath)) return false;
        Restore();
        return true;
    }

    public void Apply(string proxyServer)
    {
        // Capture first, persist the capture, and only then change anything:
        // a crash between the two must never lose the original values.
        var saved = ReadCurrent(proxyServer);
        File.WriteAllText(_markerPath, JsonSerializer.Serialize(saved));

        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
        if (key is null) throw new InvalidOperationException("Internet Settings key missing");

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
        key.SetValue("ProxyOverride",
            MergeOverride(saved.ProxyOverride), RegistryValueKind.String);
        Refresh();
    }

    public void Restore()
    {
        SavedState? saved = null;
        if (File.Exists(_markerPath))
        {
            try { saved = JsonSerializer.Deserialize<SavedState>(File.ReadAllText(_markerPath)); }
            catch (JsonException) { saved = null; }
        }

        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true))
        {
            if (key is not null)
            {
                if (saved is null)
                {
                    // No record of what was there: the safe default is proxy off,
                    // leaving any address in place rather than deleting it.
                    key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                }
                else
                {
                    Write(key, "ProxyEnable", saved.ProxyEnable, RegistryValueKind.DWord);
                    Write(key, "ProxyServer", saved.ProxyServer, RegistryValueKind.String);
                    Write(key, "ProxyOverride", saved.ProxyOverride, RegistryValueKind.String);
                }
            }
        }

        Refresh();
        try { if (File.Exists(_markerPath)) File.Delete(_markerPath); } catch { }
    }

    private static void Write(RegistryKey key, string name, object? value,
                              RegistryValueKind kind)
    {
        if (value is null) key.DeleteValue(name, throwOnMissingValue: false);
        else key.SetValue(name, value, kind);
    }

    private SavedState ReadCurrent(string appliedProxy)
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: false);
        int? enable = key?.GetValue("ProxyEnable") is int i ? i : null;
        string? server = key?.GetValue("ProxyServer") as string;

        // Never record a loopback proxy as "what the user had".
        //
        // If the current setting already points at 127.0.0.1 — because the user
        // set it by hand, or a previous run left it behind — then treating it as
        // the original means Restore faithfully puts back an address that
        // nothing is listening on, and the machine ends up with no internet and
        // no clue why. Capturing "proxy off" instead is the only restore that
        // is guaranteed to leave a working network.
        if (PointsAtLoopback(server))
        {
            LoopbackOriginalIgnored?.Invoke(server!);
            return new SavedState(0, null,
                key?.GetValue("ProxyOverride") as string,
                appliedProxy, DateTimeOffset.UtcNow);
        }

        return new SavedState(enable, server,
            key?.GetValue("ProxyOverride") as string,
            appliedProxy, DateTimeOffset.UtcNow);
    }

    /// <summary>Raised when a pre-existing loopback proxy setting is discarded.</summary>
    public event Action<string>? LoopbackOriginalIgnored;

    internal static bool PointsAtLoopback(string? proxyServer)
    {
        if (string.IsNullOrWhiteSpace(proxyServer)) return false;
        foreach (var part in proxyServer.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            string p = part.Trim();
            int eq = p.IndexOf('=');           // "http=host:port" form
            if (eq >= 0) p = p[(eq + 1)..];
            if (p.StartsWith("127.", StringComparison.Ordinal) ||
                p.StartsWith("localhost", StringComparison.OrdinalIgnoreCase) ||
                p.StartsWith("[::1]", StringComparison.Ordinal) ||
                p.StartsWith("::1", StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Emergency reset: turn the proxy off and forget any saved state. For the
    /// case where the machine is already stuck behind a dead proxy address.
    /// </summary>
    public void ForceOff()
    {
        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true))
            key?.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        Refresh();
        try { if (File.Exists(_markerPath)) File.Delete(_markerPath); } catch { }
    }

    /// <summary>Keeps the user's bypass list and adds loopback so local dev survives.</summary>
    private static string MergeOverride(string? existing)
    {
        var parts = (existing ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        foreach (var needed in new[] { "<local>", "127.0.0.1", "localhost", "::1" })
            if (!parts.Any(p => string.Equals(p, needed, StringComparison.OrdinalIgnoreCase)))
                parts.Add(needed);
        return string.Join(";", parts);
    }

    private static void Refresh()
    {
        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(
        IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
