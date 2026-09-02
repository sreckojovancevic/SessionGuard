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
/// Note this is WinINET. Chrome and Edge follow it, and so does Firefox, whose
/// default is "use system proxy settings" — Firefox's obstacle here is its
/// separate certificate store, not the proxy setting.
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
    /// What WinINET currently says, read straight back from the registry.
    ///
    /// Worth surfacing rather than assuming: "did the app actually set it?" is
    /// otherwise unanswerable without opening Internet Options by hand, which
    /// is exactly the manual step this switch exists to remove.
    /// </summary>
    public string ReadBack()
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: false);
        if (key is null) return "Internet Settings key not readable";
        object? enable = key.GetValue("ProxyEnable");
        string? server = key.GetValue("ProxyServer") as string;
        bool on = enable is int i && i != 0;
        return on
            ? $"system proxy ON -> {server ?? "(no address)"}"
            : $"system proxy OFF{(server is null ? "" : $" (address left as {server})")}";
    }

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

        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true))
        {
            if (key is null)
                throw new InvalidOperationException(
                    $"cannot open HKCU\\{RegPath} for writing");

            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
            key.SetValue("ProxyOverride",
                MergeOverride(saved.ProxyOverride), RegistryValueKind.String);
        }
        Refresh();

        // Verify rather than assume. A write that goes nowhere — wrong hive,
        // redirection, a policy overriding the value — otherwise looks exactly
        // like a working one from inside the application.
        string after = ReadBack();
        Applied?.Invoke(after);
        if (!after.Contains(proxyServer, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"wrote the proxy setting but the registry reads back as '{after}'. " +
                $"This usually means the application is running as a different " +
                $"Windows account than the browser: it writes to that account's " +
                $"HKCU, which is not the one Internet Options shows you. " +
                $"Running as: {Environment.UserDomainName}\\{Environment.UserName}");
    }

    /// <summary>
    /// Puts back what <see cref="Apply"/> replaced. Does nothing at all if this
    /// installation never applied anything.
    ///
    /// The marker file is the record of ownership, and that is the whole point:
    /// no marker means these settings are not ours to change. An earlier version
    /// treated a missing marker as "restore to a safe default" and wrote
    /// ProxyEnable=0, which meant that merely opening and closing the window
    /// turned off a proxy the user had configured by hand — a change nothing in
    /// the UI had offered to make, and one that looked from the outside like the
    /// application being unable to write the registry at all.
    ///
    /// Turning the proxy off when we did not turn it on is <see cref="ForceOff"/>,
    /// which the user asks for explicitly.
    /// </summary>
    public void Restore()
    {
        if (!File.Exists(_markerPath))
        {
            NothingToRestore?.Invoke(ReadBack());
            return;
        }

        SavedState? saved;
        try { saved = JsonSerializer.Deserialize<SavedState>(File.ReadAllText(_markerPath)); }
        catch (JsonException) { saved = null; }
        catch (IOException) { saved = null; }

        using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true))
        {
            if (key is not null)
            {
                if (saved is null)
                {
                    // The marker exists but is unreadable, so we did apply
                    // something and cannot tell what preceded it. Proxy off is
                    // the only choice that leaves a working network, since the
                    // address on file points at a port we are about to close.
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
        try { File.Delete(_markerPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        Restored?.Invoke(ReadBack());
    }

    /// <summary>Raised after a change, carrying what the registry now says.</summary>
    public event Action<string>? Applied;
    public event Action<string>? Restored;

    /// <summary>Raised when Restore was called but this installation owns nothing.</summary>
    public event Action<string>? NothingToRestore;

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
