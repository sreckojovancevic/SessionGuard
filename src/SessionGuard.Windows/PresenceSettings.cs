using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SessionGuard.Windows;

/// <summary>How the user's presence is established before a lease opens.</summary>
public enum PresenceMode
{
    /// <summary>
    /// Windows Hello signs a random challenge with a TPM-held credential the
    /// platform only releases after a biometric or PIN gesture. A success is
    /// evidence a human was at the machine — not merely that something in our
    /// process clicked a button.
    /// </summary>
    WindowsHello,

    /// <summary>
    /// No gesture at unlock; consent comes from the TPM instead. The vault key
    /// carries CngUIPolicy.ProtectKey, so Windows raises its own confirmation
    /// dialog on every unseal. Weaker as an unlock ceremony, but not nothing:
    /// the prompt still fires per use, from outside our process.
    ///
    /// Only meaningful while the sealer really is TPM-backed with that policy.
    /// </summary>
    TpmConsent,

    /// <summary>
    /// Unlock is a button click. The lease still limits time and pins the
    /// process family, but nothing verifies that a person did it. Malware that
    /// can drive the UI, or that simply waits for the user to unlock, rides
    /// along.
    /// </summary>
    None,
}

/// <summary>
/// Persisted preferences. Kept beside the host list so both can be changed
/// without rebuilding.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PresenceSettings
{
    private sealed record Doc(
        [property: JsonConverter(typeof(JsonStringEnumConverter))] PresenceMode PresenceMode,
        int LeaseMinutes);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _path;
    private Doc _doc = new(PresenceMode.WindowsHello, 15);

    public PresenceSettings(string? directory = null)
    {
        string dir = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SessionGuard");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "settings.json");
        Load();
    }

    public string Path_ => _path;

    public PresenceMode Mode
    {
        get => _doc.PresenceMode;
        set { _doc = _doc with { PresenceMode = value }; Save(); }
    }

    public TimeSpan LeaseDuration => TimeSpan.FromMinutes(Math.Clamp(_doc.LeaseMinutes, 1, 240));

    private void Load()
    {
        try
        {
            if (File.Exists(_path))
                _doc = JsonSerializer.Deserialize<Doc>(File.ReadAllText(_path), Json) ?? _doc;
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Corrupt or unreadable settings must not weaken the default.
            _doc = new Doc(PresenceMode.WindowsHello, 15);
        }
    }

    private void Save()
    {
        try { File.WriteAllText(_path, JsonSerializer.Serialize(_doc, Json)); }
        catch (IOException) { }
    }

    /// <summary>
    /// What the chosen mode actually amounts to right now.
    ///
    /// Asking for TPM consent while the vault is sealed by something without a
    /// per-use policy would be a claim the machine is not honouring, so it is
    /// reported as None instead of being quietly accepted.
    /// </summary>
    public static PresenceMode Effective(PresenceMode chosen, bool sealerRequiresPresence) =>
        chosen == PresenceMode.TpmConsent && !sealerRequiresPresence
            ? PresenceMode.None
            : chosen;

    public static string Describe(PresenceMode mode) => mode switch
    {
        PresenceMode.WindowsHello => "Windows Hello gesture",
        PresenceMode.TpmConsent => "TPM consent prompt (per use)",
        PresenceMode.None => "None — unlock is just a click",
        _ => mode.ToString(),
    };

    public static string Caveat(PresenceMode effective) => effective switch
    {
        PresenceMode.WindowsHello =>
            "A person is verified by the platform before the lease opens.",
        PresenceMode.TpmConsent =>
            "No gesture at unlock; Windows still asks for confirmation each time " +
            "the vault is opened.",
        PresenceMode.None =>
            "Nothing verifies that a person unlocked. The lease still expires and " +
            "is pinned to one browser, but anything that can click, or that waits " +
            "for you to unlock, gets the session too.",
        _ => "",
    };
}
