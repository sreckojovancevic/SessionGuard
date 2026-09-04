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

/// <summary>Which implementation seals the vault.</summary>
public enum VaultEngine
{
    /// <summary>
    /// TPM when the machine has a usable one, software otherwise — and the
    /// window says which was chosen. Automatic must never mean silent: a
    /// downgrade the user cannot see is the failure this project is written
    /// against.
    /// </summary>
    Automatic,

    /// <summary>
    /// TPM 2.0 only. If the chip is missing, locked out or refuses, the
    /// application does not run rather than quietly protecting less. Choose it
    /// when the machine-binding claim must hold or nothing should happen.
    /// </summary>
    Tpm,

    /// <summary>
    /// AES-256-GCM under a process-memory key. Works on any CPU, and is
    /// hardware-accelerated on anything since about 2010 — which is the point:
    /// TPM 2.0 is not, and an older workstation, a virtual machine without a
    /// vTPM, or a TPM 1.2 machine otherwise gets no protection at all.
    ///
    /// It is also the way out when a TPM is present but obstructive: locked out
    /// by its dictionary-attack defence, or raising consent prompts a remote
    /// session never displays.
    ///
    /// Gives up machine binding. Keeps the property that matters most in
    /// practice — the cookie is never in the browser profile.
    /// </summary>
    Software,
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
        int LeaseMinutes,
        [property: JsonConverter(typeof(JsonStringEnumConverter))] VaultEngine Engine = VaultEngine.Automatic);

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

    public VaultEngine Engine
    {
        get => _doc.Engine;
        set { _doc = _doc with { Engine = value }; Save(); }
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

    public static string Describe(VaultEngine engine) => engine switch
    {
        VaultEngine.Automatic => "Automatic — TPM if this machine has one",
        VaultEngine.Tpm => "TPM 2.0 only — refuse to run without it",
        VaultEngine.Software => "Software AES-256-GCM — works on any machine",
        _ => engine.ToString(),
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
