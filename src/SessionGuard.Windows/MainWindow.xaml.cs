using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using SessionGuard.Core.Authz;
using SessionGuard.Core.Pki;
using SessionGuard.Core.Proxy;
using SessionGuard.Core.Vault;

namespace SessionGuard.Windows;

[SupportedOSPlatform("windows10.0.17763.0")]
public partial class MainWindow : Window
{
    // 8080 collides with all sorts of local dev servers; 28080 is quieter.
    private const int ListenPort = 28080;

    /// <summary>Opt-in switch for running without a TPM. Not a default.</summary>
    public const string InsecureDevFlag = "--allow-insecure-dev-mode";

    private readonly SystemProxySwitch _sysProxy = new();
    private readonly PresenceLease _lease = new();
    private readonly CertificateAuthority _ca;
    private readonly TcpTablePeerResolver _resolver = new();
    private readonly PeerAuthorizer _authorizer;
    private readonly BrowserScanner _scanner;
    private readonly ProtectedHostStore _hosts = new();
    private readonly PresenceSettings _settings = new();
    private readonly DispatcherTimer _timer;
    private readonly StringBuilder _log = new();

    private ISecretSealer? _sealer;
    private SessionVault? _vault;
    private bool _protectedModeAvailable;
    private bool _devMode;

    private ProxyEngine? _engine;
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();

        // A marker left behind means a previous run died without cleaning up.
        // Put the user's settings back before doing anything else.
        if (_sysProxy.RecoverIfStale())
            Log("recovered stale system-proxy settings from a previous run");

        _ca = new CertificateAuthority(new DpapiCaStore());
        _authorizer = new PeerAuthorizer(_resolver, _lease);
        _scanner = new BrowserScanner(_resolver);
        _sysProxy.LoopbackOriginalIgnored += old => Dispatcher.BeginInvoke(() => Log(
            $"ignored a pre-existing loopback proxy setting ('{old}') — restoring it " +
            "later would have left this machine with no internet"));

        _devMode = Environment.GetCommandLineArgs()
            .Any(a => string.Equals(a, InsecureDevFlag, StringComparison.OrdinalIgnoreCase));

        OpenVault();

        AppDomain.CurrentDomain.ProcessExit += (_, _) => SafeRestore();
        SystemEvents.SessionEnding += (_, _) => SafeRestore();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => RefreshState();
        _timer.Start();

        PopulatePresenceModes();
        PopulateBrowsers();
        LoadHosts();
        RefreshState();
    }

    /// <summary>
    /// Opens (or reopens) the sealed vault for the currently selected presence
    /// mode.
    ///
    /// The per-use consent prompt is a property of the TPM key, not of a
    /// setting, so the mode has to drive how the key is created. A key made by
    /// an earlier run keeps its own policy: that mismatch is reported rather
    /// than papered over, and 'Reset key' is the remedy.
    /// </summary>
    private void OpenVault()
    {
        (_sealer as IDisposable)?.Dispose();
        _sealer = null;
        _vault = null;

        bool wantConsent = _settings.Mode == PresenceMode.TpmConsent;

        try
        {
            var tpm = TpmSealer.Open(requirePresence: wantConsent);
            _sealer = tpm;
            _vault = new SessionVault(tpm);
            _protectedModeAvailable = true;

            SubtitleText.Text = tpm.RequiresPresence
                ? "TPM-sealed vault, per-use consent"
                : "TPM-sealed vault";
            SealerText.Text = $"sealer: {tpm.Name} — key sealed to this TPM, not exportable";

            if (!tpm.PolicyMatchesRequest)
            {
                string has = tpm.RequiresPresence ? "per-use consent" : "no per-use consent";
                string wants = wantConsent ? "per-use consent" : "no per-use consent";
                SealerText.Text += $"  |  key has {has}, mode wants {wants}";
                SealerText.Foreground = Brush("#F5A524");
                Log($"TPM key policy mismatch: key has {has}, '{PresenceSettings.Describe(_settings.Mode)}' " +
                    "wants " + wants + ". Press 'Reset key' to recreate it.");
            }
            else
            {
                SealerText.Foreground = Brush("#8B93A1");
            }
        }
        catch (Exception ex) when (_devMode)
        {
            var eph = new EphemeralSealer();
            _sealer = eph;
            _vault = new SessionVault(eph);
            _protectedModeAvailable = true;
            SubtitleText.Text = "INSECURE DEV MODE — vault is RAM only";
            SubtitleText.Foreground = Brush("#E5484D");
            SealerText.Text = $"sealer: {eph.Name} — TPM unavailable ({ex.GetType().Name}); " +
                              "this is not a security boundary";
            Log($"running in insecure dev mode: {ex.Message}");
        }
        catch (Exception ex)
        {
            // Fail closed: a security product that silently drops to a RAM-only
            // vault when its hardware root is missing is worse than one that
            // refuses, because the user believes they are protected.
            _protectedModeAvailable = false;
            SubtitleText.Text = "PROTECTED MODE UNAVAILABLE";
            SubtitleText.Foreground = Brush("#E5484D");
            SealerText.Text = "no TPM-backed key: " + ex.Message;
            Log("protected mode unavailable — refusing to run without a hardware-sealed vault");
            Log($"start with {InsecureDevFlag} only if you are testing.");
        }

        BtnToggle.IsEnabled = _protectedModeAvailable;
        BtnUnlock.IsEnabled = _protectedModeAvailable;
    }

    private async void BtnResetKey_Click(object sender, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(
            "Delete the SessionGuard TPM key and create a new one matching the " +
            "selected presence mode?\n\n" +
            "Anything currently in the vault becomes unreadable, so you will be " +
            "signed out of protected sites and will have to log in again.",
            "SessionGuard", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK) return;

        try
        {
            if (_engine is not null) await TurnOffAsync();
            (_sealer as IDisposable)?.Dispose();
            _sealer = null;
            _vault = null;

            bool deleted = TpmSealer.DeleteKey();
            Log(deleted ? "TPM key deleted" : "no TPM key to delete");
            OpenVault();
            Log($"vault reopened for: {PresenceSettings.Describe(_settings.Mode)}");
        }
        catch (Exception ex)
        {
            Log($"reset key failed: {ex.Message}");
            MessageBox.Show(ex.Message, "SessionGuard",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RefreshPresenceCaveat();
            RefreshState();
        }
    }

    // ------------------------------------------------------------- toggle

    private async void BtnToggle_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || !_protectedModeAvailable || _vault is null) return;
        _busy = true;
        BtnToggle.IsEnabled = false;
        try
        {
            if (_engine is null) TurnOn(_vault);
            else await TurnOffAsync();
        }
        catch (Exception ex)
        {
            Log($"error: {ex.Message}");
            MessageBox.Show(ex.Message, "SessionGuard",
                            MessageBoxButton.OK, MessageBoxImage.Error);
            SafeRestore();
            if (_engine is not null) { await _engine.DisposeAsync(); _engine = null; }
        }
        finally
        {
            _busy = false;
            BtnToggle.IsEnabled = _protectedModeAvailable;
            RefreshState();
        }
    }

    private void TurnOn(SessionVault vault)
    {
        EnsureRootTrusted();

        var hosts = _hosts.Load();
        if (hosts.Count == 0 ||
            hosts.Contains(ProtectedHostStore.PlaceholderHost, StringComparer.OrdinalIgnoreCase))
        {
            MessageBox.Show(
                "No real host to protect yet.\n\n" +
                "Type the site's hostname in 'Protected hosts' and press Save, " +
                "otherwise everything is simply tunnelled and the vault stays empty.",
                "SessionGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        var options = new ProxyOptions(ListenPort, hosts);
        var engine = new ProxyEngine(options, vault, _authorizer, _ca);
        engine.Observed += ev => Dispatcher.BeginInvoke(() => Log(ev.ToString()));
        engine.Start();
        _engine = engine;

        _sysProxy.Apply($"127.0.0.1:{ListenPort}");
        Log($"guard on; system proxy -> 127.0.0.1:{ListenPort}");
    }

    private async Task TurnOffAsync()
    {
        _sysProxy.Restore();
        if (_engine is not null)
        {
            await _engine.DisposeAsync();
            _engine = null;
        }
        _lease.Close();
        Log("guard off; system proxy restored");
    }

    /// <summary>Adds the local root to the user's trust store if it is not there.</summary>
    private void EnsureRootTrusted()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var found = store.Certificates.Find(
            X509FindType.FindByThumbprint, _ca.Root.Thumbprint, false);
        if (found.Count > 0) return;

        var answer = MessageBox.Show(
            "SessionGuard needs to add its local certificate authority to your " +
            "personal trusted roots so it can inspect the sites you protect.\n\n" +
            "The private key is protected with DPAPI under your Windows account.\n\n" +
            "Add it now?",
            "SessionGuard", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK)
            throw new OperationCanceledException("certificate authority not trusted");

        store.Add(new X509Certificate2(_ca.Root.Export(X509ContentType.Cert)));
        Log($"root CA installed ({_ca.StoreDescription})");
    }

    // -------------------------------------------------------------- hosts

    private void LoadHosts()
    {
        var hosts = _hosts.Load();
        TxtHosts.Text = string.Join(", ", hosts);
        HostsText.Text = hosts.Count == 0
            ? $"none yet — nothing will be intercepted. File: {_hosts.Path_}"
            : $"{hosts.Count} host(s). File: {_hosts.Path_}";
        Log($"protected hosts: {(hosts.Count == 0 ? "(none)" : string.Join(", ", hosts))}");
    }

    private void BtnSaveHosts_Click(object sender, RoutedEventArgs e)
    {
        var entered = (TxtHosts.Text ?? "")
            .Split(new[] { ',', ';', ' ', '\n', '\r', '\t' },
                   StringSplitOptions.RemoveEmptyEntries);
        _hosts.Save(entered);
        LoadHosts();
        if (_engine is not null)
            Log("host list saved — turn the guard off and on for it to take effect");
    }

    // ----------------------------------------------------------- presence

    private bool _loadingModes;

    /// <summary>Effective mode: what the machine will actually enforce.</summary>
    private PresenceMode EffectiveMode =>
        PresenceSettings.Effective(_settings.Mode, _sealer?.RequiresPresence ?? false);

    private void PopulatePresenceModes()
    {
        _loadingModes = true;
        var choices = new[]
        {
            PresenceMode.WindowsHello, PresenceMode.TpmConsent, PresenceMode.None,
        }.Select(m => new ModeChoice(m, PresenceSettings.Describe(m))).ToArray();
        CmbPresenceMode.ItemsSource = choices;
        CmbPresenceMode.SelectedIndex =
            Math.Max(0, Array.FindIndex(choices, c => c.Mode == _settings.Mode));
        _loadingModes = false;
        RefreshPresenceCaveat();
    }

    private sealed record ModeChoice(PresenceMode Mode, string Label)
    {
        public override string ToString() => Label;
    }

    private void CmbPresenceMode_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingModes) return;
        if (CmbPresenceMode.SelectedItem is not ModeChoice choice) return;
        _settings.Mode = choice.Mode;
        Log($"presence check set to: {PresenceSettings.Describe(choice.Mode)}");

        bool wantConsent = choice.Mode == PresenceMode.TpmConsent;
        bool? keyPolicy = null;
        try { keyPolicy = TpmSealer.ExistingKeyRequiresPresence(); } catch { }
        if (keyPolicy is not null && keyPolicy != wantConsent)
            Log("the existing TPM key still carries the previous policy — " +
                "press 'Reset key' for this choice to take effect");

        RefreshPresenceCaveat();
        RefreshState();
    }

    private void RefreshPresenceCaveat()
    {
        var effective = EffectiveMode;
        string text = PresenceSettings.Caveat(effective);

        // Say so when the choice cannot be honoured, rather than showing the
        // reassuring description of a check that is not running.
        if (effective != _settings.Mode)
            text = $"'{PresenceSettings.Describe(_settings.Mode)}' is not available " +
                   $"with the current vault, so this is effectively: {text}";

        PresenceCaveat.Text = text;
        PresenceCaveat.Foreground = Brush(
            effective == PresenceMode.WindowsHello ? "#8B93A1" :
            effective == PresenceMode.TpmConsent ? "#F5A524" : "#E5484D");
    }

    private void PopulateBrowsers()
    {
        var result = _scanner.Scan();
        CmbBrowsers.ItemsSource = result.Roots;
        if (result.Roots.Count > 0) CmbBrowsers.SelectedIndex = 0;

        ScanText.Text = result.Diagnosis;
        Log("browser scan: " + result.Diagnosis);
        foreach (var c in result.All)
            Log($"  {c.Name} pid={c.Pid} ppid={c.ParentPid} window={c.HasWindow}");
    }

    /// <summary>
    /// The chosen pid, either from the list or typed into the editable box.
    /// Typing is the escape hatch for the case where enumeration comes back
    /// empty and the user can read the pid from Task Manager.
    /// </summary>
    private bool TryGetChosenPid(out int pid, out string problem)
    {
        pid = 0;
        problem = "";
        if (CmbBrowsers.SelectedItem is BrowserScanner.Candidate c)
        {
            pid = c.Pid;
            return true;
        }
        string typed = (CmbBrowsers.Text ?? "").Trim();
        if (int.TryParse(typed, out pid) && pid > 0) return true;

        problem = typed.Length == 0
            ? "Pick a browser, or type its process id (Task Manager, Details tab)."
            : $"'{typed}' is not a process id.";
        return false;
    }

    private void BtnRefresh_Click(object sender, RoutedEventArgs e) => PopulateBrowsers();

    private async void BtnUnlock_Click(object sender, RoutedEventArgs e)
    {
        if (!_protectedModeAvailable) return;
        if (!TryGetChosenPid(out int chosenPid, out string problem))
        {
            MessageBox.Show(problem, "SessionGuard");
            return;
        }

        BtnUnlock.IsEnabled = false;
        try
        {
            var mode = EffectiveMode;
            string how;

            if (mode == PresenceMode.WindowsHello)
            {
                var gesture = await WindowsHello.RequestGestureAsync();
                if (!gesture.Ok)
                {
                    // No verified human, no lease. Never silently downgrade —
                    // but do say which setting would change the requirement,
                    // so a machine without Hello is not simply a dead end.
                    Log($"unlock refused: {gesture.Detail}");
                    MessageBox.Show(
                        $"Could not verify your presence: {gesture.Detail}\n\n" +
                        "The lease stays closed.\n\n" +
                        "If this machine has no Windows Hello, change 'Check' to " +
                        "'TPM consent prompt' — Windows then asks for confirmation " +
                        "every time the vault is opened instead.",
                        "SessionGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                how = gesture.Detail;
            }
            else if (mode == PresenceMode.TpmConsent)
            {
                how = "no gesture; TPM asks per use";
            }
            else
            {
                how = "UNVERIFIED — presence check is off";
            }

            if (CmbBrowsers.SelectedItem is BrowserScanner.Candidate { Name: "firefox" })
            {
                // Firefox does use the Windows system proxy by default, but it
                // keeps its own certificate store, so the interception root has
                // to be trusted there separately.
                Log("firefox selected: it follows the system proxy, but uses its own " +
                    "certificate store — enable security.enterprise_roots in about:config " +
                    "or import the SessionGuard root manually, or protected sites will " +
                    "show a certificate error");
            }

            if (!_authorizer.TryOpenLease(chosenPid, _settings.LeaseDuration, out string why))
            {
                Log($"unlock failed: {why}");
                MessageBox.Show(why, "SessionGuard");
                return;
            }
            Log($"{why} ({how})");
        }
        catch (Exception ex)
        {
            Log($"unlock failed: {ex.Message}");
        }
        finally
        {
            BtnUnlock.IsEnabled = _protectedModeAvailable;
            RefreshState();
        }
    }

    private void BtnForget_Click(object sender, RoutedEventArgs e)
    {
        _vault?.Clear();
        Log("vault cleared");
        RefreshState();
    }

    // -------------------------------------------------------------- state

    private void RefreshState()
    {
        bool on = _engine is not null;
        StatusText.Text = !_protectedModeAvailable ? "Unavailable" : on ? "On" : "Off";
        var colour = Brush(on ? "#30A46C" : "#E5484D");
        StatusText.Foreground = colour;
        StatusDot.Fill = colour;
        BtnToggle.Content = on ? "Turn off" : "Turn on";
        BtnToggle.Background = Brush(on ? "#8B2C32" : "#3E63DD");

        var left = _lease.Remaining;
        if (left > TimeSpan.Zero)
        {
            var mode = EffectiveMode;
            LeaseText.Text = $"Unlocked for pid {_lease.PinnedPid} and its children — " +
                             $"{left:mm\\:ss} remaining " +
                             $"({(mode == PresenceMode.None ? "no presence check" : PresenceSettings.Describe(mode))})";
            LeaseText.Foreground = Brush(mode == PresenceMode.None ? "#E5484D" : "#30A46C");
        }
        else
        {
            LeaseText.Text = "Locked — requests go out without the session";
            LeaseText.Foreground = Brush("#F5A524");
        }

        var hosts = _vault?.Hosts ?? Array.Empty<string>();
        VaultText.Text = hosts.Count == 0
            ? "empty"
            : string.Join("\n", hosts.Select(h =>
                $"{h}: {string.Join(", ", _vault!.Names(h))}"));
    }

    private static SolidColorBrush Brush(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex)!);

    private void Log(string line)
    {
        _log.AppendLine($"{DateTime.Now:HH:mm:ss}  {line}");
        if (_log.Length > 16000) _log.Remove(0, 8000);
        LogText.Text = _log.ToString();
        LogScroll.ScrollToEnd();
    }

    private void SafeRestore()
    {
        try { _sysProxy.Restore(); } catch { }
    }

    private async void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        _timer.Stop();
        SafeRestore();
        if (_engine is not null)
        {
            await _engine.DisposeAsync();
            _engine = null;
        }
        (_sealer as IDisposable)?.Dispose();
    }
}
