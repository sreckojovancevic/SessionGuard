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

    /// <summary>host:name pairs the guard chose not to vault, for the UI.</summary>
    private readonly SortedSet<string> _leftAlone = new(StringComparer.OrdinalIgnoreCase);

    private bool _logging = true;
    private bool _logDirty;
    private int _suppressed;

    private readonly System.Collections.Concurrent.ConcurrentQueue<ProxyEvent> _events = new();

    private int _connections;
    private int _denied;
    private DateTime _guardOnAt = DateTime.MaxValue;

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
        _sysProxy.Applied += now => Dispatcher.BeginInvoke(() => Log("registry now says: " + now));
        _sysProxy.Restored += now => Dispatcher.BeginInvoke(() => Log("registry now says: " + now));
        _sysProxy.NothingToRestore += now => Dispatcher.BeginInvoke(() => Log(
            "left the system proxy alone — this run never changed it (" + now + ")"));
        _sysProxy.LoopbackOriginalIgnored += old => Dispatcher.BeginInvoke(() => Log(
            $"ignored a pre-existing loopback proxy setting ('{old}') — restoring it " +
            "later would have left this machine with no internet"));

        _devMode = Environment.GetCommandLineArgs()
            .Any(a => string.Equals(a, InsecureDevFlag, StringComparison.OrdinalIgnoreCase));

        OpenVault();

        AppDomain.CurrentDomain.ProcessExit += (_, _) => SafeRestore();
        SystemEvents.SessionEnding += (_, _) => SafeRestore();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => { DrainEvents(); RefreshState(); FlushLog(); };
        _timer.Start();

        PopulateEngines();
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

        // Chosen deliberately: no TPM is attempted at all, so a locked-out or
        // prompt-happy chip cannot get in the way of a mode that does not use it.
        if (_settings.Engine == VaultEngine.Software)
        {
            UseSoftwareSealer(chosenDeliberately: true, why: null);
            BtnToggle.IsEnabled = _protectedModeAvailable;
            BtnUnlock.IsEnabled = _protectedModeAvailable;
            return;
        }

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
        catch (Exception ex) when (_settings.Engine == VaultEngine.Automatic || _devMode)
        {
            // Automatic: fall back, but never quietly. The header changes, the
            // sealer line names the reason, and the log records it — so the
            // difference between "sealed to this TPM" and "sealed in memory" is
            // never something the user has to go looking for.
            UseSoftwareSealer(chosenDeliberately: false,
                              why: $"{ex.GetType().Name}: {ex.Message}");
        }
        catch (Exception ex)
        {
            // Engine is TPM by explicit choice: refuse rather than protect less
            // than was asked for. A security product that silently drops to a
            // weaker vault when its hardware root is missing is worse than one
            // that stops, because the user believes they are protected.
            _protectedModeAvailable = false;
            SubtitleText.Text = "PROTECTED MODE UNAVAILABLE";
            SubtitleText.Foreground = Brush("#E5484D");
            SealerText.Text = "no TPM-backed key: " + ex.Message;
            Log("protected mode unavailable — refusing to run without a hardware-sealed vault");

            // The reason belongs in the log, not only on the window. A saved log
            // is what gets sent to someone who can read it, and "unavailable"
            // without the cause makes that log useless — the difference between
            // a locked-out TPM, a key whose policy cannot be met in this session,
            // and no TPM at all is the whole diagnosis.
            Log($"  reason: {ex.GetType().Name}: {ex.Message}");
            if (ex is System.Security.Cryptography.CryptographicException ce)
                Log($"  win32: 0x{ce.HResult:X8}");
            Log($"  presence mode requested: {PresenceSettings.Describe(_settings.Mode)}");

            // One failure deserves its own explanation, because the provider's
            // own wording gives no remedy and the cause is a setting in this
            // window. The TPM counts every authorization it is asked for and
            // does not get — and a per-use consent prompt that is dismissed, or
            // that never appears because the session is remote, is exactly that.
            // Enough of them and the chip stops answering for a while.
            if (ex.Message.Contains("dictionary attack", StringComparison.OrdinalIgnoreCase))
            {
                SealerText.Text =
                    "the TPM is refusing for now: too many unanswered authorizations " +
                    "(its dictionary-attack defence). Wait for it to heal, then set " +
                    "Check to 'None' before pressing Reset key.";
                Log("  this is the TPM's dictionary-attack defence, not a broken key.");
                Log("  cause: authorizations that were asked for and not given. The " +
                    "'TPM consent prompt (per use)' mode asks per cookie per request, " +
                    "and over Remote Desktop those prompts may never appear at all.");
                Log("  it heals on its own — 'Get-Tpm' shows LockoutCount and " +
                    "LockoutHealTime (one count per heal interval).");
                Log("  to clear it now:  Reset-TpmLockout   (needs owner auth; do NOT " +
                    "run Clear-Tpm, which wipes every TPM key on the machine including " +
                    "BitLocker and Windows Hello).");
                Log("  then set Check to 'None' and press Reset key, so the new key " +
                    "carries no per-use consent and cannot re-trigger this.");
                Log("  note: Reset key has to open the existing key to delete it, so it " +
                    "will fail the same way until the TPM heals. Wait first.");
            }

            Log($"start with {InsecureDevFlag} only if you are testing.");
        }

        BtnToggle.IsEnabled = _protectedModeAvailable;
        BtnUnlock.IsEnabled = _protectedModeAvailable;
    }

    /// <summary>
    /// Opens the software-sealed vault, and says so where it cannot be missed.
    ///
    /// The wording differs by how we arrived here, because the two are not the
    /// same event. A deliberate choice is a decision the user made and should
    /// see confirmed; a fallback is something that happened to them, and the
    /// reason has to travel with it.
    /// </summary>
    private void UseSoftwareSealer(bool chosenDeliberately, string? why)
    {
        var soft = new SoftwareSealer();
        _sealer = soft;
        _vault = new SessionVault(soft);
        _protectedModeAvailable = true;

        SubtitleText.Text = "SOFTWARE VAULT — not sealed to this machine";
        SubtitleText.Foreground = Brush("#F5A524");
        SealerText.Foreground = Brush("#F5A524");
        SealerText.Text =
            $"sealer: {soft.Name} — the key lives in this process's memory, so the " +
            "vault is not bound to this machine. Session cookies still never reach " +
            "the browser profile, and nothing survives exit.";

        if (chosenDeliberately)
        {
            Log($"vault engine: {PresenceSettings.Describe(VaultEngine.Software)} (chosen)");
        }
        else
        {
            SealerText.Text += "  |  the TPM was tried first and refused.";
            Log("vault engine: TPM unavailable, fell back to software");
            if (why is not null) Log("  reason: " + why);
            Log("  set the engine to 'TPM 2.0 only' if this machine should refuse " +
                "to run without hardware sealing.");
        }

        if (_settings.Mode == PresenceMode.TpmConsent)
            Log("note: the software vault has no per-use consent, so the presence " +
                "check is effectively None. The lease still expires and is still " +
                "pinned to one browser.");
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

    /// <summary>
    /// Every step announces itself before it runs. The system proxy is written
    /// last, so anything that fails earlier — an untrusted root, a port already
    /// held by another copy — leaves the registry untouched, which from outside
    /// is indistinguishable from "the application cannot write the proxy
    /// setting". The line logged before each step is what tells those apart.
    /// </summary>
    private void TurnOn(SessionVault vault)
    {
        Log("turn on: checking the root certificate");
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

        Log($"turn on: opening the listener on 127.0.0.1:{ListenPort}");
        var options = new ProxyOptions(ListenPort, hosts);
        var engine = new ProxyEngine(options, vault, _authorizer, _ca);
        // Queue, do not marshal. Events arrive on the proxy's connection threads,
        // and since tracing became per-request a busy site emits several per
        // request. One Dispatcher.BeginInvoke each would post thousands of work
        // items onto the UI thread, which stops responding to the user while it
        // works through a backlog describing traffic that has already finished.
        // The queue is drained once per timer tick instead, so the network path
        // never waits on the interface.
        engine.Observed += _events.Enqueue;
        engine.Start();
        _engine = engine;
        _connections = 0;
        _denied = 0;
        _guardOnAt = DateTime.Now;

        Log("turn on: writing the system proxy setting");
        _sysProxy.Apply($"127.0.0.1:{ListenPort}");
        Log($"guard on; system proxy -> 127.0.0.1:{ListenPort}");

        // The same check as at Unlock, from the other side. Unlocking before
        // turning the guard on is a perfectly reasonable thing to do, and it
        // silently skipped the warning: at that moment there was no guard to
        // compare the browser's start time against. A check that only fires in
        // one order is not a check.
        if (_lease.IsActive) WarnIfOlderThanGuard(_lease.PinnedPid);
    }

    private async Task TurnOffAsync()
    {
        Log("turn off: restoring the system proxy setting");
        _guardOnAt = DateTime.MaxValue;
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

    private async void BtnSaveHosts_Click(object sender, RoutedEventArgs e)
    {
        var entered = (TxtHosts.Text ?? "")
            .Split(new[] { ',', ';', ' ', '\n', '\r', '\t' },
                   StringSplitOptions.RemoveEmptyEntries);
        _hosts.Save(entered);
        LoadHosts();
        if (_engine is not null)
            Log("host list saved — turn the guard off and on for it to take effect");

        BtnSaveHosts.IsEnabled = false;
        try { await ProbeHostsAsync(); }
        finally { BtnSaveHosts.IsEnabled = true; }
    }

    /// <summary>
    /// Checks each host as it is added, so a site that cannot be intercepted is
    /// reported now rather than breaking silently later. A wildcard entry is
    /// probed at its bare domain — all that can be checked without guessing
    /// subdomain names, which is exactly why the result is worded as an
    /// observation and not a promise.
    /// </summary>
    private async Task ProbeHostsAsync()
    {
        var hosts = _hosts.Load();
        if (hosts.Count == 0) return;

        Log("checking hosts…");
        bool anyProblem = false;

        foreach (string entry in hosts)
        {
            string host = entry.StartsWith("*.", StringComparison.Ordinal)
                ? entry[2..]
                : entry;
            var result = await HostProbe.RunAsync(host).ConfigureAwait(true);
            Log("  " + result.Summary);
            if (!result.CanIntercept) anyProblem = true;
        }

        Log("  note: " + ProbeResult.Caveat);
        if (anyProblem)
            MessageBox.Show(
                "One or more hosts cannot be intercepted — see the log.\n\n" +
                "They will still work; they simply pass through unprotected.",
                "SessionGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
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

    private sealed record EngineChoice(VaultEngine Engine, string Label)
    {
        public override string ToString() => Label;
    }

    private void PopulateEngines()
    {
        _loadingModes = true;
        var choices = new[] { VaultEngine.Automatic, VaultEngine.Tpm, VaultEngine.Software }
            .Select(v => new EngineChoice(v, PresenceSettings.Describe(v))).ToArray();
        CmbEngine.ItemsSource = choices;
        CmbEngine.SelectedIndex =
            Math.Max(0, Array.FindIndex(choices, c => c.Engine == _settings.Engine));
        _loadingModes = false;
    }

    /// <summary>
    /// Changing the engine changes the key, so everything sealed under the old
    /// one is unreadable. Saying that before the change rather than after is the
    /// difference between a warning and an apology.
    /// </summary>
    private async void CmbEngine_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingModes) return;
        if (CmbEngine.SelectedItem is not EngineChoice choice) return;
        if (choice.Engine == _settings.Engine) return;

        if (_vault is { } v && v.Hosts.Count > 0)
        {
            var answer = MessageBox.Show(
                "Changing the vault engine changes the key that protects it.\n\n" +
                "Everything currently held becomes unreadable, so you will be " +
                "signed out of protected sites and will have to log in again.\n\n" +
                "Continue?",
                "SessionGuard", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.OK)
            {
                PopulateEngines();     // put the selection back
                return;
            }
        }

        _settings.Engine = choice.Engine;
        Log($"vault engine set to: {PresenceSettings.Describe(choice.Engine)}");

        if (_engine is not null) await TurnOffAsync();
        _leftAlone.Clear();
        OpenVault();
        RefreshPresenceCaveat();
        RefreshState();
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
            Log($"  {c.Name} pid={c.Pid} ppid={c.ParentPid} window={c.HasWindow} " +
                $"owner={c.Owner ?? "(unreadable)"}{(c.ForeignOwner ? "  <-- different account" : "")}");
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
                // Two Firefox-specific walls, and the order matters: nothing can
                // fail on the certificate until traffic actually arrives.
                //
                // The proxy one is stated as observation, not theory. Firefox's
                // default is to follow the Windows setting and in principle that
                // works; in practice, on the machine this was developed against,
                // it never picked it up — a Firefox started after the guard, the
                // registry confirming the proxy was on, and not one connection
                // arriving, while every other application on the same machine
                // went through it. Setting it by hand fixed it immediately.
                Log("firefox selected — it needs two things Edge and Brave do not:");
                Log("  1. set the proxy BY HAND. Settings -> Network Settings -> " +
                    $"Manual proxy configuration, 127.0.0.1 port {ListenPort}, and tick " +
                    "'Also use this proxy for HTTPS'. 'Use system proxy settings' " +
                    "has been observed not to take effect at all.");
                Log("  2. trust the certificate. Firefox keeps its own store: set " +
                    "security.enterprise_roots.enabled in about:config, or press " +
                    "'Export CA' and import the file under Authorities.");
            }

            WarnIfOlderThanGuard(chosenPid);

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

    /// <summary>
    /// A browser that was already running when the guard was turned on may never
    /// have seen the proxy setting.
    ///
    /// Browsers read the Windows proxy configuration at startup. Some notice a
    /// later change and some do not — Firefox in particular caches it, and a
    /// Firefox that believes there is no proxy also enables HTTP/3, so its
    /// traffic leaves over UDP and does not pass the guard even in principle.
    ///
    /// From inside the application this is indistinguishable from success: the
    /// registry is written, the read-back confirms it, the listener is up, the
    /// lease is open — and nothing ever arrives. It cost three days to find by
    /// hand. The process start time answers it in one comparison.
    /// </summary>
    private void WarnIfOlderThanGuard(int pid)
    {
        if (_guardOnAt == DateTime.MaxValue) return;      // guard is not on
        var identity = _resolver.Describe(pid);
        if (identity is null || identity.StartTime >= _guardOnAt) return;

        Log($"note: this browser (pid {pid}) started at {identity.StartTime:HH:mm:ss}, " +
            $"before the guard was turned on at {_guardOnAt:HH:mm:ss}");
        MessageBox.Show(
            "This browser was already running when the guard was turned on.\n\n" +
            "Browsers read the Windows proxy setting when they start, and some " +
            "never notice a later change — so this one may still be sending its " +
            "traffic straight past SessionGuard.\n\n" +
            "If nothing appears in the log while you browse, close the browser " +
            "completely and start it again now.",
            "SessionGuard", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    /// <summary>
    /// Writes the root certificate out as a file.
    ///
    /// Windows trust is not universal trust. Adding the root to the user's
    /// Windows store covers Edge, Brave and Chrome, and covers nothing in Firefox,
    /// which keeps its own <c>cert9.db</c> per profile. The two are independent
    /// walls and they fail in the wrong order: traffic has to reach the guard
    /// before a certificate error can even appear, so the second problem stays
    /// hidden until the first is solved.
    ///
    /// Only the public certificate is exported — never the private key, which
    /// stays under DPAPI. A file is as far as this goes: writing into another
    /// application's certificate store is that application's business, and a
    /// tool that edits browser profiles behind the user's back is the shape of
    /// the thing this project exists to defend against.
    /// </summary>
    private void BtnExportCa_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "SessionGuard-root-CA.cer");
            File.WriteAllBytes(path, _ca.Root.Export(X509ContentType.Cert));
            Log("root CA exported to " + path);
            MessageBox.Show(
                "Saved to:\n\n" + path + "\n\n" +
                "Edge, Brave and Chrome use the Windows store and already trust it.\n\n" +
                "Firefox keeps its own certificate store, so it needs one of:\n\n" +
                "  • about:config -> security.enterprise_roots.enabled = true\n" +
                "    (Firefox then reads the Windows store; nothing to import)\n\n" +
                "  • Settings -> Privacy & Security -> Certificates ->\n" +
                "    View Certificates -> Authorities -> Import -> this file,\n" +
                "    ticking \"Trust this CA to identify websites\"\n\n" +
                "Restart the browser afterwards — and start it after the guard " +
                "is on, or it may not pick up the proxy setting.",
                "SessionGuard root certificate");
        }
        catch (Exception ex)
        {
            Log("could not export root CA: " + ex.Message);
            MessageBox.Show(ex.Message, "SessionGuard",
                            MessageBoxButton.OK, MessageBoxImage.Error);
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
        else if (_denied > 0)
        {
            // The state that cost days to recognise. Interception is running and
            // the lease is shut, so guarded cookies are taken out of the browser
            // and never put back: protected sites are signed out and stay that
            // way. Nothing is broken, everything is behaving as written — and
            // from the browser it looks exactly like the site rejecting you.
            //
            // "Locked" alone did not carry that. A count of requests actually
            // sent without their session does.
            LeaseText.Text =
                $"LOCKED — {_denied} request(s) sent without their session.\n" +
                "Protected sites will act signed-out until you press Unlock.";
            LeaseText.Foreground = Brush("#E5484D");
        }
        else
        {
            LeaseText.Text = "Locked — requests go out without the session";
            LeaseText.Foreground = Brush("#F5A524");
        }

        try
        {
            string state = _sysProxy.ReadBack();
            // Amber when the app is on but Windows does not agree — that is the
            // case worth noticing, and the one that used to need a trip to
            // Internet Options to diagnose.
            bool windowsAgrees = state.Contains($"127.0.0.1:{ListenPort}");
            bool disagreement = on != windowsAgrees;

            // The registry saying ON only means Windows was told. Whether any
            // browser is actually listening to it is a different question, and
            // it has its own answer: connections arriving, or not. A guard that
            // has been on for a while and has seen nothing is not protecting
            // anything, and saying so beats leaving the user to infer it from
            // an empty vault.
            string silent = "";
            if (on && windowsAgrees && _connections == 0 &&
                DateTime.Now - _guardOnAt > TimeSpan.FromSeconds(45))
            {
                silent = $"\nno connections in {(DateTime.Now - _guardOnAt).TotalMinutes:F0} min — " +
                         "nothing is using this proxy. Check the browser's own proxy setting, " +
                         $"and that it runs as {Environment.UserDomainName}\\{Environment.UserName}.";
            }

            ProxyStateText.Text = state + silent;
            ProxyStateText.Foreground = Brush(
                disagreement || silent.Length > 0 ? "#F5A524" : "#8B93A1");
        }
        catch (Exception ex)
        {
            ProxyStateText.Text = "could not read system proxy: " + ex.Message;
            ProxyStateText.Foreground = Brush("#E5484D");
        }

        var skipped = _engine?.Skipped.Current ?? Array.Empty<SkippedHost>();
        SkippedText.Text = skipped.Count == 0
            ? ""
            : $"{skipped.Count} host(s) passing through UNPROTECTED: " +
              string.Join("; ", skipped.Select(x => x.ToString()));

        var hosts = _vault?.Hosts ?? Array.Empty<string>();
        VaultText.Text = hosts.Count == 0
            ? "empty"
            : string.Join("\n", hosts.Select(h =>
                $"{h}: {string.Join(", ", _vault!.Names(h))}"));

        // Naming what was deliberately not taken. These cookies stay in the
        // browser profile, so they are exactly as stealable as before — and a
        // user reading a short vault list has no way to tell that from a bug.
        var lines = new List<string>();
        if (_leftAlone.Count > 0)
            lines.Add("left with the browser (script-readable, not HttpOnly): " +
                      string.Join(", ", _leftAlone.OrderBy(x => x)));

        // And what was never taken at all, which is the more dangerous half.
        // An empty or thin vault beside a working site reads as success; it is
        // the same picture as protection that never engaged.
        var never = _engine?.NeverCaptured ?? Array.Empty<string>();
        if (never.Count > 0)
            lines.Add($"NOT PROTECTED — {never.Count} cookie(s) the guard never saw: " +
                      string.Join(", ", never.OrderBy(x => x)) +
                      ".\nThe browser had them before the guard did. If a session " +
                      "cookie is among them, sign out and sign in again now that " +
                      "the guard is running.");

        LeftAloneText.Text = string.Join("\n", lines);
        LeftAloneText.Foreground = Brush(never.Count > 0 ? "#E5484D" : "#F5A524");
    }

    private static SolidColorBrush Brush(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex)!);

    /// <summary>
    /// Appends a line, unless recording is switched off.
    ///
    /// Two separate things are being managed here, and conflating them is what
    /// made the log unpleasant once per-request tracing arrived.
    ///
    /// <para><b>Whether to record at all.</b> The Logging checkbox. Off means
    /// off — including the lines this application writes about itself, because a
    /// switch that keeps logging some things is a switch nobody can reason
    /// about. Suppressed lines are counted and the count is reported when
    /// recording resumes, so a gap is never mistaken for a quiet period.</para>
    ///
    /// <para><b>When to redraw.</b> Not here. Assigning <c>LogText.Text</c>
    /// copies the whole buffer and forces a re-layout, which on a busy site with
    /// a line per request is enough to make the window stutter. The buffer is
    /// appended to immediately and the control is refreshed once per timer tick
    /// instead — a second of latency on a diagnostic log, in exchange for a UI
    /// that does not fight the traffic it is describing.</para>
    /// </summary>
    private void Log(string line)
    {
        if (!_logging) { _suppressed++; return; }
        _log.AppendLine($"{DateTime.Now:HH:mm:ss}  {line}");
        if (_log.Length > 200_000) _log.Remove(0, 100_000);
        _logDirty = true;
    }

    /// <summary>
    /// Drains proxy events on the UI thread. Bounded per tick: if traffic
    /// outruns the interface the excess is dropped and counted rather than
    /// allowed to grow without limit, since a log nobody can read is not worth
    /// the memory it costs.
    /// </summary>
    private void DrainEvents()
    {
        const int MaxPerTick = 400;
        int handled = 0;
        while (handled < MaxPerTick && _events.TryDequeue(out ProxyEvent? ev))
        {
            handled++;
            Log(ev.ToString());

            if (ev.Kind is "tunnel" or "intercept" or "tunnel_unprotected")
                _connections++;
            if (ev.Kind == "injection_denied") _denied++;
            if (ev.Kind == "injected") _denied = 0;   // the lease is doing its job now

            // Independent of the Logging checkbox: this drives the Vault panel,
            // which states what is deliberately left unprotected. Turning off
            // the log must not turn off a security-relevant readout.
            if (ev.Kind == "left_to_browser" && ev.Host is not null && ev.Detail is not null)
                foreach (var n in ev.Detail.Split(' ')[0]
                                    .Split(',', StringSplitOptions.RemoveEmptyEntries))
                    _leftAlone.Add($"{ev.Host}:{n}");
        }

        if (handled == MaxPerTick && _events.Count > 5000)
        {
            _events.Clear();
            bool was = _logging;
            _logging = true;
            Log("log backlog discarded — events are arriving faster than they can be shown");
            _logging = was;
        }
    }

    /// <summary>Called from the timer: one redraw per tick, and only if needed.</summary>
    private void FlushLog()
    {
        if (!_logDirty) return;
        _logDirty = false;

        // Autoscroll only if the view is already at the bottom. Yanking the
        // scrollbar away from someone reading an earlier line is the reason
        // logs get saved to a file and read in Notepad instead.
        bool atEnd = LogScroll.ScrollableHeight - LogScroll.VerticalOffset < 24;
        LogText.Text = _log.ToString();
        if (atEnd) LogScroll.ScrollToEnd();
    }

    private void ChkLogging_Changed(object sender, RoutedEventArgs e)
    {
        _logging = ChkLogging.IsChecked == true;
        if (_logging)
        {
            int missed = _suppressed;
            _suppressed = 0;
            Log(missed == 0
                ? "logging resumed"
                : $"logging resumed — {missed} line(s) were not recorded while it was off");
        }
        else
        {
            _logging = true;                    // so this one line gets through
            Log("logging off — the guard keeps running, nothing else changes");
            _logging = false;
            FlushLog();
        }
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e)
    {
        _log.Clear();
        _suppressed = 0;
        // Never leave the log without context. A cleared log that then records
        // only `tunnel host` lines cannot be read afterwards: whether the guard
        // was even on, which port it was listening on, and which hosts were
        // supposed to be protected are exactly the questions the missing lines
        // would have answered.
        WriteHeader("log cleared");
        _logDirty = true;
        FlushLog();
    }

    /// <summary>
    /// The state of everything a log line could be misread without. Metadata
    /// only — host names and cookie names, never a cookie value.
    /// </summary>
    private void WriteHeader(string why)
    {
        bool was = _logging;
        _logging = true;                        // a header is worth an exception
        Log($"--- {why} ---");
        Log($"  guard: {(_engine?.IsRunning == true ? $"on, listening on 127.0.0.1:{_engine.ListenPort}" : "off")}");
        if (_engine?.IsRunning == true)
            Log($"  connections since turn on: {_connections}" +
                (_connections == 0 ? "  <-- nothing is using this proxy" : ""));
        try { Log($"  windows: {_sysProxy.ReadBack()}"); } catch { }
        var hosts = _hosts.Load();
        Log($"  protected hosts: {(hosts.Count == 0 ? "(none)" : string.Join(", ", hosts))}");
        // The effective mode, not the selected one. A vault with no per-use
        // policy cannot honour "TPM consent prompt", and a header that prints
        // the request rather than the reality is the kind of quiet inaccuracy
        // this log exists to eliminate.
        var effective = EffectiveMode;
        string presence = PresenceSettings.Describe(effective);
        if (effective != _settings.Mode)
            presence += $" (selected: {PresenceSettings.Describe(_settings.Mode)}, " +
                        "not available with this vault)";

        Log($"  vault engine: {PresenceSettings.Describe(_settings.Engine)}" +
            (_sealer is null ? "" : $"  [{_sealer.Name}]"));
        Log($"  presence: {presence}; " +
            $"lease: {(_lease.IsActive ? $"open for pid {_lease.PinnedPid}, {_lease.Remaining.TotalMinutes:F0} min left" : "locked")}");
        var scopes = _vault?.Hosts ?? Array.Empty<string>();
        Log($"  vault: {(scopes.Count == 0 ? "empty" : string.Join("; ", scopes.Select(h => $"{h}=[{string.Join(",", _vault!.Names(h))}]")))}");
        if (_leftAlone.Count > 0)
            Log($"  left to browser: {string.Join(", ", _leftAlone)}");
        var neverSeen = _engine?.NeverCaptured ?? Array.Empty<string>();
        if (neverSeen.Count > 0)
            Log($"  NOT PROTECTED ({neverSeen.Count}): {string.Join(", ", neverSeen)}" +
                "  <-- the browser had these before the guard saw them");
        Log($"  running as: {Environment.UserDomainName}\\{Environment.UserName}");
        _logging = was;
    }

    private void BtnSaveLog_Click(object sender, RoutedEventArgs e)
    {
        // Anything still queued belongs in the file the user is about to read.
        DrainEvents();
        WriteHeader("state at save");
        FlushLog();
        try
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SessionGuard",
                $"log-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            File.WriteAllText(path, _log.ToString());
            Log("log saved to " + path);
            MessageBox.Show("Saved to:\n\n" + path, "SessionGuard");
        }
        catch (Exception ex)
        {
            Log("could not save log: " + ex.Message);
            MessageBox.Show(ex.Message, "SessionGuard",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
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
