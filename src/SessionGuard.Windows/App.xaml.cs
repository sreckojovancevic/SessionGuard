using System;
using System.Threading;
using System.Windows;

namespace SessionGuard.Windows;

public partial class App : Application
{
    // One instance only. Two copies would each own a "previous" system-proxy
    // state and each restore it on exit, so the second one's shutdown silently
    // undoes the first one's Turn on — the setting reverts with nothing in
    // either log to explain it.
    private const string InstanceName = @"Local\SessionGuard.SingleInstance.v1";
    private Mutex? _instance;

    protected override void OnStartup(StartupEventArgs e)
    {
        _instance = new Mutex(initiallyOwned: true, InstanceName, out bool first);
        if (!first)
        {
            MessageBox.Show(
                "SessionGuard is already running.\n\n" +
                "Only one copy may run at a time: each instance restores the " +
                "system proxy when it exits, so a second one closing would " +
                "silently switch the first one off.",
                "SessionGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown();
            return;
        }
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _instance?.ReleaseMutex(); } catch (ApplicationException) { }
        _instance?.Dispose();
        base.OnExit(e);
    }
}
