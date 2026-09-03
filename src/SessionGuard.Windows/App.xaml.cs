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
    //
    // The name is Global, not Local. Local is scoped to a single Windows
    // terminal session, so a copy left running on the console is invisible to a
    // copy started over Remote Desktop, and the two then contend for one
    // registry key — precisely the situation this exists to prevent. It is
    // scoped to the user instead, since the settings being contended are
    // per-user and two different accounts are not in each other's way.
    private static readonly string InstanceName =
        @"Global\SessionGuard.SingleInstance.v2." + Environment.UserName;
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
