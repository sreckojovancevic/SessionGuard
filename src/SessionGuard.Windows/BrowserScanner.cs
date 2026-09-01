using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using SessionGuard.Core.Authz;

namespace SessionGuard.Windows;

/// <summary>
/// Finds the process to pin a lease to.
///
/// The first version keyed on Process.MainWindowHandle, which is fragile: the
/// handle is zero before the window exists, for a minimised or restoring
/// browser, and whenever window enumeration is unavailable to us. When it
/// returned nothing the list was simply empty, with no way to tell why.
///
/// Roots are identified structurally instead: among all running browser
/// processes, a root is one whose parent is not itself one of them. That is
/// exactly the handle PeerAuthorizer's lineage walk needs, since the socket is
/// owned by a descendant (Chromium's network service), not by the root.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BrowserScanner
{
    public static readonly string[] KnownBrowsers =
        { "chrome", "msedge", "brave", "vivaldi", "opera", "opera_gx", "firefox" };

    private readonly IPeerResolver _resolver;

    public BrowserScanner(IPeerResolver resolver) => _resolver = resolver;

    public sealed record Candidate(int Pid, string Name, int ParentPid, bool HasWindow)
    {
        public bool IsRoot { get; init; }
        public override string ToString() =>
            $"{Name} (pid {Pid}){(HasWindow ? "" : " — no window")}";
    }

    public sealed record ScanResult(
        IReadOnlyList<Candidate> Roots,
        IReadOnlyList<Candidate> All,
        string Diagnosis);

    public ScanResult Scan()
    {
        var all = new List<Candidate>();
        var errors = new List<string>();

        // Enumerate everything and filter by name: GetProcessesByName has to be
        // called per name and hides the fact that nothing matched at all.
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string name = p.ProcessName;
                if (!KnownBrowsers.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;

                int ppid = -1;
                try { ppid = _resolver.Describe(p.Id)?.ParentPid ?? -1; }
                catch (Exception ex) { errors.Add($"{name}/{p.Id}: {ex.GetType().Name}"); }

                bool window = false;
                try { window = p.MainWindowHandle != IntPtr.Zero; } catch { }

                all.Add(new Candidate(p.Id, name, ppid, window));
            }
            catch (Exception ex)
            {
                errors.Add(ex.GetType().Name);
            }
            finally
            {
                p.Dispose();
            }
        }

        var pids = all.Select(c => c.Pid).ToHashSet();
        var roots = all
            .Select(c => c with { IsRoot = !pids.Contains(c.ParentPid) })
            .Where(c => c.IsRoot)
            // A root that owns a window first: that is the one the user sees.
            .OrderByDescending(c => c.HasWindow)
            .ThenBy(c => c.Pid)
            .ToList();

        // If the structure says nothing is a root — unusual, but possible with
        // an unreadable parent — offer everything rather than an empty list.
        if (roots.Count == 0 && all.Count > 0)
            roots = all.OrderByDescending(c => c.HasWindow).ThenBy(c => c.Pid).ToList();

        string diagnosis = all.Count == 0
            ? "no browser process found (looked for: " +
              string.Join(", ", KnownBrowsers) + "). Start the browser, then Refresh — " +
              "or type its pid directly."
            : $"{all.Count} browser process(es), {roots.Count} root(s)" +
              (errors.Count > 0 ? $"; {errors.Count} could not be inspected: " +
                                  string.Join(", ", errors.Take(3)) : "");

        return new ScanResult(roots, all, diagnosis);
    }
}
