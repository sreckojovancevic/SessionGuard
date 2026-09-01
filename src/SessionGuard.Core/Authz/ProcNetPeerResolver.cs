using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;

namespace SessionGuard.Core.Authz;

/// <summary>
/// Linux peer resolver via /proc. Present so the end-to-end test can prove the
/// authorization path with real, separate OS processes — including the
/// distinction between a genuine descendant of the pinned browser and an
/// unrelated process. The Windows implementation uses GetExtendedTcpTable plus
/// Toolhelp32 and lives in the Windows project.
/// </summary>
public sealed class ProcNetPeerResolver : IPeerResolver
{
    private static readonly long TicksPerJiffy = TimeSpan.TicksPerSecond / 100;

    public PeerIdentity? ResolveOwner(IPEndPoint clientEndpoint, int listenPort)
    {
        ulong inode = FindInode(clientEndpoint.Port, listenPort);
        if (inode == 0) return null;
        int pid = FindPidForInode(inode);
        return pid > 0 ? Describe(pid) : null;
    }

    public PeerIdentity? Describe(int pid)
    {
        string stat;
        try { stat = File.ReadAllText($"/proc/{pid}/stat"); }
        catch { return null; }

        // comm can contain spaces and parentheses; fields after the last ')'.
        int close = stat.LastIndexOf(')');
        if (close < 0) return null;
        var fields = stat[(close + 1)..]
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // fields[0] = state, [1] = ppid, ... [19] = starttime (field 22 overall)
        if (fields.Length < 20) return null;
        if (!int.TryParse(fields[1], out int ppid)) return null;
        if (!ulong.TryParse(fields[19], out ulong startJiffies)) return null;

        string? exe = null;
        try { exe = File.ResolveLinkTarget($"/proc/{pid}/exe", true)?.FullName; }
        catch { }

        return new PeerIdentity(pid, BootTime().AddTicks((long)startJiffies * TicksPerJiffy),
                                ppid, exe);
    }

    private static DateTime? _bootTime;

    private static DateTime BootTime()
    {
        if (_bootTime is not null) return _bootTime.Value;
        double uptime = 0;
        try
        {
            var text = File.ReadAllText("/proc/uptime").Split(' ')[0];
            double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out uptime);
        }
        catch { }
        _bootTime = DateTime.Now.AddSeconds(-uptime);
        return _bootTime.Value;
    }

    private static ulong FindInode(int localPort, int remotePort)
    {
        foreach (string path in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
        {
            if (!File.Exists(path)) continue;
            foreach (string line in File.ReadLines(path).Skip(1))
            {
                var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (f.Length < 10) continue;
                if (!TryPort(f[1], out int lp) || lp != localPort) continue;
                if (!TryPort(f[2], out int rp) || rp != remotePort) continue;
                if (ulong.TryParse(f[9], out ulong inode)) return inode;
            }
        }
        return 0;
    }

    private static bool TryPort(string hexAddr, out int port)
    {
        port = 0;
        int colon = hexAddr.LastIndexOf(':');
        return colon >= 0 &&
               int.TryParse(hexAddr.AsSpan(colon + 1), NumberStyles.HexNumber, null, out port);
    }

    private static int FindPidForInode(ulong inode)
    {
        string want = $"socket:[{inode}]";
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), out int pid)) continue;
            string[] fds;
            try { fds = Directory.GetFiles(Path.Combine(dir, "fd")); }
            catch { continue; }

            foreach (var fd in fds)
            {
                try
                {
                    var target = File.ResolveLinkTarget(fd, false);
                    if (target is not null &&
                        (target.Name == want || target.FullName.EndsWith(want, StringComparison.Ordinal)))
                        return pid;
                }
                catch { }
            }
        }
        return -1;
    }
}
