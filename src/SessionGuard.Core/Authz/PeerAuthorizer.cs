using System;
using System.Collections.Generic;
using System.Net;

namespace SessionGuard.Core.Authz;

/// <summary>Identity of a local process, enough to place it in a process tree.</summary>
public sealed record PeerIdentity(
    int Pid,
    DateTime StartTime,
    int ParentPid,
    string? ImagePath)
{
    public string Describe() =>
        $"pid={Pid} ppid={ParentPid} exe={ImagePath ?? "?"}";
}

/// <summary>Maps a loopback connection back to the local process that opened it.</summary>
public interface IPeerResolver
{
    /// <summary>
    /// <paramref name="clientEndpoint"/> is the remote endpoint of our accepted
    /// socket, i.e. the client's own local port. The client's row in the OS
    /// table therefore has LocalPort == that port and RemotePort == our listen
    /// port — matching them the other way round finds our own socket and
    /// returns the guard's own pid.
    /// </summary>
    PeerIdentity? ResolveOwner(IPEndPoint clientEndpoint, int listenPort);

    /// <summary>Identity of an arbitrary pid, for walking the parent chain.</summary>
    PeerIdentity? Describe(int pid);
}

/// <summary>Time-boxed authority, opened by a verified user gesture.</summary>
public sealed class PresenceLease
{
    private readonly object _gate = new();
    private int _pid = -1;
    private DateTime _started;
    private DateTime _expiry = DateTime.MinValue;

    public void Open(int pid, DateTime startTime, TimeSpan duration)
    {
        lock (_gate)
        {
            _pid = pid;
            _started = startTime;
            _expiry = DateTime.Now + duration;
        }
    }

    public void Close()
    {
        lock (_gate)
        {
            _pid = -1;
            _expiry = DateTime.MinValue;
        }
    }

    public bool IsActive
    {
        get { lock (_gate) return _pid != -1 && DateTime.Now <= _expiry; }
    }

    public TimeSpan Remaining
    {
        get
        {
            lock (_gate)
            {
                var left = _expiry - DateTime.Now;
                return left > TimeSpan.Zero ? left : TimeSpan.Zero;
            }
        }
    }

    public int PinnedPid { get { lock (_gate) return _pid; } }

    internal (int pid, DateTime started) Snapshot()
    {
        lock (_gate) return (_pid, _started);
    }
}

/// <summary>
/// Decides whether a connection may have the vault attached.
///
/// Pinning to the socket owner alone does not work against a real browser.
/// Chromium opens its sockets from the out-of-process network service, a child
/// of the browser process, so the pid that owns the connection is not the pid
/// the user unlocked. The rule is therefore lineage: the socket owner must be
/// the pinned process, or a descendant of that exact process instance.
///
/// The walk is deliberately conservative:
///   - the pinned process is matched by pid AND start time, so a recycled pid
///     inherits nothing;
///   - each step up requires the parent to have started no later than the
///     child, which discards stale ParentProcessId values pointing at an
///     unrelated newer process;
///   - the chain is bounded, so a cycle cannot hang the proxy.
///
/// Honest limit: on Windows a process can be created with an arbitrary declared
/// parent (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), so lineage raises the bar but
/// is forgeable by an attacker already running as this user. It is defence in
/// depth. The property that does not depend on it is that the vault cannot be
/// exfiltrated from the machine at all.
/// </summary>
public sealed class PeerAuthorizer
{
    public const int MaxAncestorDepth = 12;

    private readonly IPeerResolver _resolver;

    public PeerAuthorizer(IPeerResolver resolver, PresenceLease lease)
    {
        _resolver = resolver;
        Lease = lease;
    }

    public PresenceLease Lease { get; }

    /// <summary>
    /// Opens the lease for a process, taking its start time from the same
    /// resolver that will later verify connections.
    ///
    /// This is the only way the lease should be opened. Reading the start time
    /// from one source at unlock (Process.StartTime) and computing it from
    /// another at check time (the OS process table) yields two values that
    /// never compare equal, and every request is then rejected as a recycled
    /// pid — a failure that looks exactly like an attack.
    /// </summary>
    public bool TryOpenLease(int pid, TimeSpan duration, out string reason)
    {
        PeerIdentity? identity;
        try { identity = _resolver.Describe(pid); }
        catch (Exception ex)
        {
            reason = $"could not inspect pid {pid}: {ex.GetType().Name}";
            return false;
        }
        if (identity is null)
        {
            reason = $"process {pid} not found";
            return false;
        }
        Lease.Open(pid, identity.StartTime, duration);
        reason = $"lease open for {identity.Describe()}";
        return true;
    }

    public bool Authorize(IPEndPoint clientEndpoint, int listenPort, out string reason)
    {
        var (pinnedPid, pinnedStart) = Lease.Snapshot();
        if (!Lease.IsActive)
        {
            reason = "no active presence lease";
            return false;
        }

        PeerIdentity? owner;
        try
        {
            owner = _resolver.ResolveOwner(clientEndpoint, listenPort);
        }
        catch (Exception ex)
        {
            reason = $"peer lookup failed: {ex.GetType().Name}";
            return false;
        }

        if (owner is null)
        {
            reason = "could not identify the calling process";
            return false;
        }

        return WalkToPinned(owner, pinnedPid, pinnedStart, out reason);
    }

    private bool WalkToPinned(PeerIdentity owner, int pinnedPid, DateTime pinnedStart,
                              out string reason)
    {
        var seen = new HashSet<int>();
        PeerIdentity current = owner;

        for (int depth = 0; depth < MaxAncestorDepth; depth++)
        {
            if (!seen.Add(current.Pid))
            {
                reason = "parent chain contains a cycle";
                return false;
            }

            if (current.Pid == pinnedPid)
            {
                if (current.StartTime != pinnedStart)
                {
                    reason = $"pid {pinnedPid} was recycled since the lease was opened";
                    return false;
                }
                reason = depth == 0
                    ? "authorized (pinned process)"
                    : $"authorized (descendant of pinned process, depth {depth})";
                return true;
            }

            if (current.ParentPid <= 0 || current.ParentPid == current.Pid) break;

            PeerIdentity? parent;
            try { parent = _resolver.Describe(current.ParentPid); }
            catch { parent = null; }
            if (parent is null) break;

            // A parent that started after its child is not really its parent:
            // the pid was recycled. Stop rather than climb a bogus chain.
            if (parent.StartTime > current.StartTime) break;

            current = parent;
        }

        reason = $"not the pinned process or a descendant of it: {owner.Describe()}";
        return false;
    }
}
