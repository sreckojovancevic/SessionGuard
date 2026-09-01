using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SessionGuard.Core.Authz;

namespace SessionGuard.Windows;

/// <summary>
/// Resolves the local process behind a loopback connection via
/// GetExtendedTcpTable, and its parent via a Toolhelp32 snapshot.
///
/// Two details that are easy to get wrong and impossible to notice when you do:
///
///   tuple direction  Our accepted socket has LocalPort = the listener and
///                    RemotePort = the client's ephemeral port; the client's row
///                    is the mirror image. Searching for RemotePort == ephemeral
///                    finds our own socket and returns the guard's own pid.
///
///   the parent       Chromium opens sockets from its network-service child, so
///                    the owning pid is never the browser pid the user picked.
///                    PeerAuthorizer walks up this chain; .NET does not expose
///                    a parent pid, hence Toolhelp32.
///
/// Start times come from Process.StartTime here and nowhere else, so the value
/// recorded when the lease opens and the value compared on each request are
/// produced the same way.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TcpTablePeerResolver : IPeerResolver
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    public PeerIdentity? ResolveOwner(IPEndPoint clientEndpoint, int listenPort)
    {
        ushort wantLocal = (ushort)clientEndpoint.Port;
        ushort wantRemote = (ushort)listenPort;

        // A client may reach 127.0.0.1 over either family; check both.
        int pid = Scan(AF_INET, wantLocal, wantRemote);
        if (pid <= 0) pid = Scan(AF_INET6, wantLocal, wantRemote);
        return pid > 0 ? Describe(pid) : null;
    }

    public PeerIdentity? Describe(int pid)
    {
        DateTime start;
        string? image = null;
        try
        {
            using var proc = Process.GetProcessById(pid);
            start = proc.StartTime;
            try { image = proc.MainModule?.FileName; } catch { /* access denied */ }
        }
        catch (Exception)
        {
            return null;
        }
        return new PeerIdentity(pid, start, ParentOf(pid), image);
    }

    // ------------------------------------------------------------ tcp table

    private static int Scan(int family, ushort wantLocal, ushort wantRemote)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return -1;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, family,
                                    TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return -1;

            int count = Marshal.ReadInt32(buffer);
            IntPtr row = buffer + 4;
            int stride = family == AF_INET
                ? Marshal.SizeOf<MIB_TCPROW_OWNER_PID>()
                : Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < count; i++, row += stride)
            {
                ushort local, remote;
                int pid;
                if (family == AF_INET)
                {
                    var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(row);
                    local = Port(r.dwLocalPort);
                    remote = Port(r.dwRemotePort);
                    pid = (int)r.dwOwningPid;
                }
                else
                {
                    var r = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(row);
                    local = Port(r.dwLocalPort);
                    remote = Port(r.dwRemotePort);
                    pid = (int)r.dwOwningPid;
                }

                if (local == wantLocal && remote == wantRemote) return pid;
            }
            return -1;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Ports sit in the low two bytes of a DWORD, in network order.</summary>
    private static ushort Port(uint dword)
    {
        byte hi = (byte)(dword & 0xFF);
        byte lo = (byte)((dword >> 8) & 0xFF);
        return (ushort)((hi << 8) | lo);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }

    // --------------------------------------------------------- parent lookup

    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    private static int ParentOf(int pid)
    {
        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return -1;
        try
        {
            var entry = new PROCESSENTRY32 { dwSize = Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snapshot, ref entry)) return -1;
            do
            {
                if (entry.th32ProcessID == (uint)pid)
                    return (int)entry.th32ParentProcessID;
            }
            while (Process32Next(snapshot, ref entry));
            return -1;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public int dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
