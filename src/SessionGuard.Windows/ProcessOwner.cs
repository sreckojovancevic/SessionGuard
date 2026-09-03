using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace SessionGuard.Windows;

/// <summary>
/// Which Windows account a process runs as.
///
/// This exists because of a failure that is invisible without it. The system
/// proxy lives in HKCU, so it is per-account: SessionGuard writes it into the
/// account SessionGuard runs as, and a browser running as a different account
/// reads a different HKCU and never sees it. From inside the application
/// everything looks correct — the registry is written, the read-back confirms
/// it, the guard is listening — and yet no connection ever arrives. The only
/// way to tell that apart from "the browser ignores the setting" is to ask who
/// owns the browser process.
///
/// Failure is expected and not an error: a process belonging to another user,
/// or a protected process, will refuse to open. Those come back as null and
/// are reported as unknown rather than swallowed.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ProcessOwner
{
    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    /// <summary>DOMAIN\user for the process, or null if it cannot be determined.</summary>
    public static string? Of(int pid)
    {
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            if (!OpenProcessToken(process, TOKEN_QUERY, out IntPtr token)) return null;
            try { return NameFromToken(token); }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(process); }
    }

    private static string? NameFromToken(IntPtr token)
    {
        GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out int size);
        if (size <= 0 && Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            return null;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetTokenInformation(token, TokenUser, buffer, size, out _)) return null;

            // TOKEN_USER is a SID_AND_ATTRIBUTES whose first field is the SID
            // pointer; the SID itself lives further along in the same buffer.
            IntPtr sid = Marshal.ReadIntPtr(buffer);

            var name = new StringBuilder(256);
            var domain = new StringBuilder(256);
            int nameLen = name.Capacity, domainLen = domain.Capacity;
            if (!LookupAccountSid(null, sid, name, ref nameLen,
                                  domain, ref domainLen, out _))
                return null;

            return domain.Length > 0 ? $"{domain}\\{name}" : name.ToString();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token, int infoClass, IntPtr info, int length, out int returned);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSid(
        string? system, IntPtr sid,
        StringBuilder name, ref int nameLength,
        StringBuilder domain, ref int domainLength,
        out int use);
}
