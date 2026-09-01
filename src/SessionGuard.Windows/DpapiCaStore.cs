using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using SessionGuard.Core.Pki;

namespace SessionGuard.Windows;

/// <summary>
/// The local root CA, protected with DPAPI and kept in %LOCALAPPDATA%.
///
/// The threat this closes: a trusted local root is a licence to impersonate any
/// site to this user. Writing it beside the executable under a constant
/// password — as the earlier draft did — hands that licence to the first
/// process that reads the folder. DPAPI binds the blob to this Windows account,
/// with extra entropy so another application's DPAPI call cannot unprotect it.
///
/// CryptProtectData is called directly rather than through the
/// System.Security.Cryptography.ProtectedData package, so the project restores
/// with no external dependencies.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiCaStore : ICaStore
{
    private static readonly byte[] Entropy =
        "SessionGuard/root-ca/v1"u8.ToArray();

    private readonly string _path;

    public DpapiCaStore(string? directory = null)
    {
        string dir = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SessionGuard");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "root-ca.dpapi");
    }

    public string Describe() => $"DPAPI (CurrentUser) at {_path}";

    public byte[]? Load()
    {
        if (!File.Exists(_path)) return null;
        try { return Unprotect(File.ReadAllBytes(_path)); }
        catch (CryptographicException) { return null; } // different user or corrupt
    }

    public void Save(byte[] pkcs12)
    {
        byte[] protectedBytes = Protect(pkcs12);
        string tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, protectedBytes);
        File.Move(tmp, _path, overwrite: true);
        CryptographicOperations.ZeroMemory(pkcs12);
    }

    // ---------------------------------------------------------- DPAPI interop

    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn, string? szDataDescr, ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private static byte[] Protect(byte[] plain) => Transform(plain, protect: true);
    private static byte[] Unprotect(byte[] blob) => Transform(blob, protect: false);

    private static byte[] Transform(byte[] input, bool protect)
    {
        var inHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
        var entHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        var outBlob = default(DATA_BLOB);
        try
        {
            var inBlob = new DATA_BLOB
            {
                cbData = input.Length,
                pbData = inHandle.AddrOfPinnedObject(),
            };
            var entBlob = new DATA_BLOB
            {
                cbData = Entropy.Length,
                pbData = entHandle.AddrOfPinnedObject(),
            };

            bool ok = protect
                ? CryptProtectData(ref inBlob, "SessionGuard root CA", ref entBlob,
                                   IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN,
                                   out outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entBlob,
                                     IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN,
                                     out outBlob);

            if (!ok)
                throw new CryptographicException(Marshal.GetLastWin32Error());

            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
            entHandle.Free();
            inHandle.Free();
        }
    }
}
