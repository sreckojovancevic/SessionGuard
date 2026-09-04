using System.Security.Cryptography;

namespace SessionGuard.Core.Vault;

/// <summary>
/// AES-256-GCM under a key that exists only in this process's memory and is
/// wiped on dispose.
///
/// <para><b>What this does defeat.</b> The attack this project was built for is
/// an infostealer that reads the browser's cookie database off disk. Against
/// that, a software-sealed vault is exactly as effective as a TPM-sealed one,
/// because the protection comes from somewhere else entirely: the cookie is
/// never written to the browser profile at all. When the application exits, the
/// key and everything it protected are gone, so a powered-off machine holds
/// nothing to find — which is more than a TPM-sealed file on disk can say.</para>
///
/// <para><b>What it does not.</b> There is no non-exportability here. The key
/// sits in this process's address space, so anything that can read that memory
/// — a debugger, a crash dump, the page file, another process with
/// SeDebugPrivilege — has it, and with it every blob in the same snapshot. A
/// TPM key is created inside the chip and cannot be read out even by the process
/// using it. No software implementation can offer that, on any operating
/// system.</para>
///
/// <para>So: a real boundary against the disk, none against memory. It is a
/// deliberate mode rather than a fallback, because a machine without TPM 2.0 —
/// an older workstation, a VM with no vTPM, anything still on TPM 1.2 — would
/// otherwise get nothing at all, and "nothing" is a worse answer than "this
/// much, named precisely".</para>
/// </summary>
public sealed class SoftwareSealer : ISecretSealer, IDisposable
{
    private const int NonceLen = 12;
    private const int TagLen = 16;

    private byte[] _key = new byte[32];
    private bool _disposed;

    public SoftwareSealer() => RandomNumberGenerator.Fill(_key);

    public string Name => "software-aes-gcm";
    public bool RequiresPresence => false;

    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var blob = new byte[NonceLen + TagLen + plaintext.Length];
        var nonce = blob.AsSpan(0, NonceLen);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagLen);
        aes.Encrypt(nonce, plaintext,
                    blob.AsSpan(NonceLen + TagLen),
                    blob.AsSpan(NonceLen, TagLen));
        return blob;
    }

    public int Unseal(ReadOnlySpan<byte> blob, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int ctLen = blob.Length - NonceLen - TagLen;
        if (ctLen < 0) throw new CryptographicException("malformed blob");
        if (destination.Length < ctLen) throw new ArgumentException("destination too small");
        using var aes = new AesGcm(_key, TagLen);
        aes.Decrypt(blob.Slice(0, NonceLen),
                    blob.Slice(NonceLen + TagLen, ctLen),
                    blob.Slice(NonceLen, TagLen),
                    destination.Slice(0, ctLen));
        return ctLen;
    }

    public int MaxPlaintextLength(ReadOnlySpan<byte> blob) =>
        Math.Max(0, blob.Length - NonceLen - TagLen);

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_key);
        _key = Array.Empty<byte>();
        _disposed = true;
    }
}
