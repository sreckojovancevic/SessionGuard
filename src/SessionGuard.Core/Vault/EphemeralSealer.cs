using System.Security.Cryptography;

namespace SessionGuard.Core.Vault;

/// <summary>
/// AES-256-GCM under a key that exists only in this process's memory and is
/// wiped on dispose.
///
/// NOT a security boundary: anything that can read this process can read the
/// key. It is here so the framing, stripping and injection can be exercised on
/// a machine without a TPM. On Windows, use the TPM sealer.
/// </summary>
public sealed class EphemeralSealer : ISecretSealer, IDisposable
{
    private const int NonceLen = 12;
    private const int TagLen = 16;

    private byte[] _key = new byte[32];
    private bool _disposed;

    public EphemeralSealer() => RandomNumberGenerator.Fill(_key);

    public string Name => "ephemeral-INSECURE";
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
