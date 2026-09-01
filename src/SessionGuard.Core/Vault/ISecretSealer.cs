namespace SessionGuard.Core.Vault;

/// <summary>
/// Seals and unseals secrets. The point of the abstraction is that the sealing
/// key must be usable on this machine and not extractable from it.
///
/// On Windows the real implementation is TPM-backed (CNG, Microsoft Platform
/// Crypto Provider, ExportPolicy.None). <see cref="EphemeralSealer"/> is the
/// portable fallback and is explicitly not a security boundary — it exists so
/// the pipeline can be tested off Windows.
/// </summary>
public interface ISecretSealer
{
    string Name { get; }

    /// <summary>True when unsealing demands a user gesture (Hello / TPM PIN).</summary>
    bool RequiresPresence { get; }

    /// <summary>Encrypts plaintext; the returned blob is safe at rest.</summary>
    byte[] Seal(ReadOnlySpan<byte> plaintext);

    /// <summary>
    /// Decrypts into <paramref name="destination"/>, returning the byte count.
    /// Returning into a caller-owned buffer keeps the plaintext in one place
    /// the caller can wipe, instead of scattering copies across the heap.
    /// </summary>
    int Unseal(ReadOnlySpan<byte> blob, Span<byte> destination);

    /// <summary>Upper bound on plaintext length for a given blob.</summary>
    int MaxPlaintextLength(ReadOnlySpan<byte> blob);
}
