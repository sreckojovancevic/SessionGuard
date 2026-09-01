using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using SessionGuard.Core.Vault;

namespace SessionGuard.Windows;

/// <summary>
/// Sealing bound to the machine's TPM through CNG's Microsoft Platform Crypto
/// Provider.
///
/// Two properties matter, and they are different things:
///
///   non-exportability  ExportPolicy.None means the RSA private key is created
///                      inside the TPM and cannot be read out. The blob can be
///                      *used* on this machine and cannot be *moved* off it.
///                      Copying the vault to another PC yields nothing.
///
///   authorization      Non-exportability alone still lets anything running as
///                      this user ask the TPM to decrypt. CngUIPolicy with
///                      ProtectKey attaches a per-use consent prompt, so an
///                      unattended process cannot help itself.
///
/// Note the managed CngUIPolicy is used rather than hand-rolling the
/// NCRYPT_UI_POLICY struct: the property is named "UI Policy" on the wire and
/// takes a struct of pointers, not a string, so setting it by hand with the C
/// macro name silently does nothing.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TpmSealer : ISecretSealer, IDisposable
{
    public const string KeyName = "SessionGuard.Vault.v1";
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private const int WrappedDekLen = 256; // RSA-2048 ciphertext

    private readonly CngKey _key;

    private TpmSealer(CngKey key, bool requiresPresence, bool policyMatchesRequest)
    {
        _key = key;
        RequiresPresence = requiresPresence;
        PolicyMatchesRequest = policyMatchesRequest;
    }

    public string Name => "windows-tpm";

    /// <summary>The key's REAL policy, not what the caller asked for.</summary>
    public bool RequiresPresence { get; }

    /// <summary>
    /// False when an existing key's policy differs from what was requested.
    ///
    /// The policy lives on the TPM key, not in application settings, so a key
    /// created by an earlier run keeps its policy no matter what the UI now
    /// says. Rather than throwing — which would leave the user stuck — the real
    /// policy is reported and the caller offers to recreate the key.
    /// </summary>
    public bool PolicyMatchesRequest { get; }

    /// <summary>Opens or creates the TPM-resident wrapping key.</summary>
    public static TpmSealer Open(bool requirePresence = true)
    {
        var provider = new CngProvider(ProviderName);
        if (CngKey.Exists(KeyName, provider))
        {
            var existing = CngKey.Open(KeyName, provider);
            // requirePresence is a request, not evidence: report what the key
            // actually enforces.
            bool actual = SafeProtectionLevel(existing)
                .HasFlag(CngUIProtectionLevels.ProtectKey);
            return new TpmSealer(existing, actual, actual == requirePresence);
        }

        var parameters = new CngKeyCreationParameters
        {
            Provider = provider,
            // The key never leaves the TPM.
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None,
            KeyUsage = CngKeyUsages.Decryption,
        };
        parameters.Parameters.Add(
            new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

        if (requirePresence)
        {
            parameters.UIPolicy = new CngUIPolicy(
                CngUIProtectionLevels.ProtectKey,
                friendlyName: "SessionGuard session vault",
                description: "Unlock the protected browser session on this device.",
                useContext: "SessionGuard needs your confirmation to attach the session.",
                creationTitle: "SessionGuard");
        }

        return new TpmSealer(CngKey.Create(CngAlgorithm.Rsa, KeyName, parameters),
                             requirePresence, true);
    }

    /// <summary>
    /// Deletes the persisted TPM key so the next Open recreates it with the
    /// policy the current mode wants. Any sealed data becomes unreadable —
    /// acceptable here because the vault is in-process anyway.
    /// </summary>
    public static bool DeleteKey()
    {
        var provider = new CngProvider(ProviderName);
        if (!CngKey.Exists(KeyName, provider)) return false;
        using var key = CngKey.Open(KeyName, provider);
        key.Delete();
        return true;
    }

    /// <summary>The policy currently on the persisted key, if any.</summary>
    public static bool? ExistingKeyRequiresPresence()
    {
        var provider = new CngProvider(ProviderName);
        if (!CngKey.Exists(KeyName, provider)) return null;
        using var key = CngKey.Open(KeyName, provider);
        return SafeProtectionLevel(key).HasFlag(CngUIProtectionLevels.ProtectKey);
    }

    /// <summary>Reads the key's real UI policy; absent policy reads as None.</summary>
    private static CngUIProtectionLevels SafeProtectionLevel(CngKey key)
    {
        try { return key.UIPolicy?.ProtectionLevel ?? CngUIProtectionLevels.None; }
        catch (CryptographicException) { return CngUIProtectionLevels.None; }
    }

    // Blob layout: wrapped DEK (256) | nonce (12) | tag (16) | ciphertext
    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        // A byte[] rather than stackalloc: RSACng.Encrypt takes an array, and
        // going through .ToArray() would leave an unwiped copy of the key
        // material on the heap — the exact class of leak this type exists to
        // avoid.
        byte[] dek = new byte[32];
        RandomNumberGenerator.Fill(dek);
        try
        {
            byte[] wrapped;
            using (var rsa = new RSACng(_key))
                wrapped = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            if (wrapped.Length != WrappedDekLen)
                throw new CryptographicException("unexpected wrapped key length");

            var blob = new byte[WrappedDekLen + NonceLen + TagLen + plaintext.Length];
            wrapped.CopyTo(blob, 0);
            var nonce = blob.AsSpan(WrappedDekLen, NonceLen);
            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(dek, TagLen);
            aes.Encrypt(nonce, plaintext,
                        blob.AsSpan(WrappedDekLen + NonceLen + TagLen),
                        blob.AsSpan(WrappedDekLen + NonceLen, TagLen));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public int Unseal(ReadOnlySpan<byte> blob, Span<byte> destination)
    {
        int ctLen = blob.Length - WrappedDekLen - NonceLen - TagLen;
        if (ctLen < 0) throw new CryptographicException("malformed blob");
        if (destination.Length < ctLen) throw new ArgumentException("destination too small");

        byte[] dek;
        // The TPM performs this decrypt; with UIPolicy set it prompts first.
        using (var rsa = new RSACng(_key))
            dek = rsa.Decrypt(blob.Slice(0, WrappedDekLen).ToArray(),
                              RSAEncryptionPadding.OaepSHA256);
        try
        {
            using var aes = new AesGcm(dek, TagLen);
            aes.Decrypt(blob.Slice(WrappedDekLen, NonceLen),
                        blob.Slice(WrappedDekLen + NonceLen + TagLen, ctLen),
                        blob.Slice(WrappedDekLen + NonceLen, TagLen),
                        destination.Slice(0, ctLen));
            return ctLen;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public int MaxPlaintextLength(ReadOnlySpan<byte> blob) =>
        Math.Max(0, blob.Length - WrappedDekLen - NonceLen - TagLen);

    public void Dispose() => _key.Dispose();
}
