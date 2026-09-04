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

    private const byte FormatPerEntry = 0x01;   // an RSA unwrap for every entry
    private const byte FormatSharedDek = 0x02;  // one unwrap, at open

    private readonly CngKey _key;

    /// <summary>
    /// The shared data key, unwrapped once when the sealer opens. Null in
    /// per-entry mode, where every unseal goes to the TPM instead.
    /// </summary>
    private byte[]? _sharedDek;

    private TpmSealer(CngKey key, bool requiresPresence, bool policyMatchesRequest,
                      byte[]? sharedDek)
    {
        _key = key;
        RequiresPresence = requiresPresence;
        PolicyMatchesRequest = policyMatchesRequest;
        _sharedDek = sharedDek;
    }

    public string Name => _sharedDek is null
        ? "windows-tpm (unwrap per cookie)"
        : "windows-tpm";

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

    /// <summary>
    /// Opens or creates the TPM-resident wrapping key.
    ///
    /// <para><b>Where the TPM cost lives.</b> Sealing wraps a per-entry data key
    /// with the TPM's RSA key, so unsealing costs one TPM decryption <i>per
    /// cookie, per request</i>. A site with twenty-four session cookies
    /// therefore asks the chip twenty-four times to build one Cookie header —
    /// on a discrete TPM that is seconds, and in consent mode it is twenty-four
    /// dialogs. That cost is the envelope layout, not the TPM.</para>
    ///
    /// <para>So there are two layouts, and the presence mode chooses between
    /// them, because they differ in exactly the property that mode is about:</para>
    ///
    /// <list type="bullet">
    /// <item><b>Shared key</b> (default). One data key, unwrapped once here and
    /// held in memory. Per-request work is AES-GCM only. The TPM still binds
    /// the vault to this machine — the wrapped key cannot be unwrapped
    /// anywhere else — but it is asked once per run rather than per use.</item>
    /// <item><b>Per entry</b> (consent mode). The original layout, kept because
    /// the per-use prompt <i>is</i> the point when the user asks for it. One
    /// unwrap per cookie means one confirmation per cookie: slow by design,
    /// and honest about it.</item>
    /// </list>
    ///
    /// <para>The trade is real and belongs in front of the user: the shared key
    /// turns per-use consent into per-run consent, and a key sitting in process
    /// memory is readable by anything that can read this process. What it does
    /// not give up is machine binding, which is the claim the project makes.</para>
    /// </summary>
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
            return new TpmSealer(existing, actual, actual == requirePresence,
                                 actual ? null : NewSharedDek(existing));
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

        var created = CngKey.Create(CngAlgorithm.Rsa, KeyName, parameters);
        return new TpmSealer(created, requirePresence, true,
                             requirePresence ? null : NewSharedDek(created));
    }

    /// <summary>
    /// A fresh data key, immediately wrapped by the TPM and then unwrapped, so
    /// that the shared key in memory is one the TPM has actually vouched for.
    ///
    /// Generating it locally and skipping the round trip would be faster and
    /// would also mean the TPM had done nothing at all: the round trip is what
    /// proves the chip is present, is willing, and holds the only key that can
    /// open this vault. It happens once per run, so its cost is invisible.
    /// </summary>
    private static byte[] NewSharedDek(CngKey key)
    {
        byte[] dek = new byte[32];
        RandomNumberGenerator.Fill(dek);
        try
        {
            using var rsa = new RSACng(key);
            byte[] wrapped = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            return rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
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

    // Layouts, distinguished by their first byte so the two can never be
    // mistaken for one another after a mode change:
    //
    //   0x01 | wrapped DEK (256) | nonce (12) | tag (16) | ciphertext
    //   0x02 |                     nonce (12) | tag (16) | ciphertext
    //
    // A length check alone would not separate them: a 256-byte difference in
    // blob size is indistinguishable from a longer cookie.
    private const int HeaderLen = 1;

    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        byte[]? shared = _sharedDek;
        if (shared is not null)
        {
            var fast = new byte[HeaderLen + NonceLen + TagLen + plaintext.Length];
            fast[0] = FormatSharedDek;
            var n = fast.AsSpan(HeaderLen, NonceLen);
            RandomNumberGenerator.Fill(n);
            using var gcm = new AesGcm(shared, TagLen);
            gcm.Encrypt(n, plaintext,
                        fast.AsSpan(HeaderLen + NonceLen + TagLen),
                        fast.AsSpan(HeaderLen + NonceLen, TagLen));
            return fast;
        }

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

            var blob = new byte[HeaderLen + WrappedDekLen + NonceLen + TagLen + plaintext.Length];
            blob[0] = FormatPerEntry;
            wrapped.CopyTo(blob, HeaderLen);
            var nonce = blob.AsSpan(HeaderLen + WrappedDekLen, NonceLen);
            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(dek, TagLen);
            aes.Encrypt(nonce, plaintext,
                        blob.AsSpan(HeaderLen + WrappedDekLen + NonceLen + TagLen),
                        blob.AsSpan(HeaderLen + WrappedDekLen + NonceLen, TagLen));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public int Unseal(ReadOnlySpan<byte> blob, Span<byte> destination)
    {
        if (blob.Length < HeaderLen) throw new CryptographicException("malformed blob");

        if (blob[0] == FormatSharedDek)
        {
            byte[] shared = _sharedDek
                ?? throw new CryptographicException(
                    "this blob was sealed with a shared key, but the sealer is in " +
                    "per-use mode — the vault must be cleared after changing mode");

            int len = blob.Length - HeaderLen - NonceLen - TagLen;
            if (len < 0) throw new CryptographicException("malformed blob");
            if (destination.Length < len) throw new ArgumentException("destination too small");

            using var gcm = new AesGcm(shared, TagLen);
            gcm.Decrypt(blob.Slice(HeaderLen, NonceLen),
                        blob.Slice(HeaderLen + NonceLen + TagLen, len),
                        blob.Slice(HeaderLen + NonceLen, TagLen),
                        destination.Slice(0, len));
            return len;
        }

        if (blob[0] != FormatPerEntry) throw new CryptographicException("unknown blob format");

        int ctLen = blob.Length - HeaderLen - WrappedDekLen - NonceLen - TagLen;
        if (ctLen < 0) throw new CryptographicException("malformed blob");
        if (destination.Length < ctLen) throw new ArgumentException("destination too small");

        byte[] dek;
        // The TPM performs this decrypt; with UIPolicy set it prompts first.
        using (var rsa = new RSACng(_key))
            dek = rsa.Decrypt(blob.Slice(HeaderLen, WrappedDekLen).ToArray(),
                              RSAEncryptionPadding.OaepSHA256);
        try
        {
            using var aes = new AesGcm(dek, TagLen);
            aes.Decrypt(blob.Slice(HeaderLen + WrappedDekLen, NonceLen),
                        blob.Slice(HeaderLen + WrappedDekLen + NonceLen + TagLen, ctLen),
                        blob.Slice(HeaderLen + WrappedDekLen + NonceLen, TagLen),
                        destination.Slice(0, ctLen));
            return ctLen;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public int MaxPlaintextLength(ReadOnlySpan<byte> blob) =>
        blob.Length >= HeaderLen && blob[0] == FormatSharedDek
            ? Math.Max(0, blob.Length - HeaderLen - NonceLen - TagLen)
            : Math.Max(0, blob.Length - HeaderLen - WrappedDekLen - NonceLen - TagLen);

    public void Dispose()
    {
        if (_sharedDek is not null)
        {
            CryptographicOperations.ZeroMemory(_sharedDek);
            _sharedDek = null;
        }
        _key.Dispose();
    }
}
