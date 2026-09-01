using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SessionGuard.Core.Pki;

/// <summary>
/// Where the CA's PKCS#12 bytes live and how they are protected at rest.
///
/// This matters more than it looks. A local root CA that the machine trusts is
/// a universal certificate-minting key: whoever reads it can impersonate any
/// site to this user. Shipping it next to the executable under a hard-coded
/// password hands that capability to the very malware the product defends
/// against. The Windows store binds it with DPAPI to the current user.
/// </summary>
public interface ICaStore
{
    byte[]? Load();
    void Save(byte[] pkcs12);
    string Describe();
}

/// <summary>In-memory store, for tests only. Nothing is persisted.</summary>
public sealed class InMemoryCaStore : ICaStore
{
    private byte[]? _bytes;
    public byte[]? Load() => _bytes;
    public void Save(byte[] pkcs12) => _bytes = pkcs12;
    public string Describe() => "in-memory (test)";
}

public sealed class CertificateAuthority
{
    private static readonly Oid ServerAuth = new("1.3.6.1.5.5.7.3.1");

    private readonly ICaStore _store;
    private readonly ConcurrentDictionary<string, X509Certificate2> _leaves =
        new(StringComparer.OrdinalIgnoreCase);
    private X509Certificate2? _ca;

    public CertificateAuthority(ICaStore store) => _store = store;

    public string StoreDescription => _store.Describe();

    public X509Certificate2 Root
    {
        get
        {
            if (_ca is not null) return _ca;
            lock (_leaves)
            {
                if (_ca is not null) return _ca;
                var existing = _store.Load();
                if (existing is not null)
                {
                    _ca = new X509Certificate2(existing, (string?)null,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                    return _ca;
                }
                _ca = CreateRoot();
                _store.Save(_ca.Export(X509ContentType.Pkcs12));
                return _ca;
            }
        }
    }

    private static X509Certificate2 CreateRoot()
    {
        using var rsa = RSA.Create(4096);
        var req = new CertificateRequest(
            "CN=SessionGuard Local Root, O=SessionGuard",
            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign |
            X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var now = DateTimeOffset.UtcNow;
        using var cert = req.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
        // Round-trip through PKCS#12 so the private key is usable for signing
        // after this method's RSA instance is disposed.
        return new X509Certificate2(cert.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    /// <summary>Mints (and caches) a leaf certificate for one host.</summary>
    public X509Certificate2 LeafFor(string host) =>
        _leaves.GetOrAdd(host, CreateLeaf);

    private X509Certificate2 CreateLeaf(string host)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={host}", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        // Without serverAuth EKU, Chrome rejects the leaf outright.
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { ServerAuth }, false));

        var san = new SubjectAlternativeNameBuilder();
        if (System.Net.IPAddress.TryParse(host, out var ip)) san.AddIpAddress(ip);
        else san.AddDnsName(host);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        var now = DateTimeOffset.UtcNow;
        // Public CAs are capped at 398 days and browsers enforce it on any chain.
        using var signed = req.Create(Root, now.AddDays(-1), now.AddDays(390), serial);
        using var withKey = signed.CopyWithPrivateKey(rsa);

        // Re-import through PKCS#12: a certificate carrying an ephemeral CNG key
        // is rejected by SslStream.AuthenticateAsServer on Windows.
        return new X509Certificate2(withKey.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }
}
