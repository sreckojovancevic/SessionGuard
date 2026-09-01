using System;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Windows.Security.Credentials;
using Windows.Storage.Streams;

namespace SessionGuard.Windows;

/// <summary>
/// The presence gesture, verified by the platform rather than by us.
///
/// KeyCredentialManager signs a fresh random challenge with a key the TPM only
/// releases after a biometric or PIN gesture, so a successful signature is
/// evidence a human was at the machine — not merely that something clicked a
/// button in our own process.
///
/// When Hello is unavailable this reports failure rather than quietly
/// downgrading to no check at all: an unverifiable gesture must not open a
/// lease.
/// </summary>
[SupportedOSPlatform("windows10.0.17763.0")]
public static class WindowsHello
{
    private const string CredentialName = "SessionGuard.Presence.v1";

    public sealed record Result(bool Ok, string Detail);

    public static async Task<Result> RequestGestureAsync()
    {
        try
        {
            if (!await KeyCredentialManager.IsSupportedAsync())
                return new Result(false, "Windows Hello is not configured on this device");

            var open = await KeyCredentialManager.OpenAsync(CredentialName);
            KeyCredential? credential = open.Credential;

            if (credential is null)
            {
                var created = await KeyCredentialManager.RequestCreateAsync(
                    CredentialName, KeyCredentialCreationOption.ReplaceExisting);
                credential = created.Credential;
                if (created.Status != KeyCredentialStatus.Success || credential is null)
                    return new Result(false, $"enrolment failed: {created.Status}");
            }

            var writer = new DataWriter();
            writer.WriteBytes(RandomNumberGenerator.GetBytes(32));
            var signed = await credential.RequestSignAsync(writer.DetachBuffer());

            return signed.Status == KeyCredentialStatus.Success
                ? new Result(true, "verified by Windows Hello")
                : new Result(false, $"gesture declined: {signed.Status}");
        }
        catch (Exception ex)
        {
            return new Result(false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}
