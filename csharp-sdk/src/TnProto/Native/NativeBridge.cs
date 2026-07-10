using System.Text.Json.Nodes;

namespace TnProto.Native;

/// <summary>
/// Low-level access to the native tn-proto bridge.
/// </summary>
public static class NativeBridge
{
    /// <summary>
    /// Gets the loaded native bridge version.
    /// </summary>
    public static string Version()
    {
        return NativeString.Consume(NativeMethods.Version())
            ?? throw new TnException("native bridge returned a null version");
    }

    /// <summary>
    /// Gets the last native error recorded on the current thread.
    /// </summary>
    public static string? LastError()
    {
        return NativeString.Consume(NativeMethods.LastError());
    }

    internal static string CanonicalJson(string valueJson)
    {
        return NativeString.Consume(NativeMethods.CanonicalJson(valueJson))
            ?? throw new TnException(LastError() ?? "native canonical JSON returned a null result");
    }

    internal static string CanonicalBytesHex(string valueJson)
    {
        return NativeString.Consume(NativeMethods.CanonicalBytesHex(valueJson))
            ?? throw new TnException(LastError() ?? "native canonical bytes returned a null result");
    }

    internal static string CryptoVerifyEnvelope(string envelopeJson)
    {
        return NativeString.Consume(NativeMethods.CryptoVerifyEnvelope(envelopeJson))
            ?? throw new TnException(LastError() ?? "native envelope verify returned a null result");
    }

    internal static string CryptoSealPublic(string inputJson)
    {
        return NativeString.Consume(NativeMethods.CryptoSealPublic(inputJson))
            ?? throw new TnException(LastError() ?? "native public seal returned a null result");
    }

    internal static string IdentityGenerate()
    {
        return NativeString.Consume(NativeMethods.IdentityGenerate())
            ?? throw new TnException(LastError() ?? "native identity generate returned a null result");
    }

    internal static string IdentityFromSeedBase64(string seedBase64)
    {
        return NativeString.Consume(NativeMethods.IdentityFromSeedBase64(seedBase64))
            ?? throw new TnException(LastError() ?? "native identity derivation returned a null result");
    }

    internal static string IdentityFromMnemonic(string words, string? passphrase)
    {
        return NativeString.Consume(NativeMethods.IdentityFromMnemonic(words, passphrase))
            ?? throw new TnException(LastError() ?? "native mnemonic identity derivation returned a null result");
    }

    internal static string IdentitySignBase64(string seedBase64, string messageBase64)
    {
        return NativeString.Consume(NativeMethods.IdentitySignBase64(seedBase64, messageBase64))
            ?? throw new TnException(LastError() ?? "native identity sign returned a null result");
    }

    internal static string IdentityVerifyDidBase64(
        string did,
        string messageBase64,
        string signatureBase64)
    {
        return NativeString.Consume(NativeMethods.IdentityVerifyDidBase64(
                did,
                messageBase64,
                signatureBase64))
            ?? throw new TnException(LastError() ?? "native identity verify returned a null result");
    }

    internal static TnNativeHandle Open(string yamlPath)
    {
        var handle = NativeMethods.RuntimeOpen(yamlPath);
        return TnNativeHandle.FromOwned(handle);
    }

    internal static TnNativeHandle InitProject(string project, string? projectDir = null)
    {
        var handle = NativeMethods.RuntimeInitProject(project, projectDir);
        return TnNativeHandle.FromOwned(handle);
    }

    internal static TnNativeHandle InitProject(
        string project,
        string? projectDir,
        string? profile)
    {
        var handle = NativeMethods.RuntimeInitProjectWithOptions(project, projectDir, profile);
        return TnNativeHandle.FromOwned(handle);
    }

    internal static TnNativeHandle InitProject(
        string project,
        string? projectDir,
        string? profile,
        byte[] deviceSeed)
    {
        ArgumentNullException.ThrowIfNull(deviceSeed);
        if (deviceSeed.Length != 32)
        {
            throw new ArgumentException("TN Ed25519 identity seeds must be exactly 32 bytes.", nameof(deviceSeed));
        }

        var handle = NativeMethods.RuntimeInitProjectWithSeed(
            project,
            projectDir,
            profile,
            Convert.ToBase64String(deviceSeed));
        return TnNativeHandle.FromOwned(handle);
    }

    internal static string Did(TnNativeHandle handle)
    {
        return NativeString.Consume(NativeMethods.RuntimeDid(handle.RawHandle))
            ?? throw new TnException(LastError() ?? "native bridge returned a null DID");
    }

    internal static string YamlPath(TnNativeHandle handle)
    {
        return NativeString.Consume(NativeMethods.RuntimeYamlPath(handle.RawHandle))
            ?? throw new TnException(LastError() ?? "native bridge returned a null YAML path");
    }

    internal static string LogPath(TnNativeHandle handle)
    {
        return NativeString.Consume(NativeMethods.RuntimeLogPath(handle.RawHandle))
            ?? throw new TnException(LastError() ?? "native bridge returned a null log path");
    }

    internal static string AgentPolicyDoc(TnNativeHandle handle)
    {
        return NativeString.Consume(NativeMethods.RuntimeAgentPolicyDoc(handle.RawHandle))
            ?? throw new TnException(LastError() ?? "native agent policy doc returned a null result");
    }

    internal static string Emit(TnNativeHandle handle, string? level, string eventType, string fieldsJson)
    {
        return NativeString.Consume(NativeMethods.RuntimeEmit(handle.RawHandle, level, eventType, fieldsJson))
            ?? throw new TnException(LastError() ?? "native emit returned a null receipt");
    }

    internal static string EmitWithAad(
        TnNativeHandle handle,
        string? level,
        string eventType,
        string fieldsJson,
        string aadJson)
    {
        return NativeString.Consume(NativeMethods.RuntimeEmitWithAad(
                handle.RawHandle,
                level,
                eventType,
                fieldsJson,
                aadJson))
            ?? throw new TnException(LastError() ?? "native emit with aad returned a null receipt");
    }

    internal static string Seal(
        TnNativeHandle handle,
        string objectType,
        string fieldsJson,
        string? optionsJson)
    {
        return NativeString.Consume(NativeMethods.RuntimeSeal(
                handle.RawHandle,
                objectType,
                fieldsJson,
                optionsJson))
            ?? throw new TnException(LastError() ?? "native seal returned a null result");
    }

    internal static string Unseal(TnNativeHandle handle, string source, string? optionsJson)
    {
        var outcome = NativeString.Consume(NativeMethods.RuntimeUnseal(
            handle.RawHandle,
            source,
            optionsJson));
        if (outcome is not null)
        {
            return outcome;
        }

        throw MapUnsealError(LastError() ?? "native unseal returned a null result");
    }

    /// <summary>
    /// Map the native unseal error channel onto the typed exceptions:
    /// <c>VerifyError:{json}</c> becomes <see cref="TnVerifyException"/>,
    /// <c>UnsealError: reason</c> becomes <see cref="TnUnsealException"/>,
    /// anything else stays a plain <see cref="TnException"/>.
    /// </summary>
    private static TnException MapUnsealError(string message)
    {
        const string verifyPrefix = "VerifyError:";
        const string unsealPrefix = "UnsealError: ";

        if (message.StartsWith(verifyPrefix, StringComparison.Ordinal))
        {
            var payload = message[verifyPrefix.Length..];
            try
            {
                if (JsonNode.Parse(payload) is JsonObject details)
                {
                    var failedChecks = new List<string>();
                    if (details["failed_checks"] is JsonArray checksNode)
                    {
                        foreach (var check in checksNode)
                        {
                            if (check?.GetValue<string>() is { } name)
                            {
                                failedChecks.Add(name);
                            }
                        }
                    }

                    return new TnVerifyException(
                        failedChecks,
                        details["sequence"]?.GetValue<long>() ?? 0,
                        details["event_type"]?.GetValue<string>() ?? "");
                }
            }
            catch (System.Text.Json.JsonException)
            {
                // Fall through to the plain exception with the raw message.
            }
        }

        if (message.StartsWith(unsealPrefix, StringComparison.Ordinal))
        {
            return new TnUnsealException(message[unsealPrefix.Length..]);
        }

        return new TnException(message);
    }

    internal static string Read(TnNativeHandle handle, bool allRuns, bool verify)
    {
        return NativeString.Consume(NativeMethods.RuntimeRead(handle.RawHandle, allRuns ? 1 : 0, verify ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native read returned null entries");
    }

    internal static string AdminEnsureGroup(TnNativeHandle handle, string group, string fieldsJson)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminEnsureGroup(handle.RawHandle, group, fieldsJson))
            ?? throw new TnException(LastError() ?? "native admin ensure-group returned a null result");
    }

    internal static string AdminAddRecipient(
        TnNativeHandle handle,
        string group,
        string? recipientDid,
        string outKitPath)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminAddRecipient(
                handle.RawHandle,
                group,
                recipientDid,
                outKitPath))
            ?? throw new TnException(LastError() ?? "native admin add-recipient returned a null result");
    }

    internal static string AdminRevokeRecipient(TnNativeHandle handle, string group, ulong leafIndex)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminRevokeRecipient(
                handle.RawHandle,
                group,
                leafIndex))
            ?? throw new TnException(LastError() ?? "native admin revoke-recipient returned a null result");
    }

    internal static string AdminRotateGroup(TnNativeHandle handle, string group)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminRotateGroup(handle.RawHandle, group))
            ?? throw new TnException(LastError() ?? "native admin rotate returned a null result");
    }

    internal static string AdminGrantReader(
        TnNativeHandle handle,
        string group,
        string? readerDid,
        string outPath,
        string? idPath)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminGrantReader(
                handle.RawHandle,
                group,
                readerDid,
                outPath,
                idPath))
            ?? throw new TnException(LastError() ?? "native admin grant-reader returned a null result");
    }

    internal static string AdminRotateIdPath(
        TnNativeHandle handle,
        string group,
        string newPath,
        bool allowRootPath)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminRotateIdPath(
                handle.RawHandle,
                group,
                newPath,
                allowRootPath ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native admin rotate-id-path returned a null result");
    }

    internal static string AdminRecipients(TnNativeHandle handle, string group, bool includeRevoked)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminRecipients(
                handle.RawHandle,
                group,
                includeRevoked ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native admin recipients returned a null result");
    }

    internal static string AdminRevokedCount(TnNativeHandle handle, string group)
    {
        return NativeString.Consume(NativeMethods.RuntimeAdminRevokedCount(handle.RawHandle, group))
            ?? throw new TnException(LastError() ?? "native admin revoked-count returned a null result");
    }

    internal static string PackageExportAdminSnapshot(TnNativeHandle handle, string outPath)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgExportAdminSnapshot(handle.RawHandle, outPath))
            ?? throw new TnException(LastError() ?? "native package export-admin-snapshot returned a null result");
    }

    internal static string PackageExportKitBundle(
        TnNativeHandle handle,
        string outPath,
        string? groupsJson,
        string? toDid)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgExportKitBundle(
                handle.RawHandle,
                outPath,
                groupsJson,
                toDid))
            ?? throw new TnException(LastError() ?? "native package export-kit-bundle returned a null result");
    }

    internal static string PackageExportProjectSeed(TnNativeHandle handle, string outPath)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgExportProjectSeed(handle.RawHandle, outPath))
            ?? throw new TnException(LastError() ?? "native package export-project-seed returned a null result");
    }

    internal static string PackageExportEncryptedFullKeystore(
        TnNativeHandle handle,
        string outPath,
        string? groupsJson,
        string bekBase64)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgExportEncryptedFullKeystore(
                handle.RawHandle,
                outPath,
                groupsJson,
                bekBase64))
            ?? throw new TnException(LastError() ?? "native package export-encrypted-full-keystore returned a null result");
    }

    internal static string PackageExportGroupKeys(
        TnNativeHandle handle,
        string outPath,
        string? groupsJson)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgExportGroupKeys(
                handle.RawHandle,
                outPath,
                groupsJson))
            ?? throw new TnException(LastError() ?? "native package export-group-keys returned a null result");
    }

    internal static string VaultPushBodyWithPassphrase(
        TnNativeHandle handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string passphrase,
        string? credentialId)
    {
        return NativeString.Consume(NativeMethods.RuntimeVaultPushBodyWithPassphrase(
                handle.RawHandle,
                vaultBaseUrl,
                bearerToken,
                projectId,
                passphrase,
                credentialId))
            ?? throw new TnException(LastError() ?? "native vault push-body returned a null result");
    }

    internal static string VaultRestoreBodyWithPassphrase(
        TnNativeHandle handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string passphrase,
        string? credentialId)
    {
        return NativeString.Consume(NativeMethods.RuntimeVaultRestoreBodyWithPassphrase(
                handle.RawHandle,
                vaultBaseUrl,
                bearerToken,
                projectId,
                passphrase,
                credentialId))
            ?? throw new TnException(LastError() ?? "native vault restore-body returned a null result");
    }

    internal static string VaultRestoreInstallBodyWithPassphrase(
        TnNativeHandle handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string passphrase,
        string? credentialId,
        string targetDir,
        bool overwrite)
    {
        return NativeString.Consume(NativeMethods.RuntimeVaultRestoreInstallBodyWithPassphrase(
                handle.RawHandle,
                vaultBaseUrl,
                bearerToken,
                projectId,
                passphrase,
                credentialId,
                targetDir,
                overwrite ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native vault restore-install returned a null result");
    }

    internal static string VaultRestoreInstallBodyWithAwk(
        TnNativeHandle handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string awkBase64,
        string targetDir,
        bool overwrite)
    {
        return NativeString.Consume(NativeMethods.RuntimeVaultRestoreInstallBodyWithAwk(
                handle.RawHandle,
                vaultBaseUrl,
                bearerToken,
                projectId,
                awkBase64,
                targetDir,
                overwrite ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native vault restore-install with AWK returned a null result");
    }

    internal static string PackageBundleForRecipient(
        TnNativeHandle handle,
        string recipientDid,
        string outPath,
        string? groupsJson,
        bool sealForRecipient)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgBundleForRecipient(
                handle.RawHandle,
                recipientDid,
                outPath,
                groupsJson,
                sealForRecipient ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native package bundle-for-recipient returned a null result");
    }

    internal static string PackageCompileEnrolment(
        TnNativeHandle handle,
        string group,
        string recipientDid,
        string outPath,
        bool sealForRecipient)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgCompileEnrolment(
                handle.RawHandle,
                group,
                recipientDid,
                outPath,
                sealForRecipient ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native package compile-enrolment returned a null result");
    }

    internal static string PackageOffer(
        TnNativeHandle handle,
        string group,
        string peerDid,
        string outPath,
        bool sealForRecipient)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgOffer(
                handle.RawHandle,
                group,
                peerDid,
                outPath,
                sealForRecipient ? 1 : 0))
            ?? throw new TnException(LastError() ?? "native package offer returned a null result");
    }

    internal static string PackageInspectPath(TnNativeHandle handle, string sourcePath)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgInspectPath(handle.RawHandle, sourcePath))
            ?? throw new TnException(LastError() ?? "native package inspect returned a null result");
    }

    internal static string PackageAbsorbPath(TnNativeHandle handle, string sourcePath)
    {
        return NativeString.Consume(NativeMethods.RuntimePkgAbsorbPath(handle.RawHandle, sourcePath))
            ?? throw new TnException(LastError() ?? "native package absorb returned a null result");
    }

    internal static string InboxListLocal(TnNativeHandle handle, string dir)
    {
        return NativeString.Consume(NativeMethods.RuntimeInboxListLocal(handle.RawHandle, dir))
            ?? throw new TnException(LastError() ?? "native inbox list-local returned a null result");
    }

    internal static string InboxInspectPath(TnNativeHandle handle, string path)
    {
        return NativeString.Consume(NativeMethods.RuntimeInboxInspectPath(handle.RawHandle, path))
            ?? throw new TnException(LastError() ?? "native inbox inspect returned a null result");
    }

    internal static string InboxAcceptPath(TnNativeHandle handle, string path)
    {
        return NativeString.Consume(NativeMethods.RuntimeInboxAcceptPath(handle.RawHandle, path))
            ?? throw new TnException(LastError() ?? "native inbox accept returned a null result");
    }

    internal static string InboxMintInvitePath(
        TnNativeHandle handle,
        string recipient,
        string outPath,
        string? optionsJson)
    {
        return NativeString.Consume(NativeMethods.RuntimeInboxMintInvitePath(
                handle.RawHandle,
                recipient,
                outPath,
                optionsJson))
            ?? throw new TnException(LastError() ?? "native inbox mint returned a null result");
    }
}
