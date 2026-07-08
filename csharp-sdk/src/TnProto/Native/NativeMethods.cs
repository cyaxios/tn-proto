using System.Runtime.InteropServices;

namespace TnProto.Native;

internal static partial class NativeMethods
{
    static NativeMethods()
    {
        NativeLibraryResolver.Register();
    }

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_ffi_version")]
    internal static partial IntPtr Version();

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_last_error")]
    internal static partial IntPtr LastError();

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_string_free")]
    internal static partial void StringFree(IntPtr value);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_canonical_json", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr CanonicalJson(string valueJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_canonical_bytes_hex", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr CanonicalBytesHex(string valueJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_crypto_verify_envelope", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr CryptoVerifyEnvelope(string envelopeJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_crypto_seal_public", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr CryptoSealPublic(string inputJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_identity_generate")]
    internal static partial IntPtr IdentityGenerate();

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_identity_from_seed_b64", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr IdentityFromSeedBase64(string seedBase64);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_identity_from_mnemonic", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr IdentityFromMnemonic(string words, string? passphrase);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_identity_sign_b64", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr IdentitySignBase64(string seedBase64, string messageBase64);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_identity_verify_did_b64", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr IdentityVerifyDidBase64(
        string did,
        string messageBase64,
        string signatureBase64);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_open", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeOpen(string yamlPath);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_init_project", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInitProject(string project, string? projectDir);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_init_project_with_options", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInitProjectWithOptions(string project, string? projectDir, string? profile);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_init_project_with_seed", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInitProjectWithSeed(
        string project,
        string? projectDir,
        string? profile,
        string? deviceSeedBase64);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_did")]
    internal static partial IntPtr RuntimeDid(IntPtr handle);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_yaml_path")]
    internal static partial IntPtr RuntimeYamlPath(IntPtr handle);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_log_path")]
    internal static partial IntPtr RuntimeLogPath(IntPtr handle);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_emit", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeEmit(IntPtr handle, string? level, string eventType, string fieldsJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_read")]
    internal static partial IntPtr RuntimeRead(IntPtr handle, int allRuns, int verify);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_admin_ensure_group", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeAdminEnsureGroup(IntPtr handle, string group, string fieldsJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_admin_add_recipient", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeAdminAddRecipient(
        IntPtr handle,
        string group,
        string? recipientDid,
        string outKitPath);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_admin_revoke_recipient", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeAdminRevokeRecipient(IntPtr handle, string group, ulong leafIndex);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_admin_rotate_group", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeAdminRotateGroup(IntPtr handle, string group);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_admin_recipients", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeAdminRecipients(IntPtr handle, string group, int includeRevoked);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_admin_revoked_count", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeAdminRevokedCount(IntPtr handle, string group);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_export_admin_snapshot", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgExportAdminSnapshot(IntPtr handle, string outPath);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_export_kit_bundle", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgExportKitBundle(
        IntPtr handle,
        string outPath,
        string? groupsJson,
        string? toDid);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_export_project_seed", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgExportProjectSeed(IntPtr handle, string outPath);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_export_encrypted_full_keystore", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgExportEncryptedFullKeystore(
        IntPtr handle,
        string outPath,
        string? groupsJson,
        string bekBase64);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_export_group_keys", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgExportGroupKeys(
        IntPtr handle,
        string outPath,
        string? groupsJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_vault_push_body_with_passphrase", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeVaultPushBodyWithPassphrase(
        IntPtr handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string passphrase,
        string? credentialId);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_vault_restore_body_with_passphrase", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeVaultRestoreBodyWithPassphrase(
        IntPtr handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string passphrase,
        string? credentialId);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_vault_restore_install_body_with_passphrase", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeVaultRestoreInstallBodyWithPassphrase(
        IntPtr handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string passphrase,
        string? credentialId,
        string targetDir,
        int overwrite);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_vault_restore_install_body_with_awk", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeVaultRestoreInstallBodyWithAwk(
        IntPtr handle,
        string vaultBaseUrl,
        string? bearerToken,
        string? projectId,
        string awkBase64,
        string targetDir,
        int overwrite);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_bundle_for_recipient", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgBundleForRecipient(
        IntPtr handle,
        string recipientDid,
        string outPath,
        string? groupsJson,
        int sealForRecipient);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_compile_enrolment", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgCompileEnrolment(
        IntPtr handle,
        string group,
        string recipientDid,
        string outPath,
        int sealForRecipient);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_offer", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgOffer(
        IntPtr handle,
        string group,
        string peerDid,
        string outPath,
        int sealForRecipient);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_inspect_path", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgInspectPath(IntPtr handle, string sourcePath);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_pkg_absorb_path", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimePkgAbsorbPath(IntPtr handle, string sourcePath);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_inbox_list_local", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInboxListLocal(IntPtr handle, string dir);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_inbox_inspect_path", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInboxInspectPath(IntPtr handle, string path);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_inbox_accept_path", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInboxAcceptPath(IntPtr handle, string path);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_inbox_mint_invite_path", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr RuntimeInboxMintInvitePath(
        IntPtr handle,
        string recipient,
        string outPath,
        string? optionsJson);

    [LibraryImport("tn_core_ffi", EntryPoint = "tn_runtime_close")]
    internal static partial int RuntimeClose(IntPtr handle);
}
