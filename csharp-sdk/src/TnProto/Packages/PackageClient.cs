using System.Text.Json;
using System.Text.Json.Nodes;
using TnProto.Native;

namespace TnProto.Packages;

/// <summary>
/// Package export and absorb helpers.
/// </summary>
public sealed class PackageClient
{
    private readonly Tn _tn;

    internal PackageClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// Export an admin-log snapshot package.
    /// </summary>
    public Task<PackageExportResult> ExportAdminSnapshotAsync(
        string outPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(outPath));
        }

        var fullPath = Path.GetFullPath(outPath);
        var resultJson = NativeBridge.PackageExportAdminSnapshot(_tn.NativeHandle, fullPath);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package export returned non-object JSON");

        return Task.FromResult(new PackageExportResult(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package export result omitted path"))));
    }

    /// <summary>
    /// Export existing reader kits from the local keystore as a kit bundle.
    /// </summary>
    public Task<PackageExportResult> ExportKitBundleAsync(
        string outPath,
        IEnumerable<string>? groups = null,
        string? toDid = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(outPath));
        }

        var groupsJson = SerializeGroups(groups);

        var fullPath = Path.GetFullPath(outPath);
        var resultJson = NativeBridge.PackageExportKitBundle(
            _tn.NativeHandle,
            fullPath,
            groupsJson,
            toDid);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package export returned non-object JSON");

        return Task.FromResult(new PackageExportResult(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package export result omitted path"))));
    }

    /// <summary>
    /// Export the current project as a project-seed bootstrap package.
    /// </summary>
    public Task<PackageExportResult> ExportProjectSeedAsync(
        string outPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(outPath));
        }

        var fullPath = Path.GetFullPath(outPath);
        var resultJson = NativeBridge.PackageExportProjectSeed(_tn.NativeHandle, fullPath);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package export-project-seed returned non-object JSON");

        return Task.FromResult(new PackageExportResult(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package export-project-seed result omitted path"))));
    }

    /// <summary>
    /// Export local group-key material as a Python/TypeScript-compatible group-key package.
    /// </summary>
    public Task<PackageExportResult> ExportGroupKeysAsync(
        string outPath,
        IEnumerable<string>? groups = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(outPath));
        }

        var fullPath = Path.GetFullPath(outPath);
        var resultJson = NativeBridge.PackageExportGroupKeys(
            _tn.NativeHandle,
            fullPath,
            SerializeGroups(groups));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package export-group-keys returned non-object JSON");

        return Task.FromResult(new PackageExportResult(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package export-group-keys result omitted path"))));
    }

    /// <summary>
    /// Mint fresh reader kits for a recipient and export them as a kit bundle.
    /// </summary>
    public Task<BundleForRecipientResult> BundleForRecipientAsync(
        string recipientDid,
        string outPath,
        BundleForRecipientOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(recipientDid))
        {
            throw new ArgumentException("Recipient DID must not be empty.", nameof(recipientDid));
        }

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(outPath));
        }

        var fullPath = Path.GetFullPath(outPath);
        var resultJson = NativeBridge.PackageBundleForRecipient(
            _tn.NativeHandle,
            recipientDid,
            fullPath,
            SerializeGroups(options?.Groups),
            options?.SealForRecipient ?? false);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package bundle-for-recipient returned non-object JSON");
        var groups = result["groups"] as JsonArray
            ?? throw new TnException("native package bundle-for-recipient result omitted groups");

        return Task.FromResult(new BundleForRecipientResult(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package bundle-for-recipient result omitted path")),
            result["recipient_did"]?.GetValue<string>()
                ?? throw new TnException("native package bundle-for-recipient result omitted recipient DID"),
            groups.Select(group => group?.GetValue<string>() ?? string.Empty).ToArray()));
    }

    /// <summary>
    /// Export an admin snapshot and recipient reader bundle into one handoff directory.
    /// </summary>
    public async Task<RecipientHandoffResult> ExportRecipientHandoffAsync(
        RecipientHandoffOptions options,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.RecipientDid))
        {
            throw new ArgumentException("Recipient DID must not be empty.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.OutDirectory))
        {
            throw new ArgumentException("Output directory must not be empty.", nameof(options));
        }

        var outDirectory = Path.GetFullPath(options.OutDirectory);
        Directory.CreateDirectory(outDirectory);

        var adminPath = Path.Combine(outDirectory, "admin-snapshot.tnpkg");
        var bundlePath = Path.Combine(outDirectory, "reader-bundle.tnpkg");

        var admin = await ExportAdminSnapshotAsync(adminPath, cancellationToken).ConfigureAwait(false);
        var bundle = await BundleForRecipientAsync(
            options.RecipientDid,
            bundlePath,
            new BundleForRecipientOptions
            {
                Groups = options.Groups,
                SealForRecipient = options.SealForRecipient,
            },
            cancellationToken).ConfigureAwait(false);

        var adminInfo = await InspectAsync(admin.Path, cancellationToken).ConfigureAwait(false);
        var bundleInfo = await InspectAsync(bundle.Path, cancellationToken).ConfigureAwait(false);

        return new RecipientHandoffResult(
            admin.Path,
            bundle.Path,
            bundle.RecipientDid,
            bundle.Groups,
            adminInfo,
            bundleInfo);
    }

    /// <summary>
    /// Compile a recipient enrolment handoff package.
    /// </summary>
    public Task<CompiledPackageResult> CompileEnrolmentAsync(
        CompileEnrolmentOptions options,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Group))
        {
            throw new ArgumentException("Group must not be empty.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.RecipientDid))
        {
            throw new ArgumentException("Recipient DID must not be empty.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.OutPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(options));
        }

        var resultJson = NativeBridge.PackageCompileEnrolment(
            _tn.NativeHandle,
            options.Group,
            options.RecipientDid,
            Path.GetFullPath(options.OutPath),
            options.SealForRecipient);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package compile-enrolment returned non-object JSON");
        var groups = result["groups"] as JsonArray
            ?? throw new TnException("native package compile-enrolment result omitted groups");

        return Task.FromResult(new CompiledPackageResult(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package compile-enrolment result omitted path")),
            result["recipient_did"]?.GetValue<string>()
                ?? throw new TnException("native package compile-enrolment result omitted recipient DID"),
            groups.Select(group => group?.GetValue<string>() ?? string.Empty).ToArray(),
            result["manifest_sha256"]?.GetValue<string>()
                ?? throw new TnException("native package compile-enrolment result omitted manifest hash"),
            result["package_sha256"]?.GetValue<string>()
                ?? throw new TnException("native package compile-enrolment result omitted package hash")));
    }

    /// <summary>
    /// Compile an offer package and emit a local offer attestation.
    /// </summary>
    public Task<OfferReceipt> OfferAsync(
        OfferOptions options,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Group))
        {
            throw new ArgumentException("Group must not be empty.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.PeerDid))
        {
            throw new ArgumentException("Peer DID must not be empty.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.OutPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(options));
        }

        var resultJson = NativeBridge.PackageOffer(
            _tn.NativeHandle,
            options.Group,
            options.PeerDid,
            Path.GetFullPath(options.OutPath),
            options.SealForRecipient);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package offer returned non-object JSON");

        return Task.FromResult(new OfferReceipt(
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native package offer result omitted path")),
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native package offer result omitted group"),
            result["peer_did"]?.GetValue<string>()
                ?? throw new TnException("native package offer result omitted peer DID"),
            result["package_sha256"]?.GetValue<string>()
                ?? throw new TnException("native package offer result omitted package hash"),
            result["status"]?.GetValue<string>()
                ?? throw new TnException("native package offer result omitted status")));
    }

    /// <summary>
    /// Inspect package metadata from disk without absorbing the package.
    /// </summary>
    public Task<PackageInfo> InspectAsync(
        string sourcePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArgumentException("Source package path must not be empty.", nameof(sourcePath));
        }

        var resultJson = NativeBridge.PackageInspectPath(_tn.NativeHandle, Path.GetFullPath(sourcePath));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package inspect returned non-object JSON");
        var signature = result["signature"] as JsonObject
            ?? throw new TnException("native package inspect result omitted signature");
        var bodyEntryNames = result["body_entry_names"] as JsonArray
            ?? throw new TnException("native package inspect result omitted body entry names");

        return Task.FromResult(new PackageInfo(
            RequiredString(result, "kind", "native package inspect result omitted kind"),
            RequiredString(result, "category", "native package inspect result omitted category"),
            RequiredString(result, "scope", "native package inspect result omitted scope"),
            RequiredString(result, "publisher_identity", "native package inspect result omitted publisher identity"),
            result["recipient_identity"]?.GetValue<string>(),
            RequiredString(result, "ceremony_id", "native package inspect result omitted ceremony id"),
            RequiredUInt64(result, "event_count", "native package inspect result omitted event count"),
            result["head_row_hash"]?.GetValue<string>(),
            new PackageSignatureInfo(
                RequiredString(signature, "status", "native package inspect signature omitted status"),
                RequiredBool(signature, "verified", "native package inspect signature omitted verified flag"),
                signature["reason"]?.GetValue<string>()),
            RequiredUInt64(result, "body_entry_count", "native package inspect result omitted body entry count"),
            bodyEntryNames.Select(entry => entry?.GetValue<string>() ?? string.Empty).ToArray(),
            RequiredBool(result, "contains_secret_material", "native package inspect result omitted secret-material flag"),
            RequiredBool(result, "contains_reader_keys", "native package inspect result omitted reader-key flag"),
            RequiredBool(result, "has_package_json", "native package inspect result omitted package-json flag"),
            RequiredBool(result, "sealed", "native package inspect result omitted sealed flag")));
    }

    /// <summary>
    /// Absorb a package from disk.
    /// </summary>
    public Task<PackageAbsorbReceipt> AbsorbAsync(
        string sourcePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArgumentException("Source package path must not be empty.", nameof(sourcePath));
        }

        var resultJson = NativeBridge.PackageAbsorbPath(_tn.NativeHandle, Path.GetFullPath(sourcePath));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native package absorb returned non-object JSON");
        var replacedKitPaths = result["replaced_kit_paths"] as JsonArray
            ?? throw new TnException("native package absorb result omitted replaced kit paths");

        return Task.FromResult(new PackageAbsorbReceipt(
            result["kind"]?.GetValue<string>()
                ?? throw new TnException("native package absorb result omitted kind"),
            result["status"]?.GetValue<string>()
                ?? throw new TnException("native package absorb result omitted status"),
            result["accepted_count"]?.GetValue<ulong>()
                ?? throw new TnException("native package absorb result omitted accepted count"),
            result["deduped_count"]?.GetValue<ulong>()
                ?? throw new TnException("native package absorb result omitted deduped count"),
            result["noop"]?.GetValue<bool>()
                ?? throw new TnException("native package absorb result omitted noop flag"),
            result["conflict_count"]?.GetValue<ulong>()
                ?? throw new TnException("native package absorb result omitted conflict count"),
            result["legacy_status"]?.GetValue<string>() ?? string.Empty,
            result["legacy_reason"]?.GetValue<string>() ?? string.Empty,
            replacedKitPaths
                .Select(item => Path.GetFullPath(item?.GetValue<string>() ?? string.Empty))
                .ToArray()));
    }

    private static string? SerializeGroups(IEnumerable<string>? groups)
    {
        if (groups is null)
        {
            return null;
        }

        var groupList = groups.Select(group =>
        {
            if (string.IsNullOrWhiteSpace(group))
            {
                throw new ArgumentException("Groups must not contain empty values.", nameof(groups));
            }

            return group;
        }).ToArray();
        return JsonSerializer.Serialize(groupList);
    }

    private static string RequiredString(JsonObject obj, string key, string message)
    {
        return obj[key]?.GetValue<string>() ?? throw new TnException(message);
    }

    private static ulong RequiredUInt64(JsonObject obj, string key, string message)
    {
        return obj[key]?.GetValue<ulong>() ?? throw new TnException(message);
    }

    private static bool RequiredBool(JsonObject obj, string key, string message)
    {
        return obj[key]?.GetValue<bool>() ?? throw new TnException(message);
    }
}
