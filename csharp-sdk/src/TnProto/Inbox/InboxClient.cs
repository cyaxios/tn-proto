using System.Text.Json.Nodes;
using System.Text.Json;
using TnProto.Native;

namespace TnProto.Inbox;

/// <summary>
/// Local invitation inbox helpers.
/// </summary>
public sealed class InboxClient
{
    private readonly Tn _tn;

    internal InboxClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// List local <c>tn-invite-*.zip</c> files in a directory.
    /// </summary>
    public Task<IReadOnlyList<string>> ListLocalAsync(
        string directory,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("Directory must not be empty.", nameof(directory));
        }

        var resultJson = NativeBridge.InboxListLocal(_tn.NativeHandle, Path.GetFullPath(directory));
        var result = JsonNode.Parse(resultJson) as JsonArray
            ?? throw new TnException("native inbox list-local returned non-array JSON");
        var paths = result
            .Select(path => Path.GetFullPath(path?.GetValue<string>() ?? string.Empty))
            .ToArray();

        return Task.FromResult<IReadOnlyList<string>>(paths);
    }

    /// <summary>
    /// Inspect an invitation zip without accepting it into the local project.
    /// </summary>
    public Task<InvitationInfo> InspectAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Invitation path must not be empty.", nameof(path));
        }

        var resultJson = NativeBridge.InboxInspectPath(_tn.NativeHandle, Path.GetFullPath(path));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native inbox inspect returned non-object JSON");
        return Task.FromResult(ParseInfo(result, "native inbox inspect"));
    }

    /// <summary>
    /// Accept an invitation zip into the local project.
    /// </summary>
    public Task<InvitationAcceptResult> AcceptAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Invitation path must not be empty.", nameof(path));
        }

        var resultJson = NativeBridge.InboxAcceptPath(_tn.NativeHandle, Path.GetFullPath(path));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native inbox accept returned non-object JSON");
        var info = result["info"] as JsonObject
            ?? throw new TnException("native inbox accept result omitted info");

        return Task.FromResult(new InvitationAcceptResult(
            ParseInfo(info, "native inbox accept info"),
            Path.GetFullPath(RequiredString(result, "kit_path", "native inbox accept result omitted kit path")),
            OptionalString(result, "backup_path") is { } backupPath ? Path.GetFullPath(backupPath) : null,
            RequiredString(result, "absorbed_at", "native inbox accept result omitted absorbed timestamp"),
            RequiredString(result, "group_name", "native inbox accept result omitted group name"),
            RequiredString(result, "from_email", "native inbox accept result omitted sender"),
            result["leaf_index"]?.DeepClone()));
    }

    /// <summary>
    /// Mint a local invitation zip for a recipient.
    /// </summary>
    public Task<MintInvitationResult> MintInviteAsync(
        string recipient,
        string outPath,
        MintInvitationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(recipient))
        {
            throw new ArgumentException("Recipient must not be empty.", nameof(recipient));
        }

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output path must not be empty.", nameof(outPath));
        }

        var resultJson = NativeBridge.InboxMintInvitePath(
            _tn.NativeHandle,
            recipient,
            Path.GetFullPath(outPath),
            SerializeMintOptions(options));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native inbox mint returned non-object JSON");
        var manifest = result["manifest"] as JsonObject
            ?? throw new TnException("native inbox mint result omitted manifest");

        return Task.FromResult(new MintInvitationResult(
            Path.GetFullPath(RequiredString(result, "path", "native inbox mint result omitted path")),
            RequiredString(result, "recipient_did", "native inbox mint result omitted recipient DID"),
            ParseManifest(manifest),
            RequiredString(result, "kit_entry_name", "native inbox mint result omitted kit entry name"),
            RequiredUInt64(result, "zip_len", "native inbox mint result omitted zip length")));
    }

    private static InvitationInfo ParseInfo(JsonObject result, string context)
    {
        var manifest = result["manifest"] as JsonObject
            ?? throw new TnException($"{context} result omitted manifest");
        var kitHash = result["kit_hash"] as JsonObject
            ?? throw new TnException($"{context} result omitted kit hash");

        return new InvitationInfo(
            ParseManifest(manifest),
            RequiredString(result, "group_name", $"{context} result omitted group name"),
            RequiredString(result, "kit_entry_name", $"{context} result omitted kit entry name"),
            RequiredUInt64(result, "kit_len", $"{context} result omitted kit length"),
            RequiredString(result, "kit_sha256_actual", $"{context} result omitted kit hash"),
            new InvitationKitHash(
                RequiredString(kitHash, "status", $"{context} kit hash omitted status"),
                RequiredBool(kitHash, "verified", $"{context} kit hash omitted verified flag"),
                kitHash["expected"]?.GetValue<string>()),
            RequiredBool(result, "kit_hash_verified", $"{context} result omitted kit hash verified flag"));
    }

    private static InvitationManifest ParseManifest(JsonObject manifest)
    {
        return new InvitationManifest(
            OptionalString(manifest, "invitation_id"),
            OptionalString(manifest, "from_account_did"),
            OptionalString(manifest, "from_email"),
            OptionalString(manifest, "project_id"),
            OptionalString(manifest, "project_name"),
            OptionalString(manifest, "group_name"),
            manifest["leaf_index"]?.DeepClone(),
            OptionalString(manifest, "kit_sha256"),
            manifest["event_id"]?.DeepClone(),
            OptionalString(manifest, "created_at"),
            OptionalString(manifest, "note"),
            OptionalString(manifest, "provenance"),
            (JsonObject)manifest.DeepClone());
    }

    private static string? OptionalString(JsonObject obj, string key)
    {
        return obj[key] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
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

    private static string? SerializeMintOptions(MintInvitationOptions? options)
    {
        if (options is null)
        {
            return null;
        }

        var obj = new JsonObject
        {
            ["group"] = options.Group,
            ["from_email"] = options.FromEmail,
            ["project_id"] = options.ProjectId,
            ["project_name"] = options.ProjectName,
            ["note"] = options.Note,
            ["invitation_id"] = options.InvitationId,
            ["provenance"] = options.Provenance,
        };
        return JsonSerializer.Serialize(obj);
    }
}
