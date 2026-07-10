using System.Text.Json;
using System.Text.Json.Nodes;
using TnProto.Native;

namespace TnProto.Admin;

/// <summary>
/// Administration helpers for group setup and recipient management.
/// </summary>
public sealed class AdminClient
{
    private readonly Tn _tn;

    internal AdminClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// Ensure a group exists and route the supplied private fields into it.
    /// </summary>
    public Task<AdminEnsureGroupResult> EnsureGroupAsync(
        string group,
        IEnumerable<string> fields,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(group))
        {
            throw new ArgumentException("Group must not be empty.", nameof(group));
        }

        ArgumentNullException.ThrowIfNull(fields);
        var fieldList = fields.Select(field =>
        {
            if (string.IsNullOrWhiteSpace(field))
            {
                throw new ArgumentException("Fields must not contain empty values.", nameof(fields));
            }

            return field;
        }).ToArray();

        var resultJson = NativeBridge.AdminEnsureGroup(
            _tn.NativeHandle,
            group,
            JsonSerializer.Serialize(fieldList));
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin ensure-group returned non-object JSON");
        var resultFields = result["fields"] as JsonArray
            ?? throw new TnException("native admin ensure-group result omitted fields");

        return Task.FromResult(new AdminEnsureGroupResult(
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native admin ensure-group result omitted group"),
            resultFields.Select(item => item?.GetValue<string>() ?? string.Empty).ToArray(),
            result["created"]?.GetValue<bool>()
                ?? throw new TnException("native admin ensure-group result omitted created flag"),
            result["changed"]?.GetValue<bool>()
                ?? throw new TnException("native admin ensure-group result omitted changed flag")));
    }

    /// <summary>
    /// Mint a reader kit for a recipient in a group.
    /// </summary>
    public Task<AdminAddRecipientResult> AddRecipientAsync(
        string group,
        string outKitPath,
        string? recipientDid = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(group))
        {
            throw new ArgumentException("Group must not be empty.", nameof(group));
        }

        if (string.IsNullOrWhiteSpace(outKitPath))
        {
            throw new ArgumentException("Output kit path must not be empty.", nameof(outKitPath));
        }

        if (!outKitPath.EndsWith(".btn.mykit", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Output kit path must end with .btn.mykit.", nameof(outKitPath));
        }

        var fullKitPath = Path.GetFullPath(outKitPath);
        var resultJson = NativeBridge.AdminAddRecipient(_tn.NativeHandle, group, recipientDid, fullKitPath);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin add-recipient returned non-object JSON");

        return Task.FromResult(new AdminAddRecipientResult(
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native admin add-recipient result omitted group"),
            result["recipient_did"]?.GetValue<string>(),
            result["leaf_index"]?.GetValue<ulong>()
                ?? throw new TnException("native admin add-recipient result omitted leaf index"),
            Path.GetFullPath(result["kit_path"]?.GetValue<string>()
                ?? throw new TnException("native admin add-recipient result omitted kit path"))));
    }

    /// <summary>
    /// Revoke a recipient reader by leaf index.
    /// </summary>
    public Task<AdminRevokeRecipientResult> RevokeRecipientAsync(
        string group,
        ulong leafIndex,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ValidateGroup(group);

        var resultJson = NativeBridge.AdminRevokeRecipient(_tn.NativeHandle, group, leafIndex);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin revoke-recipient returned non-object JSON");

        return Task.FromResult(new AdminRevokeRecipientResult(
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native admin revoke-recipient result omitted group"),
            result["leaf_index"]?.GetValue<ulong>()
                ?? throw new TnException("native admin revoke-recipient result omitted leaf index")));
    }

    /// <summary>
    /// Rotate a btn publisher group to a fresh key generation.
    /// </summary>
    public Task<AdminRotateGroupResult> RotateAsync(
        string group,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ValidateGroup(group);

        var resultJson = NativeBridge.AdminRotateGroup(_tn.NativeHandle, group);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin rotate returned non-object JSON");

        return Task.FromResult(new AdminRotateGroupResult(
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate result omitted group"),
            result["generation"]?.GetValue<uint>()
                ?? throw new TnException("native admin rotate result omitted generation"),
            result["previous_kit_sha256"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate result omitted previous kit hash"),
            result["new_kit_sha256"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate result omitted new kit hash"),
            result["rotated_at"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate result omitted rotated timestamp")));
    }

    /// <summary>
    /// HIBE's add-recipient: mint a delegated identity key for a reader and
    /// export it as an absorbable <c>.tnpkg</c> kit. Hibe groups only —
    /// grant_reader is hibe-only; use <see cref="AddRecipientAsync"/> for
    /// btn/jwe groups. <paramref name="idPath"/> defaults to the group's
    /// current sealing path; pass an ancestor path to hand out a key the
    /// reader can delegate further down. The kit body is sealed to
    /// <paramref name="readerDid"/> when the DID embeds a resolvable key,
    /// and the grant is recorded in the authority's grant registry.
    /// </summary>
    public Task<AdminGrantReaderResult> GrantReaderAsync(
        string group,
        string readerDid,
        string outPath,
        string? idPath = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ValidateGroup(group);

        if (string.IsNullOrWhiteSpace(readerDid))
        {
            throw new ArgumentException("Reader DID must not be empty.", nameof(readerDid));
        }

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("Output package path must not be empty.", nameof(outPath));
        }

        var fullOutPath = Path.GetFullPath(outPath);
        var resultJson = NativeBridge.AdminGrantReader(
            _tn.NativeHandle,
            group,
            readerDid,
            fullOutPath,
            idPath);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin grant-reader returned non-object JSON");

        return Task.FromResult(new AdminGrantReaderResult(
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native admin grant-reader result omitted group"),
            result["reader_did"]?.GetValue<string>(),
            result["id_path"]?.GetValue<string>()
                ?? throw new TnException("native admin grant-reader result omitted id path"),
            Path.GetFullPath(result["path"]?.GetValue<string>()
                ?? throw new TnException("native admin grant-reader result omitted kit path"))));
    }

    /// <summary>
    /// Rotate a hibe group's identity path so FUTURE seals use
    /// <paramref name="newPath"/>. Admission rotation, not revocation:
    /// pre-rotation seals stay open for prior grantees, and the authority
    /// keeps opening every epoch via the recorded path history. The live
    /// runtime's group cipher is refreshed, so the next emit or seal
    /// through this handle already lands on the new path. The root path
    /// (empty string) requires <paramref name="allowRootPath"/>.
    /// </summary>
    public Task<AdminRotateIdPathResult> RotateIdPathAsync(
        string group,
        string newPath,
        bool allowRootPath = false,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ValidateGroup(group);
        ArgumentNullException.ThrowIfNull(newPath);

        var resultJson = NativeBridge.AdminRotateIdPath(_tn.NativeHandle, group, newPath, allowRootPath);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin rotate-id-path returned non-object JSON");

        return Task.FromResult(new AdminRotateIdPathResult(
            result["group"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate-id-path result omitted group"),
            result["previous_path"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate-id-path result omitted previous path"),
            result["new_path"]?.GetValue<string>()
                ?? throw new TnException("native admin rotate-id-path result omitted new path")));
    }

    /// <summary>
    /// Return recipient roster rows for a group.
    /// </summary>
    public Task<IReadOnlyList<AdminRecipient>> RecipientsAsync(
        string group,
        bool includeRevoked = false,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ValidateGroup(group);

        var recipientsJson = NativeBridge.AdminRecipients(_tn.NativeHandle, group, includeRevoked);
        var node = JsonNode.Parse(recipientsJson) as JsonArray
            ?? throw new TnException("native admin recipients returned non-array JSON");
        var recipients = new List<AdminRecipient>(node.Count);

        foreach (var item in node)
        {
            var recipient = item as JsonObject
                ?? throw new TnException("native admin recipients returned a non-object row");
            recipients.Add(new AdminRecipient(
                recipient["leaf_index"]?.GetValue<ulong>()
                    ?? throw new TnException("native admin recipient omitted leaf index"),
                recipient["recipient_identity"]?.GetValue<string>(),
                recipient["minted_at"]?.GetValue<string>(),
                recipient["kit_sha256"]?.GetValue<string>(),
                recipient["revoked"]?.GetValue<bool>()
                    ?? throw new TnException("native admin recipient omitted revoked flag"),
                recipient["revoked_at"]?.GetValue<string>()));
        }

        return Task.FromResult<IReadOnlyList<AdminRecipient>>(recipients);
    }

    /// <summary>
    /// Return the number of revoked recipient leaves in a group.
    /// </summary>
    public Task<ulong> RevokedCountAsync(
        string group,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();
        ValidateGroup(group);

        var resultJson = NativeBridge.AdminRevokedCount(_tn.NativeHandle, group);
        var result = JsonNode.Parse(resultJson) as JsonObject
            ?? throw new TnException("native admin revoked-count returned non-object JSON");
        return Task.FromResult(result["revoked_count"]?.GetValue<ulong>()
            ?? throw new TnException("native admin revoked-count result omitted count"));
    }

    private static void ValidateGroup(string group)
    {
        if (string.IsNullOrWhiteSpace(group))
        {
            throw new ArgumentException("Group must not be empty.", nameof(group));
        }
    }
}
