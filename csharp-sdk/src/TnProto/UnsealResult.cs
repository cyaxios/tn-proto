using System.Text.Json.Nodes;

namespace TnProto;

/// <summary>
/// Which of the two sealed-object integrity checks passed. Both report
/// <see langword="false"/> when <see cref="UnsealOptions.Verify"/> was off.
/// </summary>
public sealed class UnsealValidity
{
    internal UnsealValidity(bool signature, bool rowHash)
    {
        Signature = signature;
        RowHash = rowHash;
    }

    /// <summary>
    /// The envelope's signature verifies over its row hash under its
    /// device identity.
    /// </summary>
    public bool Signature { get; }

    /// <summary>
    /// The row hash recomputes from the envelope's own contents.
    /// </summary>
    public bool RowHash { get; }

    /// <summary>
    /// True when both checks passed.
    /// </summary>
    public bool IsValid => Signature && RowHash;
}

/// <summary>
/// One group block <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>
/// could not open, with everything a managed cipher needs for a second-pass
/// decrypt: the wire ciphertext, the reconstructed AAD bytes (both base64),
/// and which cipher kinds have key files on disk the native build could not
/// use (<c>"jwe"</c> always; <c>"hibe"</c> only in hibe-less native builds).
/// </summary>
public sealed record SealedBlock(
    string Name,
    string CiphertextB64,
    IReadOnlyDictionary<string, string> FieldHashes,
    string AadB64,
    IReadOnlyList<string> KeystoreCandidates);

/// <summary>
/// Result of <see cref="Tn.UnsealAsync(string, UnsealOptions?, CancellationToken)"/>:
/// the verified envelope, every group block a held key opened, and the
/// blocks left sealed.
/// </summary>
public sealed class UnsealResult
{
    internal UnsealResult(
        JsonObject envelope,
        IReadOnlyDictionary<string, JsonObject> plaintext,
        UnsealValidity valid,
        IReadOnlyList<string> hiddenGroups,
        IReadOnlyList<SealedBlock> sealedBlocks,
        JsonObject fields)
    {
        Envelope = envelope;
        Plaintext = plaintext;
        Valid = valid;
        HiddenGroups = hiddenGroups;
        SealedBlocks = sealedBlocks;
        Fields = fields;
    }

    /// <summary>
    /// The envelope, wire-faithful (keeps the <c>tn_sealed</c> marker).
    /// </summary>
    public JsonObject Envelope { get; }

    /// <summary>
    /// Opened groups only: group name to decrypted JSON body.
    /// </summary>
    public IReadOnlyDictionary<string, JsonObject> Plaintext { get; }

    /// <summary>
    /// Which integrity checks passed.
    /// </summary>
    public UnsealValidity Valid { get; }

    /// <summary>
    /// Blocks present in the envelope but not opened, sorted.
    /// </summary>
    public IReadOnlyList<string> HiddenGroups { get; }

    /// <summary>
    /// Per-unopened-block decrypt material — the managed-cipher
    /// second-pass seam.
    /// </summary>
    public IReadOnlyList<SealedBlock> SealedBlocks { get; }

    /// <summary>
    /// Entry-style merge: opened group plaintexts (alphabetical group
    /// order, last-write-wins), then non-reserved non-block public extras.
    /// The <c>tn_sealed</c> wire marker is dropped.
    /// </summary>
    public JsonObject Fields { get; }

    /// <summary>
    /// Parse the native unseal outcome JSON into a typed result.
    /// </summary>
    internal static UnsealResult FromNativeJson(string json)
    {
        var outcome = JsonNode.Parse(json) as JsonObject
            ?? throw new TnException("native unseal returned non-object JSON");

        var envelope = outcome["envelope"] as JsonObject
            ?? throw new TnException("native unseal outcome omitted the envelope");
        var fields = outcome["fields"] as JsonObject
            ?? throw new TnException("native unseal outcome omitted fields");

        var plaintext = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        if (outcome["plaintext"] is JsonObject plaintextNode)
        {
            foreach (var (group, body) in plaintextNode)
            {
                if (body is JsonObject bodyObject)
                {
                    plaintext[group] = bodyObject;
                }
            }
        }

        var validNode = outcome["valid"] as JsonObject;
        var valid = new UnsealValidity(
            validNode?["signature"]?.GetValue<bool>() ?? false,
            validNode?["row_hash"]?.GetValue<bool>() ?? false);

        var hiddenGroups = new List<string>();
        if (outcome["hidden_groups"] is JsonArray hiddenNode)
        {
            foreach (var item in hiddenNode)
            {
                if (item?.GetValue<string>() is { } group)
                {
                    hiddenGroups.Add(group);
                }
            }
        }

        var sealedBlocks = new List<SealedBlock>();
        if (outcome["sealed_blocks"] is JsonArray blocksNode)
        {
            foreach (var item in blocksNode)
            {
                if (item is not JsonObject block)
                {
                    continue;
                }

                var fieldHashes = new Dictionary<string, string>(StringComparer.Ordinal);
                if (block["field_hashes"] is JsonObject hashesNode)
                {
                    foreach (var (name, token) in hashesNode)
                    {
                        if (token?.GetValue<string>() is { } value)
                        {
                            fieldHashes[name] = value;
                        }
                    }
                }

                var candidates = new List<string>();
                if (block["keystore_candidates"] is JsonArray candidatesNode)
                {
                    foreach (var candidate in candidatesNode)
                    {
                        if (candidate?.GetValue<string>() is { } kind)
                        {
                            candidates.Add(kind);
                        }
                    }
                }

                sealedBlocks.Add(new SealedBlock(
                    block["name"]?.GetValue<string>() ?? "",
                    block["ciphertext_b64"]?.GetValue<string>() ?? "",
                    fieldHashes,
                    block["aad_b64"]?.GetValue<string>() ?? "",
                    candidates));
            }
        }

        return new UnsealResult(envelope, plaintext, valid, hiddenGroups, sealedBlocks, fields);
    }
}
