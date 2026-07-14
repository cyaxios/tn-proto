using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace TnProto;

/// <summary>
/// Operation whose normal security guarantees were explicitly weakened.
/// </summary>
public enum UnsafeOperation
{
    /// <summary>Read one or more existing log sources.</summary>
    Read,

    /// <summary>Watch a log source for new entries.</summary>
    Watch,

    /// <summary>Register a raw JWE recipient without a verified key binding.</summary>
    JweAddRecipient,

    /// <summary>Deliver a HIBE reader grant through an unsafe compatibility path.</summary>
    HibeGrant,

    /// <summary>Import a legacy package without current identity guarantees.</summary>
    LegacyPackageImport,
}

/// <summary>
/// Individual guarantee relaxed for an <see cref="UnsafeOperation"/>.
/// </summary>
public enum UnsafeRelaxation
{
    /// <summary>Disable cryptographic verification.</summary>
    VerificationDisabled,

    /// <summary>Permit an unsigned record or package.</summary>
    SignatureNotRequired,

    /// <summary>Permit records that are not authenticated.</summary>
    UnauthenticatedAllowed,

    /// <summary>Permit a writer outside the receiver's trust policy.</summary>
    UnknownWriterAllowed,

    /// <summary>Use a public key without a verified DID binding.</summary>
    UnverifiedKeyBinding,

    /// <summary>Deliver a bearer artifact without recipient sealing.</summary>
    PlaintextBearerDelivery,

    /// <summary>Accept a legacy package whose claimed and actual signers differ.</summary>
    LegacySignerMismatch,
}

/// <summary>
/// Canonical five-field payload for an explicitly weakened security operation.
/// </summary>
public sealed class UnsafeOperationNotice
{
    private static readonly JsonWriterOptions CanonicalWriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
        SkipValidation = false,
    };

    /// <summary>
    /// Initializes a notice and normalizes its relaxations into unique wire-name order.
    /// </summary>
    public UnsafeOperationNotice(
        UnsafeOperation operation,
        IEnumerable<UnsafeRelaxation> relaxations,
        string? group = null,
        string? subjectDid = null,
        string? artifactDigest = null)
    {
        ArgumentNullException.ThrowIfNull(relaxations);
        _ = OperationWireName(operation);

        Operation = operation;
        Relaxations = Array.AsReadOnly(
            relaxations
                .Distinct()
                .OrderBy(static value => RelaxationWireName(value), StringComparer.Ordinal)
                .ToArray());
        Group = group;
        SubjectDid = subjectDid;
        ArtifactDigest = artifactDigest;
    }

    /// <summary>Operation whose guarantees were weakened.</summary>
    public UnsafeOperation Operation { get; }

    /// <summary>Sorted, de-duplicated guarantees that were relaxed.</summary>
    public IReadOnlyList<UnsafeRelaxation> Relaxations { get; }

    /// <summary>Optional affected encryption group.</summary>
    public string? Group { get; }

    /// <summary>Optional DID of the principal affected by the operation.</summary>
    public string? SubjectDid { get; }

    /// <summary>Optional digest of the artifact involved in the operation.</summary>
    public string? ArtifactDigest { get; }

    /// <summary>Returns the stable cross-SDK wire name for an operation.</summary>
    public static string OperationWireName(UnsafeOperation operation) => operation switch
    {
        UnsafeOperation.Read => "read",
        UnsafeOperation.Watch => "watch",
        UnsafeOperation.JweAddRecipient => "jwe_add_recipient",
        UnsafeOperation.HibeGrant => "hibe_grant",
        UnsafeOperation.LegacyPackageImport => "legacy_package_import",
        _ => throw new ArgumentOutOfRangeException(
            nameof(operation),
            operation,
            "Unknown unsafe operation."),
    };

    /// <summary>Returns the stable cross-SDK wire name for a relaxation.</summary>
    public static string RelaxationWireName(UnsafeRelaxation relaxation) => relaxation switch
    {
        UnsafeRelaxation.VerificationDisabled => "verification_disabled",
        UnsafeRelaxation.SignatureNotRequired => "signature_not_required",
        UnsafeRelaxation.UnauthenticatedAllowed => "unauthenticated_allowed",
        UnsafeRelaxation.UnknownWriterAllowed => "unknown_writer_allowed",
        UnsafeRelaxation.UnverifiedKeyBinding => "unverified_key_binding",
        UnsafeRelaxation.PlaintextBearerDelivery => "plaintext_bearer_delivery",
        UnsafeRelaxation.LegacySignerMismatch => "legacy_signer_mismatch",
        _ => throw new ArgumentOutOfRangeException(
            nameof(relaxation),
            relaxation,
            "Unknown unsafe relaxation."),
    };

    /// <summary>
    /// Serializes the exact five-field payload as compact, canonical JSON.
    /// </summary>
    public string ToCanonicalJson()
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, CanonicalWriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("artifact_digest", ArtifactDigest);
            writer.WriteString("group", Group);
            writer.WriteString("operation", OperationWireName(Operation));
            writer.WriteStartArray("relaxations");
            foreach (var relaxation in Relaxations)
            {
                writer.WriteStringValue(RelaxationWireName(relaxation));
            }

            writer.WriteEndArray();
            writer.WriteString("subject_did", SubjectDid);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
