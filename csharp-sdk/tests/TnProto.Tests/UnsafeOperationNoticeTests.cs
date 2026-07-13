using System.Runtime.CompilerServices;

namespace TnProto.Tests;

public sealed class UnsafeOperationNoticeTests
{
    [Fact]
    public void CanonicalPayloadUsesExactFiveFieldContract()
    {
        var notice = new UnsafeOperationNotice(
            UnsafeOperation.Read,
            [UnsafeRelaxation.VerificationDisabled]);

        Assert.Equal(
            "{\"artifact_digest\":null,\"group\":null,\"operation\":\"read\","
                + "\"relaxations\":[\"verification_disabled\"],\"subject_did\":null}",
            notice.ToCanonicalJson());
    }

    [Fact]
    public void ConstructorSortsAndDeduplicatesRelaxations()
    {
        var notice = new UnsafeOperationNotice(
            UnsafeOperation.JweAddRecipient,
            [
                UnsafeRelaxation.UnverifiedKeyBinding,
                UnsafeRelaxation.SignatureNotRequired,
                UnsafeRelaxation.UnverifiedKeyBinding,
            ],
            group: "default",
            subjectDid: "did:key:zExample",
            artifactDigest: "sha256:abc");

        Assert.Equal(
            [
                UnsafeRelaxation.SignatureNotRequired,
                UnsafeRelaxation.UnverifiedKeyBinding,
            ],
            notice.Relaxations);
    }

    [Fact]
    public void EnumsFreezeEveryCrossSdkWireValue()
    {
        Assert.Equal(
            ["read", "watch", "jwe_add_recipient", "hibe_grant", "legacy_package_import"],
            Enum.GetValues<UnsafeOperation>().Select(UnsafeOperationNotice.OperationWireName));
        Assert.Equal(
            [
                "verification_disabled",
                "signature_not_required",
                "unauthenticated_allowed",
                "unknown_writer_allowed",
                "unverified_key_binding",
                "plaintext_bearer_delivery",
                "legacy_signer_mismatch",
            ],
            Enum.GetValues<UnsafeRelaxation>().Select(UnsafeOperationNotice.RelaxationWireName));
    }

    [Fact]
    public void TnRaisesSharedSecurityWarningEventWithSameNotice()
    {
        var tn = (Tn)RuntimeHelpers.GetUninitializedObject(typeof(Tn));
        var notice = new UnsafeOperationNotice(
            UnsafeOperation.Read,
            [UnsafeRelaxation.VerificationDisabled]);
        TnSecurityWarningEventArgs? observed = null;

        tn.SecurityWarning += (_, args) => observed = args;
        tn.RaiseSecurityWarning(notice);

        Assert.NotNull(observed);
        Assert.Same(notice, observed.Notice);
    }
}
