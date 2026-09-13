//! Governed data objects for `tn-proto`.
//!
//! This crate is the user-facing Rust wrapper around `tn-core`, the shared
//! protocol runtime used by the Python and TypeScript SDKs. Start with
//! [`Governance`], [`DataObject`], and [`GovernedObject`]. Release inserts the
//! encrypted use contract, binds each group with governance AAD, and signs.
//!
//! The application workflow is:
//!
//! ```text
//! create_obj -> receive -> mutate / attach / include -> release
//!             -> retain or forward the exact signed snapshot
//! ```
//!
//! [`Tn::open_objects`] loads an object context directly from configuration.
//! [`Tn::objects`] uses an existing runtime's material. [`GovernedWriter`] and
//! [`GovernedReader`] also work directly with supplied ciphers. The event,
//! administration, and package APIs support these data flows.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// Vault account binding helpers.
#[cfg(feature = "fs")]
pub mod account;
/// Ceremony administration helpers.
#[cfg(feature = "fs")]
pub mod admin;
/// Credential-store helpers for cached vault account keys.
#[cfg(feature = "fs")]
pub mod credential_store;
/// Trusted-principal enrollment: strict statements, locked receiver-local
/// state, and unsafe-operation observability. Root re-exports are added by
/// the shared native/SDK bridge integration.
#[cfg(feature = "fs")]
pub mod enrollment;
/// Stable Rust-facing read entry type.
#[cfg(feature = "fs")]
pub mod entry;
/// SDK-wide error and result types.
pub mod error;
/// Machine-global identity helpers.
#[cfg(feature = "fs")]
pub mod identity;
/// Local invitation inbox helpers.
#[cfg(feature = "fs")]
pub mod inbox;
#[doc = include_str!("../GOVERNED_OBJECTS.md")]
pub mod objects;
/// `.tnpkg` package export and absorb helpers.
#[cfg(feature = "fs")]
pub mod pkg;
/// Receiver-local exact-DID trust providers for secure reads.
#[cfg(feature = "fs")]
pub mod read_trust;
#[cfg(feature = "fs")]
mod security_warning;
/// Main `Tn` handle and lifecycle/read/emit APIs.
#[cfg(feature = "fs")]
pub mod tn;
/// Vault audit-event helpers.
#[cfg(feature = "fs")]
pub mod vault;
/// Headless wallet sync helpers.
#[cfg(feature = "fs")]
pub mod wallet;
/// Live log tailing APIs.
#[cfg(feature = "fs")]
pub mod watch;

#[cfg(feature = "fs")]
pub use account::{
    Account, AccountIdentityMetadata, AccountLogoutResult, AccountState, AccountStatus,
    AccountUseVaultResult, AccountVerdict,
};
#[cfg(feature = "http")]
#[cfg(feature = "fs")]
pub use account::{
    AccountConnectOptions, AccountConnectResult, ResolvedSigningIdentity, SigningIdentityTier,
};
#[cfg(feature = "fs")]
pub use admin::{
    AddRecipientResult, Admin, EnsureGroupResult, GrantReaderResult, RevokeRecipientResult,
    RotateIdPathResult,
};
#[cfg(feature = "http")]
#[cfg(feature = "fs")]
pub use credential_store::cache_account_awk_with_client;
#[cfg(feature = "fs")]
pub use credential_store::{
    awk_key_name, default_credential_store, default_identity_dir, default_identity_path,
    load_cached_account_awk, CredentialStore, FileCredentialStore,
};
#[cfg(feature = "fs")]
pub use entry::{Entry, EntryValidity};
pub use error::{Error, Result};
#[cfg(feature = "fs")]
pub use identity::{Identity, IdentityPrefs, IdentitySaveOptions};
#[cfg(feature = "fs")]
pub use inbox::{
    inspect_invitation_bytes, inspect_invitation_path, list_local as list_local_invites, Inbox,
    InvitationAcceptResult, InvitationInfo, InvitationKitHash, InvitationManifest,
    MintInvitationOptions, MintInvitationResult,
};
pub use objects::{
    AdmissionContext, AdmittedObject, AttachmentContext, ContractBinding, DataObject,
    DatasetBinding, DatasetCatalog, DatasetEdition, DatasetEditionDraft, DatasetSelection,
    EvaluatorArtifactSet, Governance, GovernanceView, GovernedDraft, GovernedObject,
    GovernedReader, GovernedWriter, LineageVerifier, OpenedObject, OwnedAdmissionContext,
    PolicyDag, PolicyParent, PolicyRelation, PolicyRevision, PolicyRevisionDraft,
    PublicationReport, ReleaseContext, SourceReference, UseContext, VerifiedLineage,
    DATASET_EDITION_GROUP, DATASET_EDITION_TYPE, GOVERNANCE_GROUP, POLICY_REVISION_GROUP,
    POLICY_REVISION_TYPE,
};
#[cfg(feature = "fs")]
pub use pkg::{
    AbsorbReceipt, AbsorbReceiptExt, AbsorbStatus, BundleForRecipientOptions,
    BundleForRecipientResult, CompileEnrolmentOptions, CompiledPackage, ContactUpdateApplyResult,
    ContactUpdateBody, ContactUpdatePackage, ExportOptions as PkgExportOptions, ManifestKind,
    OfferOptions, OfferReceipt, Package, PackageCategory, PackageInfo, PackageJsonPayload,
    PackageManifest, PackageSignatureStatus, SecretExportConsent,
};
#[cfg(feature = "fs")]
pub use read_trust::{
    ConfigReadTrustProvider, InMemoryReadTrustProvider, ReadTrustProvider, TrustSource,
};
#[cfg(feature = "fs")]
pub use tn::{
    ConfigView, EmitReceipt, LogLevel, ReadOptions, ReadPolicyOptions, ReadReport, SealedObject,
    Tn, TnInitOptions, TnProfile, TnProjectOptions,
};
#[cfg(feature = "http")]
#[cfg(feature = "fs")]
pub use tn::{TnProjectVaultClaim, TnProjectVaultClaimOptions};
#[cfg(feature = "fs")]
pub use tn_core::runtime::{CursorKind, ReadCursorV1, SourceCursorV1, VerifyMode};
#[cfg(feature = "fs")]
pub use tn_core::{
    RecipientEntry, SealOptions, SealedGroupInfo, SealedValid, UnsealOptions, UnsealOutcome,
};
#[cfg(feature = "fs")]
pub use vault::{
    decrypt_vault_body, derive_awk_from_material, derive_bek_from_material,
    derive_credential_key_pbkdf2, encrypt_vault_body, encrypt_vault_body_with_nonce,
    install_vault_body, unwrap_bek_from_awk, wrap_bek_under_awk, wrap_bek_under_awk_with_nonce,
    SetLinkStateOptions, Vault, VaultAwk, VaultBek, VaultBodyPlaintext, VaultClientConnectOptions,
    VaultConnectOptions, VaultConnectResult, VaultCredentialKdfParams, VaultCredentialWrap,
    VaultInstallBodyOptions, VaultInstallBodyResult, VaultLinkResult, VaultLinkState,
    VaultLinkStateInfo, VaultLinkStateResult, VaultProject, VaultProjectClient, VaultUnlinkResult,
    VaultWrappedBek, VAULT_AWK_WRAP_AAD, VAULT_BEK_WRAP_AAD, VAULT_BODY_CIPHER_SUITE,
    VAULT_BODY_FRAME, VAULT_MIN_PBKDF2_ITERATIONS,
};
#[cfg(feature = "http")]
#[cfg(feature = "fs")]
pub use vault::{
    VaultAccountInboxItem, VaultDeviceIdentity, VaultFile, VaultHttpConnectOptions,
    VaultHttpProjectClient, VaultHttpProjectClientOptions, VaultIdentity, VaultInboxSnapshot,
    VaultInitUploadOptions, VaultInitUploadResult, VaultPushBodyOptions, VaultPushBodyResult,
    VaultPushWithAwkOptions, VaultPushWithAwkResult, VaultPushWithCachedAwkOptions,
    VaultPushWithPassphraseOptions, VaultRestoreAndInstallWithAwkResult,
    VaultRestoreWithAwkOptions, VaultRestoreWithAwkResult, VaultRestoreWithCachedAwkOptions,
    VaultRestoreWithPassphraseOptions,
};
#[cfg(feature = "fs")]
pub use wallet::{
    inbox_dir, is_account_bound as wallet_is_account_bound, safe_path_segment, stem_dir,
    sync_state_path as wallet_sync_state_path, wallet_paths, Wallet, WalletPaths,
    WalletPullAbsorbResult, WalletStageInboxOptions, WalletStageInboxResult, WalletSyncOptions,
    WalletSyncResult,
};
#[cfg(feature = "http")]
#[cfg(feature = "fs")]
pub use wallet::{WalletPublishGroupKeysOptions, WalletPublishGroupKeysResult};
#[cfg(feature = "watch")]
#[cfg(feature = "fs")]
pub use watch::{NativeWatch, NativeWatchOptions};
#[cfg(feature = "fs")]
pub use watch::{PollingWatch, PollingWatchOptions, Watch, WatchIter, WatchOptions, WatchStart};

#[cfg(feature = "fs")]
pub use objects::{ObjectRegisters, Objects, Publication, ReleasePlan, Session, Workflow};

/// Common imports for applications that want a compact `use` line.
pub mod prelude {
    pub use crate::objects::{
        AdmissionContext, AdmittedObject, AttachmentContext, ContractBinding, DataObject,
        DatasetBinding, DatasetCatalog, DatasetEdition, DatasetEditionDraft, DatasetSelection,
        EvaluatorArtifactSet, Governance, GovernanceView, GovernedDraft, GovernedObject,
        GovernedReader, GovernedWriter, LineageVerifier, OpenedObject, OwnedAdmissionContext,
        PolicyDag, PolicyParent, PolicyRelation, PolicyRevision, PolicyRevisionDraft,
        PublicationReport, ReleaseContext, SourceReference, UseContext, VerifiedLineage,
        DATASET_EDITION_GROUP, DATASET_EDITION_TYPE, GOVERNANCE_GROUP, POLICY_REVISION_GROUP,
        POLICY_REVISION_TYPE,
    };
    #[cfg(feature = "fs")]
    pub use crate::{
        awk_key_name, decrypt_vault_body, default_credential_store, default_identity_dir,
        default_identity_path, derive_awk_from_material, derive_bek_from_material,
        derive_credential_key_pbkdf2, encrypt_vault_body, encrypt_vault_body_with_nonce,
        install_vault_body, load_cached_account_awk, unwrap_bek_from_awk, wrap_bek_under_awk,
        wrap_bek_under_awk_with_nonce, AbsorbReceipt, AbsorbReceiptExt, AbsorbStatus, Account,
        AccountIdentityMetadata, AccountLogoutResult, AccountState, AccountStatus,
        AccountUseVaultResult, AccountVerdict, AddRecipientResult, Admin,
        BundleForRecipientOptions, BundleForRecipientResult, CompileEnrolmentOptions,
        CompiledPackage, ConfigReadTrustProvider, ConfigView, CredentialStore, EmitReceipt,
        EnsureGroupResult, Entry, EntryValidity, Error, FileCredentialStore, Identity,
        IdentityPrefs, IdentitySaveOptions, InMemoryReadTrustProvider, Inbox,
        InvitationAcceptResult, InvitationInfo, InvitationKitHash, InvitationManifest, LogLevel,
        ManifestKind, MintInvitationOptions, MintInvitationResult, OfferOptions, OfferReceipt,
        Package, PackageInfo, PackageManifest, PackageSignatureStatus, PkgExportOptions,
        PollingWatch, PollingWatchOptions, ReadCursorV1, ReadOptions, ReadPolicyOptions,
        ReadReport, ReadTrustProvider, RecipientEntry, Result, RevokeRecipientResult, SealOptions,
        SealedGroupInfo, SealedObject, SealedValid, SecretExportConsent, SetLinkStateOptions,
        SourceCursorV1, Tn, TnInitOptions, TnProfile, TnProjectOptions, TrustSource, UnsealOptions,
        UnsealOutcome, Vault, VaultAwk, VaultBek, VaultBodyPlaintext, VaultClientConnectOptions,
        VaultConnectOptions, VaultConnectResult, VaultCredentialKdfParams, VaultCredentialWrap,
        VaultInstallBodyOptions, VaultInstallBodyResult, VaultLinkResult, VaultLinkState,
        VaultLinkStateInfo, VaultLinkStateResult, VaultProject, VaultProjectClient,
        VaultUnlinkResult, VaultWrappedBek, VerifyMode, Wallet, WalletPaths,
        WalletPullAbsorbResult, WalletStageInboxOptions, WalletStageInboxResult, WalletSyncOptions,
        WalletSyncResult, Watch, WatchIter, WatchOptions, WatchStart, VAULT_AWK_WRAP_AAD,
        VAULT_BEK_WRAP_AAD, VAULT_BODY_CIPHER_SUITE, VAULT_BODY_FRAME, VAULT_MIN_PBKDF2_ITERATIONS,
    };
    #[cfg(feature = "http")]
    #[cfg(feature = "fs")]
    pub use crate::{
        cache_account_awk_with_client, AccountConnectOptions, AccountConnectResult,
        ResolvedSigningIdentity, SigningIdentityTier, TnProjectVaultClaim,
        TnProjectVaultClaimOptions, VaultAccountInboxItem, VaultDeviceIdentity, VaultFile,
        VaultHttpConnectOptions, VaultHttpProjectClient, VaultHttpProjectClientOptions,
        VaultIdentity, VaultInboxSnapshot, VaultInitUploadOptions, VaultInitUploadResult,
        VaultPushBodyOptions, VaultPushBodyResult, VaultPushWithAwkOptions, VaultPushWithAwkResult,
        VaultPushWithCachedAwkOptions, VaultPushWithPassphraseOptions,
        VaultRestoreAndInstallWithAwkResult, VaultRestoreWithAwkOptions, VaultRestoreWithAwkResult,
        VaultRestoreWithCachedAwkOptions, VaultRestoreWithPassphraseOptions,
        WalletPublishGroupKeysOptions, WalletPublishGroupKeysResult,
    };
    #[cfg(feature = "watch")]
    #[cfg(feature = "fs")]
    pub use crate::{NativeWatch, NativeWatchOptions};
    #[cfg(feature = "fs")]
    pub use crate::{ObjectRegisters, Objects, Publication, ReleasePlan, Session, Workflow};
}

/// Typed native provider contracts and first adapters.
pub use tn_core::providers;
