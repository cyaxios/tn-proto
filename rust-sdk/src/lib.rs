//! Idiomatic Rust SDK for `tn-proto`.
//!
//! This crate is the user-facing Rust wrapper around `tn-core`, the shared
//! protocol runtime used by the Python and TypeScript SDKs. Keep protocol
//! primitives in `tn-core`; this crate should focus on Rust ergonomics:
//! lifecycle, emit/read verbs, admin helpers, package helpers, and watch APIs.
//!
//! The first implementation milestone is intentionally small:
//!
//! ```text
//! Tn::init(...) -> tn.info(...) -> tn.read(...) -> tn.close()
//! ```
//!
//! Once that path is stable and covered by parity tests, the admin, package,
//! and watch modules can grow around the same `Tn` handle.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// Vault account binding helpers.
pub mod account;
/// Ceremony administration helpers.
pub mod admin;
/// Byte-oriented BTN broadcast-encryption primitives.
pub mod btn;
/// Credential-store helpers for cached vault account keys.
pub mod credential_store;
/// Trusted-principal enrollment: strict statements, locked receiver-local
/// state, and unsafe-operation observability. Root re-exports are added by
/// the shared native/SDK bridge integration.
pub mod enrollment;
/// Stable Rust-facing read entry type.
pub mod entry;
/// SDK-wide error and result types.
pub mod error;
/// Machine-global identity helpers.
pub mod identity;
/// Local invitation inbox helpers.
pub mod inbox;
/// Byte-oriented RFC 7516 JWE primitives.
pub mod jwe;
/// `.tnpkg` package export and absorb helpers.
pub mod pkg;
/// Receiver-local exact-DID trust providers for secure reads.
pub mod read_trust;
mod security_warning;
/// Main `Tn` handle and lifecycle/read/emit APIs.
pub mod tn;
/// Vault audit-event helpers.
pub mod vault;
/// Headless wallet sync helpers.
pub mod wallet;
/// Live log tailing APIs.
pub mod watch;

pub use account::{
    Account, AccountIdentityMetadata, AccountLogoutResult, AccountState, AccountStatus,
    AccountUseVaultResult, AccountVerdict,
};
#[cfg(feature = "http")]
pub use account::{
    AccountConnectOptions, AccountConnectResult, ResolvedSigningIdentity, SigningIdentityTier,
};
pub use admin::{
    AddRecipientResult, Admin, EnsureGroupResult, GrantReaderResult, RevokeRecipientResult,
    RotateIdPathResult,
};
#[cfg(feature = "http")]
pub use credential_store::cache_account_awk_with_client;
pub use credential_store::{
    awk_key_name, default_credential_store, default_identity_dir, default_identity_path,
    load_cached_account_awk, CredentialStore, FileCredentialStore,
};
pub use entry::{Entry, EntryValidity};
pub use error::{Error, Result};
pub use identity::{Identity, IdentityPrefs, IdentitySaveOptions};
pub use inbox::{
    inspect_invitation_bytes, inspect_invitation_path, list_local as list_local_invites, Inbox,
    InvitationAcceptResult, InvitationInfo, InvitationKitHash, InvitationManifest,
    MintInvitationOptions, MintInvitationResult,
};
pub use pkg::{
    AbsorbReceipt, AbsorbReceiptExt, AbsorbStatus, BundleForRecipientOptions,
    BundleForRecipientResult, CompileEnrolmentOptions, CompiledPackage, ContactUpdateApplyResult,
    ContactUpdateBody, ContactUpdatePackage, ExportOptions as PkgExportOptions, ManifestKind,
    OfferOptions, OfferReceipt, Package, PackageCategory, PackageInfo, PackageJsonPayload,
    PackageManifest, PackageSignatureStatus, SecretExportConsent,
};
pub use read_trust::{
    ConfigReadTrustProvider, InMemoryReadTrustProvider, ReadTrustProvider, TrustSource,
};
pub use tn::{
    ConfigView, EmitReceipt, LogLevel, ReadOptions, ReadPolicyOptions, ReadReport, SealedObject,
    Tn, TnInitOptions, TnProfile, TnProjectOptions,
};
#[cfg(feature = "http")]
pub use tn::{TnProjectVaultClaim, TnProjectVaultClaimOptions};
pub use tn_core::runtime::{CursorKind, ReadCursorV1, SourceCursorV1, VerifyMode};
pub use tn_core::{
    RecipientEntry, SealOptions, SealedGroupInfo, SealedValid, UnsealOptions, UnsealOutcome,
};
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
pub use vault::{
    VaultAccountInboxItem, VaultDeviceIdentity, VaultFile, VaultHttpConnectOptions,
    VaultHttpProjectClient, VaultHttpProjectClientOptions, VaultIdentity, VaultInboxSnapshot,
    VaultInitUploadOptions, VaultInitUploadResult, VaultPushBodyOptions, VaultPushBodyResult,
    VaultPushWithAwkOptions, VaultPushWithAwkResult, VaultPushWithCachedAwkOptions,
    VaultPushWithPassphraseOptions, VaultRestoreAndInstallWithAwkResult,
    VaultRestoreWithAwkOptions, VaultRestoreWithAwkResult, VaultRestoreWithCachedAwkOptions,
    VaultRestoreWithPassphraseOptions,
};
pub use wallet::{
    inbox_dir, is_account_bound as wallet_is_account_bound, safe_path_segment, stem_dir,
    sync_state_path as wallet_sync_state_path, wallet_paths, Wallet, WalletPaths,
    WalletPullAbsorbResult, WalletStageInboxOptions, WalletStageInboxResult, WalletSyncOptions,
    WalletSyncResult,
};
#[cfg(feature = "http")]
pub use wallet::{WalletPublishGroupKeysOptions, WalletPublishGroupKeysResult};
#[cfg(feature = "watch")]
pub use watch::{NativeWatch, NativeWatchOptions};
pub use watch::{PollingWatch, PollingWatchOptions, Watch, WatchIter, WatchOptions, WatchStart};

/// Common imports for applications that want a compact `use` line.
pub mod prelude {
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
    pub use crate::{NativeWatch, NativeWatchOptions};
}
