# JWE Documentation Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Normalize repository text around the standard JWE capabilities that ship today.

**Architecture:** Treat RFC 7516 General JSON JWE as a normal TN per-group cipher. Rust owns the normative seal/open primitives and runtime verbs; Wasm exposes those primitives and verbs; TypeScript uses the Rust/Wasm surface; Python and C# describe their actual public surfaces with operation-specific boundaries.

**Tech Stack:** Markdown, Rust/rustdoc, TypeScript test comments, C# test comments, GitHub CLI.

---

### Task 1: Correct active JWE documentation

**Files:**
- Modify: `crypto/tn-wasm/README.md`
- Modify: `docs/JWE-cipher-spec.md`
- Modify: `docs/guide/cookbook-typescript.md`
- Modify: `docs/guide/jwe-hibe-key-ceremonies.md`
- Modify: `docs/guide/jwe-howto.md`

1. State the standard Rust/Wasm-backed JWE behavior and ordinary language surfaces.
2. Preserve concrete API limitations only when scoped to a particular operation.
3. Search these documents for obsolete architecture names and availability language.

### Task 2: Correct source and test commentary

**Files:**
- Modify: `crypto/tn-wasm/src/runtime.rs`
- Modify: `crypto/tn-core/src/runtime/admin.rs`
- Modify: `ts-sdk/test/scenarios/alice/s02_rotate.test.ts`
- Modify: `csharp-sdk/tests/TnProto.Tests/JweSealedGroupCipherTests.cs`

1. Rewrite comments to match implemented Rust/Wasm runtime JWE support.
2. Scope reader-kit transfer and foreign-kit dispatch rules to those operations.
3. Run formatting checks for touched language files.

### Task 3: Normalize historical architecture statements

**Files:**
- Modify: `CHANGELOG.md`
- Modify: relevant tracked files under `docs/superpowers/`

1. Phrase every historical architecture statement as the current standard JWE design.
2. Keep useful decisions phrased as the current standard JWE architecture.
3. Run a repository-wide negative search for every forbidden phrase and manually classify any remaining matches.

### Task 4: Verify and publish

1. Run documentation checks and `git diff --check`.
2. Inspect the complete diff for accidental capability overclaims.
3. Commit and push the cleanup to PR #5.
4. Update the PR description to current status and monitor required CI checks.
