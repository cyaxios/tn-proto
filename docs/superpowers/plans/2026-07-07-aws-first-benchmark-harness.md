# AWS-First Benchmark Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` if splitting this work across workers. If executing inline, use `superpowers:executing-plans` and keep every step verification-gated.

**Goal:** Build the benchmark harness needed by `C:\codex\tn\tn-paper\bench-plan.md`: local smoke first, then AWS smoke using S3 for source and artifact handoff, then AWS small-machine and paper profiles. Vercel is deferred until AWS is smooth.

**Current Active Checkout:** `C:\codex\tn\tn_proto` on `main` at `024aad4` before this plan. Prior planning commits exist in `C:\codex\tn\tn_proto_archive`; do not treat that archive as the active source of truth.

**Architecture:** Add a TypeScript benchmark package under `tools/bench_artifact/`. Runners write to `artifacts/bench-artifact-<revision>-<date>/` locally first, then sync completed artifacts to S3 with AWS CLI. Windows `rclone mount` is only an inspection convenience. EC2 Ubuntu runners use Mountpoint for Amazon S3 only after local disk writes are complete.

**Tech Stack:** Node 22, TypeScript, Node built-in test runner, `tsx`, existing `ts-sdk` `NodeRuntime`, PowerShell scripts on Windows, Bash scripts on Ubuntu 24.04 EC2, AWS CLI v2, `rclone` + WinFsp on Windows, Mountpoint for Amazon S3 on Linux.

**Machine State After Restart:**
- Windows Git works.
- WSL Git works.
- Windows AWS CLI can call STS and S3.
- Windows `rclone` and WinFsp are available.
- WSL does not currently have `aws`, `rclone`, `mount-s3`, or `s3fs`.
- C: has about 41 GB free, so local artifacts must stay small by default and be ignored.
- Windows Node process count is much lower after restart; smoke commands must not leave watchers running.

**Rules:**
- The active local branch is the source of truth for AWS. Upload a Git bundle from this checkout; do not assume the branch exists remotely.
- Run `local-smoke` before any AWS work.
- Run `aws-smoke` before `aws-small`.
- Run `aws-paper` only after reviewing `aws-small` artifacts.
- Do not copy smoke values into paper `[MEASURE:*]` slots.
- Store raw operation NDJSON as the artifact of record; stats are reproducible derivations.
- Treat missing `TN_BENCH_S3_URI` as the only expected blocker before AWS smoke.

## File Structure

Create:

```text
tools/bench_artifact/
  package.json
  tsconfig.json
  README.md
  src/aws/s3.ts
  src/cli/run.ts
  src/core/artifact.ts
  src/core/cells.ts
  src/core/profile.ts
  src/core/stats.ts
  src/core/types.ts
  src/runner/baseline.ts
  src/runner/node-runtime.ts
  test/artifact.test.ts
  test/profile.test.ts
  test/s3.test.ts
  test/stats.test.ts
  aws/prepare-s3.ps1
  aws/prepare-source.ps1
  aws/bootstrap-ec2.sh
  aws/run-aws-smoke.sh
  aws/run-aws-paper.sh
```

Modify:

```text
.gitignore
```

## Task 1: Scaffold Package and Profiles

Create `tools/bench_artifact/package.json`:

```json
{
  "name": "@tn-proto/bench-artifact",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "node --import tsx --test \"test/**/*.test.ts\"",
    "typecheck": "tsc --noEmit -p tsconfig.json",
    "run": "node --import tsx src/cli/run.ts",
    "smoke:local": "node --import tsx src/cli/run.ts --profile local-smoke",
    "smoke:aws": "node --import tsx src/cli/run.ts --profile aws-smoke",
    "run:aws-small": "node --import tsx src/cli/run.ts --profile aws-small",
    "run:aws-paper": "node --import tsx src/cli/run.ts --profile aws-paper"
  },
  "dependencies": {
    "@cyaxios/tn-proto": "file:../../ts-sdk"
  },
  "devDependencies": {
    "@types/node": "^22.13.0",
    "tsx": "^4.22.4",
    "typescript": "^5.6.0"
  },
  "engines": {
    "node": ">=22"
  }
}
```

Create `tools/bench_artifact/tsconfig.json` with strict NodeNext settings and no `rootDir`, so TypeScript can resolve the local SDK package cleanly after `ts-sdk` is built.

Create `src/core/types.ts`:

```typescript
export type BenchProfileName = "local-smoke" | "aws-smoke" | "aws-small" | "aws-paper";
export type BenchCipherName = "plain" | "signchain" | "btn" | "jwe" | "hibe";
export type BenchOp = "emit" | "read";
export type BenchStatus = "ok" | "skipped" | "failed";

export interface BenchCell {
  readonly id: string;
  readonly cipher: BenchCipherName;
  readonly recipients: number;
  readonly payloadBytes: number;
  readonly revocation: "none" | "dispersed" | "clustered";
  readonly operations: number;
  readonly trials: number;
  readonly warmupTrials: number;
}

export interface BenchProfile {
  readonly name: BenchProfileName;
  readonly description: string;
  readonly cells: readonly BenchCell[];
}

export interface OperationRecord {
  readonly cell: string;
  readonly op: BenchOp;
  readonly trial: number;
  readonly i: number;
  readonly lat_ns: number;
  readonly wire_bytes: number;
  readonly ok: boolean;
  readonly note?: string;
}

export interface CellResult {
  readonly cell: string;
  readonly status: BenchStatus;
  readonly records: readonly OperationRecord[];
  readonly note?: string;
}
```

Create `src/core/profile.ts`:

```typescript
import type { BenchCell, BenchProfile, BenchProfileName } from "./types.js";

const localSmokeCells: readonly BenchCell[] = [
  { id: "plain.p1k", cipher: "plain", recipients: 1, payloadBytes: 1024, revocation: "none", operations: 3, trials: 1, warmupTrials: 0 },
  { id: "signchain.p1k", cipher: "signchain", recipients: 1, payloadBytes: 1024, revocation: "none", operations: 3, trials: 1, warmupTrials: 0 },
  { id: "btn.r1.p1k.none", cipher: "btn", recipients: 1, payloadBytes: 1024, revocation: "none", operations: 3, trials: 1, warmupTrials: 0 },
  { id: "jwe.r1.p1k.none", cipher: "jwe", recipients: 1, payloadBytes: 1024, revocation: "none", operations: 3, trials: 1, warmupTrials: 0 },
  { id: "hibe.r1.p1k.none", cipher: "hibe", recipients: 1, payloadBytes: 1024, revocation: "none", operations: 3, trials: 1, warmupTrials: 0 }
];

const awsSmallCells: readonly BenchCell[] = [
  ...localSmokeCells,
  { id: "btn.r4.p4k.none", cipher: "btn", recipients: 4, payloadBytes: 4096, revocation: "none", operations: 100, trials: 3, warmupTrials: 1 },
  { id: "jwe.r4.p4k.none", cipher: "jwe", recipients: 4, payloadBytes: 4096, revocation: "none", operations: 100, trials: 3, warmupTrials: 1 },
  { id: "hibe.r4.p4k.none", cipher: "hibe", recipients: 4, payloadBytes: 4096, revocation: "none", operations: 100, trials: 3, warmupTrials: 1 }
];

export function getBenchProfile(name: BenchProfileName): BenchProfile {
  if (name === "local-smoke") return { name, description: "Cheap local wiring smoke.", cells: localSmokeCells };
  if (name === "aws-smoke") return { name, description: "Cheap EC2 smoke with S3 artifact sync.", cells: localSmokeCells };
  if (name === "aws-small") return { name, description: "Small EC2 rehearsal before paper scale.", cells: awsSmallCells };
  return { name, description: "Paper-shaped EC2 profile from tn-paper/bench-plan.md.", cells: expandPaperCells() };
}

function expandPaperCells(): readonly BenchCell[] {
  const cells: BenchCell[] = [];
  for (const payloadBytes of [1024, 4096, 32768]) {
    cells.push({ id: `plain.p${payloadBytes / 1024}k`, cipher: "plain", recipients: 1, payloadBytes, revocation: "none", operations: 1000, trials: 30, warmupTrials: 1 });
    cells.push({ id: `signchain.p${payloadBytes / 1024}k`, cipher: "signchain", recipients: 1, payloadBytes, revocation: "none", operations: 1000, trials: 30, warmupTrials: 1 });
    for (const recipients of [1, 4, 8, 32]) {
      for (const revocation of ["none", "dispersed", "clustered"] as const) {
        cells.push({ id: `btn.r${recipients}.p${payloadBytes / 1024}k.${revocation}`, cipher: "btn", recipients, payloadBytes, revocation, operations: 1000, trials: 30, warmupTrials: 1 });
      }
      cells.push({ id: `jwe.r${recipients}.p${payloadBytes / 1024}k.none`, cipher: "jwe", recipients, payloadBytes, revocation: "none", operations: 1000, trials: 30, warmupTrials: 1 });
      cells.push({ id: `hibe.r${recipients}.p${payloadBytes / 1024}k.none`, cipher: "hibe", recipients, payloadBytes, revocation: "none", operations: 1000, trials: 30, warmupTrials: 1 });
    }
  }
  return cells;
}
```

Add profile tests that assert:

```text
local-smoke contains plain, signchain, btn, jwe, hibe
local-smoke has at most 3 operations per cell
aws-paper has exactly 66 cells
aws-paper btn cell count is 36
aws-paper jwe cell count is 12
aws-paper hibe cell count is 12
aws-paper baseline cell count is 6
```

Update `.gitignore`:

```gitignore
/tools/bench_artifact/node_modules/
/tools/bench_artifact/dist/
/artifacts/bench-artifact-*/
/artifacts/source/
```

Verify:

```powershell
npm --prefix ts-sdk install
npm --prefix ts-sdk run build
npm --prefix tools/bench_artifact install
npm --prefix tools/bench_artifact run typecheck
npm --prefix tools/bench_artifact test
```

Commit:

```powershell
git add .gitignore tools/bench_artifact
git commit -m "Scaffold benchmark artifact harness"
```

## Task 2: Artifact Layout and Stats

Create `src/core/artifact.ts` with:
- `artifactRoot(baseDir, revision, date)` returning `bench-artifact-<revision>-<yyyy-mm-dd>`.
- `createArtifactLayout(root)` creating `raw/`, `stats/`, `logs/`, and `scripts/`.
- `appendNdjson(filePath, rows)` appending newline-delimited JSON.
- `writeManifest(layout, profile, revision, results)` writing `schema: "tn-bench-artifact/v1"`.
- `writeEnvDescriptor(layout)` recording Node version, platform, architecture, Git revision, Git branch, Windows/EC2 marker, and command line.

Create `src/core/stats.ts` with nearest-rank `p50`, `p95`, `p99`, `min`, `max`, `count`, and failure count grouped by `cell` and `op`.

Tests:
- `artifactRoot("artifacts", "024aad4", 2026-07-07)` ends in `bench-artifact-024aad4-2026-07-07`.
- `appendNdjson` appends two valid JSON rows.
- `writeManifest` includes `tn-bench-artifact/v1`.
- Stats for `[1, 3, 7, 10]` produce `p50=3`, `p95=10`, `p99=10`.

Verify:

```powershell
npm --prefix tools/bench_artifact run typecheck
npm --prefix tools/bench_artifact test
```

Commit:

```powershell
git add tools/bench_artifact/src/core/artifact.ts tools/bench_artifact/src/core/stats.ts tools/bench_artifact/test/artifact.test.ts tools/bench_artifact/test/stats.test.ts
git commit -m "Add benchmark artifact layout and stats"
```

## Task 3: Local Smoke Runner

Create `src/core/cells.ts`:

```typescript
import type { BenchCell } from "./types.js";

export function payloadForCell(cell: BenchCell, trial: number, i: number): Record<string, unknown> {
  const prefix = `${cell.id}:${trial}:${i}:`;
  return { payload: prefix + "x".repeat(Math.max(0, cell.payloadBytes - prefix.length)) };
}
```

Create `src/runner/baseline.ts`:
- `plain`: canonical JSON append to a temp NDJSON file.
- `signchain`: use `DeviceKey`, `ZERO_HASH`, `rowHash`, `signatureB64`, and `buildEnvelopeLine` exported by `@cyaxios/tn-proto`.
- Record `wire_bytes` as `Buffer.byteLength(line)`.
- Measure each operation with `process.hrtime.bigint()`.

Create `src/runner/node-runtime.ts`:
- For `btn`, `hibe`, and `jwe`, call `NodeRuntime.init(yamlPath, { cipher: cell.cipher })`.
- For every cipher, emit with `runtime.info(eventType, payload)` and read with
  `runtime.read()` so the benchmark measures the same application surface.
- Emit records first, then time a full verified read pass over the same log.
- Record `wire_bytes` from the emitted log line length.
- Close the runtime in `finally`.

Create `src/cli/run.ts`:
- Parse `--profile`, default `local-smoke`.
- Parse `--out`, default `artifacts`.
- Refuse `aws-paper` unless `--confirm-paper RUN_AWS_PAPER` is present.
- Build artifact layout.
- Run every cell.
- Write `raw/<cell>.ndjson`, `raw/env.json`, `stats/summary.ndjson`, and `manifest.json`.
- Exit nonzero if any cell status is `failed`.

Verify local smoke:

```powershell
npm --prefix ts-sdk install
npm --prefix ts-sdk run build
npm --prefix tools/bench_artifact install
npm --prefix tools/bench_artifact run typecheck
npm --prefix tools/bench_artifact test
npm --prefix tools/bench_artifact run smoke:local
```

Expected files:

```text
artifacts/bench-artifact-<revision>-<date>/manifest.json
artifacts/bench-artifact-<revision>-<date>/raw/env.json
artifacts/bench-artifact-<revision>-<date>/raw/plain.p1k.ndjson
artifacts/bench-artifact-<revision>-<date>/raw/signchain.p1k.ndjson
artifacts/bench-artifact-<revision>-<date>/raw/btn.r1.p1k.none.ndjson
artifacts/bench-artifact-<revision>-<date>/raw/jwe.r1.p1k.none.ndjson
artifacts/bench-artifact-<revision>-<date>/raw/hibe.r1.p1k.none.ndjson
artifacts/bench-artifact-<revision>-<date>/stats/summary.ndjson
```

Commit:

```powershell
git add tools/bench_artifact/src/core/cells.ts tools/bench_artifact/src/runner tools/bench_artifact/src/cli tools/bench_artifact/README.md
git commit -m "Add local benchmark smoke runner"
```

## Task 4: S3 Prep and Source Bundle

Create `src/aws/s3.ts` with `parseS3Uri(uri)` and `joinS3Uri(base, child)`. Tests cover valid `s3://tn-bench-artifacts/dev`, invalid HTTPS input, and slash normalization.

Create `aws/prepare-s3.ps1`:
- Required parameter: `-S3Uri`.
- Default region: `us-east-1`.
- Validate `aws sts get-caller-identity`.
- Validate bucket with `aws s3api head-bucket`.
- If `-CreateBucket` is passed and head-bucket fails, create the bucket.
- Upload and list `probe/windows-probe.txt`.
- If `-Mount` is passed, create or update an `rclone` remote named `tn-bench-s3`, start `rclone mount`, print PID, mount path, and stop command.

Create `aws/prepare-source.ps1`:
- Required parameter: `-S3Uri`.
- Refuse dirty working tree unless `-AllowDirty` is passed.
- Create `artifacts/source/tn-proto-<revision>.bundle` with `git bundle create`.
- Upload bundle and source manifest to `$TN_BENCH_S3_URI/source/<revision>/`.
- Print `source bundle uploaded:` followed by the exact S3 URI and `revision=` followed by the exact Git revision.

Verify:

```powershell
npm --prefix tools/bench_artifact run typecheck
npm --prefix tools/bench_artifact test
powershell -NoProfile -ExecutionPolicy Bypass -File tools/bench_artifact/aws/prepare-s3.ps1 -S3Uri $env:TN_BENCH_S3_URI
powershell -NoProfile -ExecutionPolicy Bypass -File tools/bench_artifact/aws/prepare-source.ps1 -S3Uri $env:TN_BENCH_S3_URI
```

If `TN_BENCH_S3_URI` is empty, stop before the two PowerShell script executions and report that exact blocker.

Commit:

```powershell
git add tools/bench_artifact/src/aws tools/bench_artifact/test/s3.test.ts tools/bench_artifact/aws/prepare-s3.ps1 tools/bench_artifact/aws/prepare-source.ps1
git commit -m "Add S3 preparation for benchmark artifacts"
```

## Task 5: EC2 Bootstrap and AWS Runners

Create `aws/bootstrap-ec2.sh`:
- Arguments: source bundle URI and work directory.
- Install build essentials, Git, Node 22, Rust stable, AWS CLI v2, and Mountpoint for Amazon S3.
- Download the source bundle from S3.
- Clone it into `/opt/tn-bench/tn_proto`.
- Run `npm --prefix ts-sdk install`, `npm --prefix ts-sdk run build`, and `npm --prefix tools/bench_artifact install`.
- Print Node, npm, rustc, cargo, aws, mount-s3, and Git revision versions.

Create `aws/run-aws-smoke.sh`:
- Arguments: repo directory and S3 artifact URI.
- Run typecheck, tests, and `npm --prefix tools/bench_artifact run smoke:aws`.
- Sync latest `artifacts/bench-artifact-*` to the S3 artifact URI.
- Print the exact synced artifact URI.

Create `aws/run-aws-paper.sh`:
- Arguments: repo directory, S3 artifact URI, confirmation token.
- Refuse unless the third argument is `RUN_AWS_PAPER`.
- Run `aws-paper`.
- Sync latest artifact to S3.

Verify scripts locally without launching EC2:

```powershell
bash -n tools/bench_artifact/aws/bootstrap-ec2.sh
bash -n tools/bench_artifact/aws/run-aws-smoke.sh
bash -n tools/bench_artifact/aws/run-aws-paper.sh
```

Commit:

```powershell
git add tools/bench_artifact/aws/bootstrap-ec2.sh tools/bench_artifact/aws/run-aws-smoke.sh tools/bench_artifact/aws/run-aws-paper.sh
git commit -m "Add EC2 benchmark runners"
```

## Task 6: Execution Order

Local:

```powershell
git status --short
npm --prefix ts-sdk install
npm --prefix ts-sdk run build
npm --prefix tools/bench_artifact install
npm --prefix tools/bench_artifact run smoke:local
```

S3:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/bench_artifact/aws/prepare-s3.ps1 -S3Uri $env:TN_BENCH_S3_URI
powershell -NoProfile -ExecutionPolicy Bypass -File tools/bench_artifact/aws/prepare-source.ps1 -S3Uri $env:TN_BENCH_S3_URI
```

EC2:

```bash
test -n "${SOURCE_BUNDLE_URI:?set SOURCE_BUNDLE_URI to the source bundle URI printed by prepare-source.ps1}"
test -n "${TN_BENCH_ARTIFACT_URI:?set TN_BENCH_ARTIFACT_URI to the selected S3 artifact destination}"
/opt/tn-bench/tn_proto/tools/bench_artifact/aws/bootstrap-ec2.sh "$SOURCE_BUNDLE_URI" /opt/tn-bench
/opt/tn-bench/tn_proto/tools/bench_artifact/aws/run-aws-smoke.sh /opt/tn-bench/tn_proto "$TN_BENCH_ARTIFACT_URI"
```

Windows verification after AWS smoke:

```powershell
aws s3 ls "$env:TN_BENCH_S3_URI/artifacts/" --recursive
```

Paper run is allowed only after `aws-small` succeeds and the artifact manifest shows zero failures.

## Final Report Contents

Report:
- Active checkout path and revision.
- Local smoke pass/fail.
- S3 destination or missing `TN_BENCH_S3_URI` blocker.
- Source bundle URI.
- AWS smoke artifact URI.
- Failed or skipped cells.
- Whether `aws-small` is clear to run.
