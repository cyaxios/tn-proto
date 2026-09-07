#!/usr/bin/env python3
"""Run the six completed enterprise consumers against this SDK, without editing them.

Requires Python 3.11+, Rust/Cargo, and an already-populated Cargo dependency cache.
All Cargo commands are offline. Only a temporary consumer copy is adapted.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib


PATTERNS = {
    "p01": ("01_modular_monolith", 13),
    "p02": ("02_request_reply", 10),
    "p03": ("03_pubsub", 12),
    "p04": ("04_saga", 16),
    "p05": ("05_outbox", 11),
    "p06": ("06_cqrs", 8),
}
OLD_P05 = '''        let altered = Governance::from_template(security.device.did(), &template)?;
        assert_eq!(altered.policy_ref(), security.policy.policy_ref());
        assert_ne!(altered.fields(), security.policy.fields());
        let envelope = security.seal(&security.device, altered, &sale("sale-forged-rules", 950))?;
        GovernedObject::parse(envelope.wire())?;
        assert!(store
            .receive(
                &security.admission(),
                &security.reader(true)?,
                envelope.wire(),
                OPERATION,
                "none"
            )
            .is_err());
'''
NEW_P05 = '''        // Current SDK rejects a mutated parsed template before it can be sealed.
        assert!(Governance::from_template(security.device.did(), &template).is_err());
'''


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprints(root: Path, files: list[Path]) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): sha256(path) for path in sorted(files)}


def verify_vendor(corpus: Path) -> dict[str, object]:
    manifest_path = corpus / "vendor/SOURCE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    vendor = (corpus / "vendor/tn-proto").resolve()
    for name, expected in manifest["files"].items():
        path = (vendor / name).resolve()
        if vendor not in path.parents or sha256(path) != expected:
            raise ValueError(f"Frozen vendor manifest mismatch: {name}")
    return {"commit": manifest["commit"], "verified_files": len(manifest["files"]),
            "manifest_sha256": sha256(manifest_path)}


def toml_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key} = {toml_value(item)}" for key, item in value.items()) + " }"
    raise ValueError(f"Unsupported dependency TOML value: {type(value).__name__}")


def write_manifest(corpus: Path, sdk: Path, destination: Path) -> None:
    baseline = tomllib.loads((corpus / "Cargo.toml").read_text(encoding="utf-8-sig"))
    dependencies = baseline["dependencies"]
    for name, relative in {
        "tn-core": "crypto/tn-core",
        "tn-proto": "rust-sdk",
        "tn-btn": "crypto/tn-btn",
    }.items():
        dependency = dependencies[name]
        if not isinstance(dependency, dict) or "path" not in dependency:
            raise ValueError(f"Expected the corpus to have a path dependency for {name}")
        dependency["path"] = (sdk / relative).as_posix()
    text = '''[package]
name = "tn-enterprise-patterns"
version = "0.1.0"
edition = "2021"
publish = false
autobins = false
autotests = false

[workspace]

[lib]
name = "tn_pattern_lab"
path = "src/lib.rs"

[dependencies]
'''
    text += "\n".join(f"{name} = {toml_value(value)}" for name, value in dependencies.items()) + "\n"
    for name, (folder, _) in PATTERNS.items():
        text += f'\n[[bin]]\nname = "{name}"\npath = "patterns/{folder}/main.rs"\n'
    text += '\n[[test]]\nname = "fixture_authority"\npath = "tests/fixture_authority.rs"\n'
    destination.write_text(text, encoding="utf-8")


def adapt_p05(copy: Path) -> dict[str, str]:
    path = copy / "patterns/05_outbox/main.rs"
    before = path.read_text(encoding="utf-8-sig")
    function = "fn accepted_policy_reference_does_not_admit_altered_carried_rules()"
    start = before.index(function)
    end = before.index("    #[test]", start)
    if before.count(OLD_P05) != 1 or OLD_P05 not in before[start:end]:
        raise ValueError("P05-C01 source changed: inspect the copied-test adaptation before updating it")
    after = before.replace(OLD_P05, NEW_P05, 1)
    before_hash = sha256(path)
    path.write_text(after, encoding="utf-8", newline="\n")
    patch = "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="corpus/patterns/05_outbox/main.rs",
        tofile="temporary-copy/patterns/05_outbox/main.rs",
    ))
    print("Only copied P05-C01 is adapted; trusted-sale and zero-effect assertions remain:", flush=True)
    print(patch, flush=True)
    return {"complaint": "P05-C01", "before_sha256": before_hash,
            "after_sha256": sha256(path), "patch": patch}


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: int) -> dict[str, object]:
    print("Running " + subprocess.list2cmdline(command), flush=True)
    try:
        process = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                 errors="replace", timeout=timeout, check=False)
        output, returncode = process.stdout, process.returncode
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or b""
        output = partial.decode("utf-8", errors="replace") if isinstance(partial, bytes) else partial
        output += f"\nHarness timed out after {timeout} seconds.\n"
        returncode = 124
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    return {"command": command, "exit_code": returncode, "output": output}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True,
                        help="Path to the existing tn-enterprise-patterns repository")
    parser.add_argument("--sdk", type=Path, default=Path(__file__).resolve().parents[1],
                        help="TN SDK repository root (default: this checkout)")
    parser.add_argument("--target-dir", type=Path,
                        help="Reusable Cargo target directory; defaults to CARGO_TARGET_DIR or a temporary directory")
    parser.add_argument("--report", type=Path, help="Write machine-readable evidence outside the corpus")
    parser.add_argument("--timeout", type=int, default=600, help="Seconds allowed for each Cargo command")
    args = parser.parse_args()
    corpus, sdk = args.corpus.resolve(), args.sdk.resolve()
    report_path = args.report.resolve() if args.report else None
    target = args.target_dir or (Path(os.environ["CARGO_TARGET_DIR"]) if "CARGO_TARGET_DIR" in os.environ else None)
    target = target.resolve() if target else None
    temporary_parent = Path(tempfile.gettempdir()).resolve()
    for output in (report_path, target, temporary_parent):
        if output and (output == corpus or corpus in output.parents):
            parser.error("Report, build output, and system temporary directory must be outside the original corpus/vendor")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    ledger = json.loads((corpus / "LEDGER.json").read_text(encoding="utf-8-sig"))
    complete = {entry["target"] for entry in ledger if entry["status"] == "complete"}
    if complete != set(PATTERNS):
        raise ValueError(f"Expected exactly the six completed consumers; ledger has {sorted(complete)}")
    source_files = list((corpus / "src").rglob("*.rs")) + [corpus / "tests/fixture_authority.rs"]
    complaints = []
    for name, (folder, _) in PATTERNS.items():
        directory = corpus / "patterns" / folder
        source_files.extend(path for path in directory.rglob("*") if path.suffix in (".rs", ".py"))
        complaints.extend(json.loads((directory / "complaints.json").read_text(encoding="utf-8-sig")))
    if len(complaints) != 14 or len({item["id"] for item in complaints}) != 14:
        raise ValueError("Expected the original fourteen distinct complaint entries")
    observed_files = source_files + [corpus / "Cargo.toml", corpus / "Cargo.lock", corpus / "LEDGER.json"]
    observed_files += [corpus / "patterns" / folder / "complaints.json" for folder, _ in PATTERNS.values()]
    before = fingerprints(corpus, observed_files)
    vendor_before = verify_vendor(corpus)
    sdk_files = [sdk / "Cargo.toml"]
    for relative in ("rust-sdk", "crypto/tn-core", "crypto/tn-btn"):
        crate = sdk / relative
        sdk_files.append(crate / "Cargo.toml")
        sdk_files.extend((crate / "src").rglob("*.rs"))
    sdk_before = fingerprints(sdk, sdk_files)
    evidence = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "corpus": str(corpus), "sdk": str(sdk), "python": sys.executable,
                "expected_pattern_tests": 70, "expected_fixture_tests": 2,
                "ledger": [{"target": item["target"], "status": item["status"]} for item in ledger],
                "complaints": complaints, "corpus_source_sha256": before,
                "sdk_source_sha256": sdk_before, "frozen_vendor": vendor_before, "runs": []}
    success = False
    try:
        with tempfile.TemporaryDirectory(prefix="tn-enterprise-sdk-") as temporary:
            copy = Path(temporary)
            print(f"Temporary consumer: {copy}\nSDK: {sdk}\nCorpus: {corpus}", flush=True)
            for source in source_files:
                destination = copy / source.relative_to(corpus)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            shutil.copyfile(corpus / "Cargo.lock", copy / "Cargo.lock")
            write_manifest(corpus, sdk, copy / "Cargo.toml")
            evidence["manifest"] = (copy / "Cargo.toml").read_text(encoding="utf-8")
            evidence["adaptation"] = adapt_p05(copy)
            env = os.environ.copy()
            env.update({"CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never",
                        "CARGO_TARGET_DIR": str(target or (copy / "target")),
                        "TN_PATTERN_PYTHON": sys.executable})
            evidence["target_dir"] = env["CARGO_TARGET_DIR"]
            for command in (["cargo", "--version"], ["rustc", "--version"]):
                version = run(command, copy, env, args.timeout)
                evidence["runs"].append(version)
                if version["exit_code"] != 0:
                    return 1
            # Preserve locked registry versions while refreshing local workspace
            # dependency records for the SDK checkout. The baseline lock is read-only.
            lock = run(["cargo", "update", "--offline", "--workspace"], copy, env, args.timeout)
            evidence["runs"].append(lock)
            if lock["exit_code"] != 0:
                return 1
            evidence["effective_lock_sha256"] = sha256(copy / "Cargo.lock")
            evidence["effective_lock"] = (copy / "Cargo.lock").read_text(encoding="utf-8")
            success = True
            for name, (_, expected) in [*PATTERNS.items(), ("fixture_authority", ("", 2))]:
                selector = "--test" if name == "fixture_authority" else "--bin"
                result = run(["cargo", "test", "--offline", "--locked", selector, name], copy, env, args.timeout)
                summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", str(result["output"]))
                result.update({"target": name, "expected_passed": expected})
                result["verified_count"] = summaries == [(str(expected), "0", "0", "0", "0")]
                evidence["runs"].append(result)
                success &= result["exit_code"] == 0 and result["verified_count"]
            print("Verified 70 pattern tests and 2 fixture tests." if success else
                  "Consumer regression failed; inspect the output and evidence counts.", flush=True)
    finally:
        evidence["corpus_inputs_unchanged"] = fingerprints(corpus, observed_files) == before
        sdk_after = fingerprints(sdk, sdk_files)
        evidence["sdk_inputs_unchanged"] = sdk_after == sdk_before
        evidence["sdk_changed_files"] = [name for name in sdk_before if sdk_after.get(name) != sdk_before[name]]
        try:
            evidence["frozen_vendor_unchanged"] = verify_vendor(corpus) == vendor_before
        except (OSError, ValueError, KeyError) as error:
            evidence["frozen_vendor_unchanged"] = False
            evidence["frozen_vendor_error"] = str(error)
        evidence["test_counts_passed"] = bool(success)
        success &= evidence["corpus_inputs_unchanged"] and evidence["sdk_inputs_unchanged"] and evidence["frozen_vendor_unchanged"]
        evidence["success"] = bool(success)
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            print(f"Evidence: {report_path}", flush=True)
        if not evidence["corpus_inputs_unchanged"]:
            print("Original corpus inputs changed during the run; refusing a clean result.", file=sys.stderr)
        if not evidence["sdk_inputs_unchanged"]:
            print("SDK sources changed during the run; rerun against a stable checkout.", file=sys.stderr)
        if not evidence["frozen_vendor_unchanged"]:
            print("Frozen vendor verification changed during the run; refusing a clean result.", file=sys.stderr)
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"Enterprise regression setup failed: {error}", file=sys.stderr)
        sys.exit(1)
