"""Python-side stress runner — hammers btn.Runtime for a fixed duration.

Usage:
  python examples/python_stress.py --duration-secs=30

Opens a fresh ceremony, mints some readers, logs a stream of events,
periodically revokes and re-opens, verifies everything reads back.
"""
import argparse
import sys
import tempfile
import time
from pathlib import Path

import tn_btn as btn


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--duration-secs", type=float, default=30.0)
    p.add_argument("--payload-size", type=int, default=256)
    p.add_argument("--readers", type=int, default=10)
    return p.parse_args()


def main():
    args = parse_args()
    print(f"btn python stress")
    print(f"  btn.tree_height: {btn.tree_height()}")
    print(f"  btn.max_leaves:  {btn.max_leaves()}")
    print(f"  duration_secs:   {args.duration_secs}")
    print(f"  payload_size:    {args.payload_size}")
    print(f"  readers:         {args.readers}")
    print("-" * 100)

    payload = b"x" * args.payload_size

    with tempfile.TemporaryDirectory(prefix="btn-stress-") as tmp:
        dir_path = Path(tmp) / "ceremony"
        with btn.init(dir_path) as rt:
            kits = [rt.mint() for _ in range(args.readers)]

            start = time.perf_counter()
            last_report = start
            log_count = 0
            failures = 0
            revoke_count = 0

            # Pick one kit minted before any revokes as our "never-revoked"
            # reader. We verify at the end that it reads back every entry
            # correctly. kits[0] would work too but it gets rotated, so
            # we mint a fresh one dedicated to verification.
            verifier_kit = rt.mint()

            while True:
                now = time.perf_counter()
                if now - start >= args.duration_secs:
                    break

                # Log a batch via the public API.
                for _ in range(100):
                    rt.log(payload)
                    log_count += 1

                # Periodically revoke a reader and mint a replacement
                # (if the tree still has unused leaves). Once exhausted,
                # stop rotating and just keep logging.
                if log_count % 1000 == 0:
                    idx = revoke_count % len(kits)
                    rt.revoke_kit(kits[idx])
                    try:
                        kits[idx] = rt.mint()
                        revoke_count += 1
                    except btn.BtnRuntimeError as e:
                        if "tree exhausted" in str(e):
                            # Quietly stop rotating once we fill the tree.
                            pass
                        else:
                            raise

                if now - last_report >= 5.0:
                    elapsed = now - start
                    rate = log_count / elapsed
                    print(
                        f"[{elapsed:6.1f}s] logs={log_count:>10} ({rate:>7.0f}/s) "
                        f"revokes={revoke_count:>5} failures={failures}"
                    )
                    last_report = now

            # End-of-run verification: read the entire log with
            # verifier_kit (a never-revoked reader) and confirm every
            # entry decrypts to the payload. One O(n) pass, not O(n^2).
            rt.close()  # flush + close log handle before reading
            print("-" * 100)
            print("Verifying log integrity (this may take a few seconds)...")
            verify_start = time.perf_counter()
            decrypt_count = 0
            for _, pt in btn.read(dir_path / "log.btn", verifier_kit):
                decrypt_count += 1
                if pt != payload:
                    failures += 1
            verify_elapsed = time.perf_counter() - verify_start
            print(
                f"  Verified {decrypt_count} entries in {verify_elapsed:.2f}s "
                f"({decrypt_count/verify_elapsed:.0f}/s decrypt rate)"
            )

            elapsed = time.perf_counter() - start
            print("-" * 100)
            print(f"=== Final report ===")
            print(f"  Duration:         {elapsed:.1f} s")
            print(f"  Logs written:     {log_count} ({log_count/elapsed:.0f}/s)")
            print(f"  Decrypts (verify): {decrypt_count}")
            print(f"  Revokes:          {revoke_count}")
            print(f"  Failures:         {failures}")
            if failures == 0:
                print(f"  STATUS:     OK")
                return 0
            else:
                print(f"  STATUS:     FAILURES DETECTED")
                return 1


if __name__ == "__main__":
    sys.exit(main())
