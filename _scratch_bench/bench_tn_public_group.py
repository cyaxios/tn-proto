"""Same TN stage breakdown, but with the test ceremony's default group
flipped to `policy: public`. Shows what the floor looks like when the
btn cipher is bypassed for unrouted fields.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

PY = sys.executable
N = 1000


def run_scenario(label: str, profile: str, public: bool) -> None:
    code = textwrap.dedent(f"""
        import os, tempfile, time, yaml
        os.environ['TN_NO_STDOUT'] = '1'
        os.environ['TN_AUTOINIT_QUIET'] = '1'
        os.environ['TN_PERF_TRACE'] = '1'
        td = tempfile.mkdtemp(); os.chdir(td)
        import tn
        tn.init(profile={profile!r})

        if {public!r}:
            # Patch the on-disk yaml to flip the default group's policy
            # from private to public. The runtime now honors policy=public
            # by routing the group's fields into envelope plaintext
            # instead of running them through the cipher.
            from pathlib import Path
            yaml_path = Path(tn._require_dispatch()._yaml)
            doc = yaml.safe_load(yaml_path.read_text())
            doc['default_policy'] = 'public'
            for g in doc.get('groups', {{}}).values():
                g['policy'] = 'public'
            yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False))
            # Re-init the dispatch runtime so the Rust side picks up the
            # yaml change. flush_and_close drops the old runtime first.
            tn.flush_and_close()
            tn.init(profile={profile!r})

        from tn_core._core import perf_snapshot, perf_reset
        for i in range(50):
            tn.log('warmup', i=i)
        perf_reset()

        t0 = time.perf_counter()
        for i in range({N}):
            tn.log('bench', i=i)
        wall = time.perf_counter() - t0
        tn.flush_and_close()

        snap = sorted(perf_snapshot(), key=lambda r: -r[2])
        total = next((ns for s, _c, ns in snap if s == 'emit:_TOTAL'), 0)
        print(f'--- {label} ---')
        print(f'wall total      : {{wall*1000:8.2f}} ms = {{wall/{N}*1000:7.3f}} ms/emit')
        if total:
            print(f'emit:_TOTAL sum : {{total/1e6:8.2f}} ms = {{total/{N}/1000:7.3f}} us/emit (Rust)')
        print(f'  {{\"stage\":28s}}  {{\"count\":>6s}}  {{\"total_ms\":>10s}}  {{\"avg_us\":>10s}}  {{\"%total\":>7s}}')
        for stage, count, total_ns in snap:
            avg = total_ns/count/1000.0 if count else 0
            pct = 100*total_ns/total if total else 0
            print(f'  {{stage:28s}}  {{count:>6d}}  {{total_ns/1e6:>10.2f}}  {{avg:>10.2f}}  {{pct:>6.1f}}%')
    """)
    proc = subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        print(f"FAILED {label}:\n{proc.stderr}")
        return
    print(proc.stdout)


def main() -> None:
    print(f"# TN stage breakdown — default group policy private vs public (N={N})\n")
    run_scenario("telemetry  default=PRIVATE (cipher on)", "telemetry", public=False)
    run_scenario("telemetry  default=PUBLIC  (cipher off)", "telemetry", public=True)


if __name__ == "__main__":
    main()
