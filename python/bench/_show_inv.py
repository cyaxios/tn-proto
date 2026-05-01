import glob
import json
import os
import sys

root = sys.argv[1]
for path in sorted(glob.glob(os.path.join(root, "alice_*", "metrics.json"))):
    name = os.path.basename(os.path.dirname(path))
    d = json.load(open(path, encoding="utf-8"))
    inv = d.get("invariants", {})
    print(name + ":")
    if not inv:
        # aggregate from cell files
        cells = sorted(glob.glob(os.path.join(os.path.dirname(path), "metrics.cell_*.json")))
        if cells:
            agg = {}
            for c in cells:
                cd = json.load(open(c, encoding="utf-8"))
                for k, v in cd.get("invariants", {}).items():
                    agg.setdefault(k, []).append(v)
            for k, vs in agg.items():
                ok = all(vs)
                print(f"  [{'PASS' if ok else 'FAIL'}] {k} (cells: {sum(vs)}/{len(vs)})")
        else:
            print("  (no invariants)")
    else:
        for k, v in inv.items():
            print(f"  [{'PASS' if v else 'FAIL'}] {k}")
