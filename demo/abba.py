"""Compare two builds of examples/rig.rs, interleaved A B B A so drift on a
busy machine hits both alike. Prints per-category speed and every query
whose results differ.

usage: python3 abba.py <rig A> <rig B> <snap dir> <corpus.json> [rounds] [kinds]
"""

import json, math, os, subprocess, sys, tempfile
from collections import defaultdict

a, b, snap, corpus = sys.argv[1:5]
rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 1
kinds = sys.argv[6:7]
samples = {"A": defaultdict(list), "B": defaultdict(list)}
meta, digest = {}, {"A": {}, "B": {}}
with tempfile.TemporaryDirectory() as tmp:
    for r in range(rounds):
        for arm in "ABBA":
            out = os.path.join(tmp, f"{arm}{r}.json")
            subprocess.run([a if arm == "A" else b, "run", snap, corpus, out, *kinds], check=True, stdout=subprocess.DEVNULL)
            for k, v in json.load(open(out)).items():
                if not isinstance(v, dict):
                    continue
                samples[arm][k] += v["ms"]
                meta[k] = (v["kind"], v["cat"])
                digest[arm][k] = v["digest"]


def med(x):
    x = sorted(x)
    return x[len(x) // 2]


cats = defaultdict(list)
for k in meta:
    if samples["A"][k] and samples["B"][k]:
        cats[meta[k]].append((med(samples["A"][k]), med(samples["B"][k])))
print(f"{'kind':7} {'cat':8} {'n':>3}  {'A ms':>8} {'B ms':>8}  {'B/A':>6}")
total = []
for (kind, cat), pairs in sorted(cats.items()):
    ga = math.exp(sum(math.log(max(p[0], 1e-3)) for p in pairs) / len(pairs))
    gb = math.exp(sum(math.log(max(p[1], 1e-3)) for p in pairs) / len(pairs))
    total += [math.log(max(p[1], 1e-3) / max(p[0], 1e-3)) for p in pairs]
    print(f"{kind:7} {cat:8} {len(pairs):3}  {ga:8.3f} {gb:8.3f}  {gb / ga:6.3f}")
print(f"overall geomean B/A {math.exp(sum(total) / len(total)):.3f}")
diff = [k for k in meta if digest["A"].get(k) != digest["B"].get(k)]
print(f"{len(diff)} queries with different results" + "".join(f"\n  {k}" for k in diff[:30]))
