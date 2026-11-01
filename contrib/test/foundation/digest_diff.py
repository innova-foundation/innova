#!/usr/bin/env python3
"""Compare two state-digest JSONL files at common heights. Exit 1 on any difference."""
import json, sys

def load(p):
    out = {}
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                d = json.loads(line)
                out.setdefault(d.get("height"), d)
    return out

def flat(d, pre=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from flat(v, pre + k + ".")
        else:
            yield pre + k, v

a, b = load(sys.argv[1]), load(sys.argv[2])
require_same_heights = len(sys.argv) > 3 and sys.argv[3] == "--strict"
common = sorted(set(a) & set(b))
diffs = []
for h in common:
    fa, fb = dict(flat(a[h])), dict(flat(b[h]))
    for k in sorted(set(fa) | set(fb)):
        if fa.get(k) != fb.get(k):
            diffs.append({"height": h, "field": k, "a": fa.get(k), "b": fb.get(k)})
only = sorted(set(a) ^ set(b))
res = {"common_heights": len(common), "max_common_height": common[-1] if common else None,
       "diff_count": len(diffs), "diffs": diffs[:50],
       "heights_only_in_one": only[:50] if require_same_heights else len(only)}
print(json.dumps(res, indent=1))
sys.exit(1 if diffs or not common or (require_same_heights and only) else 0)
