#!/usr/bin/env python3
"""
全模块差分批跑 —— 对每个建成 fresh DUT 的模块执行 diff_replay,
产出 fuzz/diff_<module>.json（triage 自动复用）。

用法（容器内）: batch_diff.py [module ...]
缺省: 全部有 fresh DUT 且有 ctf 的模块
"""

import json
import os
import subprocess
import sys
import time

PF = "/workspace/HTFuzz"


def main():
    mods = sys.argv[1:]
    if not mods:
        mods = sorted(
            d[:-6]
            for d in os.listdir(f"{PF}/perip")
            if d.endswith("-fresh")
            and os.path.isdir(f"{PF}/perip/{d}/obj_so")
            and any(f.endswith(".so") for f in os.listdir(f"{PF}/perip/{d}/obj_so"))
        )
        mods = [m for m in mods if os.path.isdir(f"{PF}/perip/{m}-ctf")]
    results = {}
    for m in mods:
        t0 = time.time()
        p = subprocess.run(
            [sys.executable, f"{PF}/scripts/diff_replay.py", m, "0"],
            capture_output=True,
            text=True,
            timeout=900,
            cwd=PF,
        )
        dt = time.time() - t0
        verdict, n_div, first = "?", 0, None
        jf = f"{PF}/fuzz/diff_{m}.json"
        if os.path.exists(jf):
            try:
                j = json.load(open(jf))
                verdict = j.get("verdict", "?")
                n_div = j.get("n_divergences", 0)
                first = j.get("first_divergence")
            except Exception:
                pass
        results[m] = {
            "verdict": verdict,
            "n_divergences": n_div,
            "elapsed_s": round(dt, 1),
            "rc": p.returncode,
        }
        fd = ""
        if first:
            tgt = first.get("signal") or f"addr={first.get('addr')}"
            fd = f" 首偏离: idx={first['idx']} {tgt}"
        print(f"[{m}] {dt:.0f}s {verdict} (偏离 {n_div} 项){fd}", flush=True)
    div = [m for m, v in results.items() if v["verdict"] == "DIVERGENT"]
    print(f"\n=== 差分汇总: DIVERGENT {len(div)}/{len(results)} → {sorted(div)} ===")
    json.dump(results, open(f"{PF}/fuzz/batch_diff.json", "w"), indent=1)


if __name__ == "__main__":
    main()
