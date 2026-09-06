#!/usr/bin/env python3
"""全量 O-K 不变量检查: 有 invariants 且有 -ctf DUT 的模块"""

import json
import os
import re
import subprocess
import sys

PF = "/workspace/HTFuzz"
MODS = [
    "aes",
    "ascon",
    "hmac",
    "kmac",
    "rom_ctrl",
    "pattgen",
    "rv_timer",
    "sram_ctrl",
    "aon_timer",
    "clkmgr",
    "rstmgr",
    "alert_handler",
    "gpio",
]

summary = {}
for m in MODS:
    inv = f"{PF}/invariants/{m}.json"
    if not os.path.exists(inv):
        print(f"[{m}] SKIP (no invariants)")
        continue
    args = [
        sys.executable,
        f"{PF}/scripts/ok_invariant.py",
        "check",
        m,
        "--dut-dir",
        f"{PF}/perip/{m}-ctf",
        "--regmap",
        f"{PF}/traces/{m}_regmap.json",
    ]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=240, cwd=PF)
        out = p.stdout + p.stderr
        rc = p.returncode
    except subprocess.TimeoutExpired:
        out, rc = "[TIMEOUT]", -9
    viol = re.findall(r"\[VIOLATION\] (\S+) \((\w+)\): (.+)", out)
    nin = 0
    mm = re.search(r"不变量检查: \S+（(\d+) 条）", out)
    if mm:
        nin = int(mm.group(1))
    summary[m] = {
        "n_inv": nin,
        "n_viol": len(viol),
        "violations": viol,
        "rc": rc,
        "tail": out[-200:] if not viol else "",
    }
    print(
        f"[{m}] inv={nin} VIOLATION={len(viol)}" + ("" if viol else f"  {out[-100:]!r}"), flush=True
    )

with open(f"{PF}/fuzz/ok_check_summary.json", "w") as f:
    json.dump(summary, f, indent=1, ensure_ascii=False)
tv = sum(len(v["violations"]) for v in summary.values())
print(f"\n=== O-K 汇总: {tv} 条 VIOLATION ===")
for m, v in summary.items():
    for sig, rule, desc in v["violations"]:
        print(f"  {m}: [{rule}] {sig} — {desc[:70]}")
