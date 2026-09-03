#!/usr/bin/env python3
"""全量检出扫描: per-IP DUT × O-A~G oracle 盲测引擎"""
import json, os, re, subprocess, sys, time

PF = "/workspace/HTFuzz"
DUTS = ["aes", "ascon", "hmac", "kmac", "keymgr", "lc-ctf", "rom_ctrl",
        "ibex", "uart", "prim", "pattgen", "rv_timer", "spi_host",
        "sram_ctrl", "aon_timer", "clkmgr", "csrng", "entropy_src",
        "alert_handler", "pwrmgr", "rstmgr", "rv_dm"]

results = {}
for d in DUTS:
    module = "lc_ctrl" if d == "lc-ctf" else d
    dut_dir = f"{PF}/perip/{d}-ctf"
    if not os.path.isdir(dut_dir) or not os.path.isdir(f"{dut_dir}/obj_so"):
        print(f"[{module}] SKIP (no obj_so)", flush=True)
        continue
    regmap = f"{PF}/traces/{module}_regmap.json"
    args = [sys.executable, f"{PF}/scripts/discover_engine.py", dut_dir, module]
    if os.path.exists(regmap):
        args.append(regmap)
    t0 = time.time()
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=150, cwd=PF)
        out = p.stdout + p.stderr
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        so = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        se = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        out = so + se + "\n[TIMEOUT]"
        rc = -9
    dt = time.time() - t0
    # 直接读引擎落盘 JSON（stdout 只打印前 10 条，会丢后面的 oracle）
    jf = f"{PF}/fuzz/discover_{module}.json"
    findings = []
    if os.path.exists(jf):
        try:
            for f in json.load(open(jf)).get("findings", []):
                findings.append((f.get("oracle", "?"), f.get("signal", "?"),
                                 f.get("desc", "")))
        except Exception:
            pass
    uniq, seen = [], set()
    for o, sig, desc in findings:
        key = (o, sig, desc[:60])
        if key not in seen:
            seen.add(key)
            uniq.append({"oracle": o, "signal": sig, "desc": desc})
    results[module] = {"elapsed_s": round(dt, 1), "rc": rc,
                       "raw": len(findings), "findings": uniq,
                       "err_head": out[:200] if not findings else ""}
    print(f"[{module}] {dt:.0f}s rc={rc} raw={len(findings)} uniq={len(uniq)}"
          + ("" if findings else f"  ERR: {out[:120]!r}"), flush=True)

with open(f"{PF}/fuzz/full_sweep.json", "w") as f:
    json.dump(results, f, indent=1, ensure_ascii=False)

n = sum(v["findings"] and len(v["findings"]) or 0 for v in results.values())
mods = {k: v["findings"] for k, v in results.items() if v["findings"]}
print(f"\n=== 全量汇总: {n} 条唯一发现, 覆盖 {len(mods)} 个模块 ===")
for k in sorted(mods, key=lambda x: -len(mods[x])):
    print(f"  {k}: {len(mods[k])}")
