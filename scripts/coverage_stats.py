#!/usr/bin/env python3
"""
HTFuzz 覆盖率统计 — regmap 覆盖（寄存器/字段触达分析）
==========================================================
从 fuzz 运行的 TL-UL trace 统计:
  1. 寄存器覆盖: 哪些寄存器被读/写
  2. 字段覆盖: CFG/CMD 等控制寄存器的哪些字段被赋过非零值
  3. 访问方向覆盖: R/W/越界
  4. oracle 覆盖: O1-O4 各触发次数
"""

import json
import re
import sys
from pathlib import Path

HMAC_BASE = 0x41110000
LOG_DIR = Path("/workspace/HTFuzz/fuzz/logs")
RUNFILES_ROOT = Path("/root/.cache/bazel/_bazel_root/03a1af92d3fbbb38fde0b168dde284dc/execroot/_main/bazel-out")


def find_traces():
    """找所有 pickerfuzz runfiles 下的 tlul_trace.log"""
    traces = {}
    for rf in RUNFILES_ROOT.glob("k8-fastbuild-*/bin/sw/device/tests/pickerfuzz_tests/*_sim_verilator.bash.runfiles"):
        name = rf.name.replace("_sim_verilator.bash.runfiles", "")
        t = rf / "_main" / "tlul_trace.log"
        if t.exists():
            traces[name] = t
    return traces


def load_regmap():
    return json.load(open("/workspace/HTFuzz/traces/hmac_regmap.json"))


def build_field_map(regmap):
    """offset → [(field_name, hi, lo)]"""
    fm = {}
    for e in regmap:
        if e["kind"] == "reg":
            flds = []
            for f in e.get("fields", []):
                bits = f["bits"]
                if ":" in bits:
                    hi, lo = map(int, bits.split(":"))
                else:
                    hi = lo = int(bits)
                flds.append((f["name"], hi, lo))
            fm[e["offset"]] = flds
    return fm


def analyze():
    regmap = load_regmap()
    field_map = build_field_map(regmap)
    traces = find_traces()

    reg_rw = {}       # name → {"R": n, "W": n}
    field_hit = {}    # "CFG.sha_en" → set of values
    oob_hits = []     # 越界地址
    oracle_hits = {"O1": 0, "O2": 0, "O3": 0, "O4": 0}
    total_txns = 0

    for name, tpath in sorted(traces.items()):
        pending = None
        for line in open(tpath):
            ma = re.match(r"\[TLUL\] (\d+) A op=(\d) addr=([0-9a-f]+) data=([0-9a-f]+)", line)
            if ma:
                if pending:
                    total_txns += 1
                op = int(ma.group(2))
                addr = int(ma.group(3), 16)
                data = int(ma.group(4), 16)
                off = addr - HMAC_BASE
                if not (0 <= off < 0x2000):
                    oob_hits.append((name, addr))
                    pending = None
                    continue
                # 寄存器名
                rname = None
                for e in regmap:
                    if e["kind"] == "reg" and e["offset"] == off:
                        rname = e["name"]
                    elif e["kind"] == "multireg" and e["offset"] <= off < e["offset"] + e["count"] * e["stride"]:
                        rname = "%s[%d]" % (e["name"], (off - e["offset"]) // e["stride"])
                    elif e["kind"] == "window" and e["offset"] <= off < e["offset"] + e.get("items", 0) * 4:
                        rname = e["name"]
                rname = rname or "UNK_0x%03x" % off
                d = reg_rw.setdefault(rname, {"R": 0, "W": 0})
                d["W" if op in (0, 1) else "R"] += 1
                # 字段覆盖
                if op in (0, 1) and off in field_map:
                    for fname, hi, lo in field_map[off]:
                        val = (data >> lo) & ((1 << (hi - lo + 1)) - 1)
                        if val:
                            field_hit.setdefault("%s.%s" % (rname, fname), set()).add(val)
                pending = True
                continue
            md = re.match(r"\[TLUL\] (\d+) D op=(\d) data=([0-9a-f]+)", line)
            if md and pending:
                total_txns += 1
                pending = None

    # oracle 命中（从 UART 日志）
    for ulog in LOG_DIR.glob("*_sim.log"):
        pass
    # UART 在 runfiles 里，改从 summary + sim log 找
    for name in traces:
        uart = traces[name].parent / "uart0.log"
        if uart.exists():
            txt = uart.read_text(errors="ignore")
            for k in oracle_hits:
                oracle_hits[k] += len(re.findall(r"\[%s\]" % k, txt))

    # 输出报告
    print("=" * 64)
    print("HTFuzz 覆盖率报告 (HMAC @ 0x41110000)")
    print("=" * 64)
    print()
    n_traces = len(traces)
    print("仿真运行数: %d   TL-UL 事务总数: %d" % (n_traces, total_txns))
    print()
    print("--- 寄存器访问覆盖 (R/W) ---")
    total_regs = sum(1 for e in regmap if e["kind"] == "reg") + \
                 sum(e["count"] for e in regmap if e["kind"] == "multireg") + \
                 sum(1 for e in regmap if e["kind"] == "window")
    hit_regs = len(reg_rw)
    print("触达 %d / %d 个寄存器位置 (%.0f%%)" % (hit_regs, total_regs, 100.0 * hit_regs / total_regs))
    for name in sorted(reg_rw, key=lambda n: regmap_order(regmap, n)):
        d = reg_rw[name]
        print("  %-18s R=%-4d W=%-4d" % (name, d["R"], d["W"]))
    print()
    print("--- 控制字段覆盖 (非零写入值) ---")
    for fname in sorted(field_hit):
        vals = sorted(field_hit[fname])
        show = ",".join("0x%x" % v for v in vals[:6])
        if len(vals) > 6:
            show += ",..."
        print("  %-24s %d 值: %s" % (fname, len(vals), show))
    print()
    print("--- 越界访问 (被硬件拦截) ---")
    for name, addr in oob_hits:
        print("  %s @ 0x%08x" % (name, addr))
    if not oob_hits:
        print("  (无)")
    print()
    print("--- Oracle 触发统计 ---")
    for k, v in oracle_hits.items():
        print("  %s: %d" % (k, v))
    print()

    # 保存 JSON
    out = {
        "runs": n_traces, "txns": total_txns,
        "reg_coverage": {"hit": hit_regs, "total": total_regs,
                         "pct": round(100.0 * hit_regs / total_regs, 1)},
        "regs": {k: v for k, v in reg_rw.items()},
        "fields": {k: sorted(v) for k, v in field_hit.items()},
        "oob": [{"run": n, "addr": "0x%08x" % a} for n, a in oob_hits],
        "oracles": oracle_hits,
    }
    outp = Path("/workspace/HTFuzz/fuzz/coverage.json")
    outp.write_text(json.dumps(out, indent=1))
    print("详细数据: %s" % outp)


def regmap_order(regmap, name):
    for i, e in enumerate(regmap):
        base = e["name"]
        if name == base or name.startswith(base + "["):
            return e["offset"]
    return 0xFFFF


if __name__ == "__main__":
    analyze()
