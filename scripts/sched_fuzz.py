#!/usr/bin/env python3
"""
HTFuzz M9: 语料库调度（seed trace 片段 + 覆盖率反馈）
========================================================
计划书 M9:
  - 语料库: 从 seed trace 解析片段（poll 压缩）+ hjson 合法序列
  - 调度: 产生新覆盖的序列进种子池加权（AFL 式）；安全敏感寄存器
    （KEY/DIGEST/MSG_LENGTH/wipe）覆盖权重加倍
  - 验收: 覆盖率随迭代单调增长；对比"纯随机 vs 语料调度"的覆盖差异
"""

import ctypes
import json
import random
import re
import sys
import time
from pathlib import Path

LIB = "/workspace/pickerfuzz/perip/hmac/obj_so/liblibpf_hmac.so"
REGMAP = "/workspace/pickerfuzz/traces/hmac_regmap.json"
SEED_TRACE = "/workspace/pickerfuzz/traces/hmac_smoketest_tlul.log"
OUT_DIR = Path("/workspace/pickerfuzz/fuzz/sched")

HMAC_BASE = 0x41110000

# 安全敏感寄存器（计划书 M9: 覆盖权重加倍）
SECURITY_CRITICAL = {"KEY", "DIGEST", "MSG_LENGTH_LOWER", "MSG_LENGTH_UPPER",
                     "WIPE_SECRET", "CFG", "CMD"}


def load_lib():
    lib = ctypes.CDLL(LIB)
    lib.pf_init.argtypes = [ctypes.c_uint]
    lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    lib.pf_write.restype = ctypes.c_int
    lib.pf_read.argtypes = [ctypes.c_uint32]
    lib.pf_read.restype = ctypes.c_uint32
    lib.pf_poll.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int]
    lib.pf_poll.restype = ctypes.c_int
    lib.pf_reset.argtypes = []
    return lib


class RegModel:
    def __init__(self, path):
        self.entries = json.load(open(path))
        self.by_off = {}
        for e in self.entries:
            if e["kind"] == "reg":
                self.by_off[e["offset"]] = e
            elif e["kind"] == "multireg":
                for i in range(e["count"]):
                    self.by_off[e["offset"] + i * e["stride"]] = {
                        "name": "%s[%d]" % (e["name"], i),
                        "swaccess": e.get("swaccess"),
                        "fields": e.get("fields", []),
                        "parent": e["name"]}
            elif e["kind"] == "window":
                self.by_off[e["offset"]] = e

    def lookup(self, off):
        return self.by_off.get(off)

    def name(self, off):
        e = self.lookup(off)
        return e["name"] if e else "UNK_%x" % off

    def parent_name(self, off):
        e = self.lookup(off)
        if e is None:
            return None
        return e.get("parent") or e.get("name")

    def writable_offsets(self):
        return [o for o, e in self.by_off.items()
                if (e.get("swaccess") or (e["fields"][0].get("swaccess") if e.get("fields") else None))
                in ("rw", "wo", "rw1c", "rw1s")]


# ---------------------------------------------------------------------------
# M2: seed trace 片段解析（poll 压缩）
# ---------------------------------------------------------------------------

def parse_seed_fragments(trace_path):
    """解析 TL-UL trace → 片段列表（连续同地址读压缩为 poll）"""
    txns = []
    pending = None
    for line in open(trace_path):
        ma = re.match(r"\[TLUL\] (\d+) A op=(\d) addr=([0-9a-f]+) data=([0-9a-f]+)", line)
        if ma:
            if pending:
                txns.append(pending)
            pending = {"op": int(ma.group(2)), "addr": int(ma.group(3), 16),
                       "data": int(ma.group(4), 16)}
            continue
        md = re.match(r"\[TLUL\] (\d+) D op=(\d) data=([0-9a-f]+)", line)
        if md and pending:
            pending["d_data"] = int(md.group(3), 16)
            txns.append(pending)
            pending = None
    if pending:
        txns.append(pending)

    # poll 压缩: 连续同地址读 → poll(addr, last_expect, count)
    frags = []
    i = 0
    while i < len(txns):
        t = txns[i]
        off = t["addr"] - HMAC_BASE
        if t["op"] == 4:  # Get
            # 数连续同地址读
            j = i
            while j < len(txns) and txns[j]["op"] == 4 and txns[j]["addr"] == t["addr"]:
                j += 1
            count = j - i
            last = txns[j - 1].get("d_data", 0)
            if count >= 3:
                frags.append(("POLL", off, last, count))
            else:
                for k in range(i, j):
                    frags.append(("R", txns[k]["addr"] - HMAC_BASE, 0, 0xF))
            i = j
        else:
            frags.append(("W", off, t["data"], 0xF))
            i += 1
    return frags


def split_fragments(frags, max_len=12):
    """按空闲间隔/长度切分成片段库"""
    corpus = []
    for start in range(0, len(frags), max_len):
        chunk = frags[start:start + max_len]
        if len(chunk) >= 3:
            corpus.append(chunk)
    return corpus


# ---------------------------------------------------------------------------
# 语料调度执行器
# ---------------------------------------------------------------------------

def exec_op(lib, op):
    kind = op[0]
    if kind == "W":
        _, off, data, mask = op
        return lib.pf_write(HMAC_BASE + off, data, mask)
    if kind == "R":
        _, off, _, _ = op
        lib.pf_read(HMAC_BASE + off)
        return 0
    if kind == "POLL":
        _, off, expect, count = op
        for _ in range(count):
            if lib.pf_read(HMAC_BASE + off) == expect:
                break
        return 0
    return 0


def run_corpus_sequence(lib, seq):
    """执行语料序列，返回触达的寄存器集合 + 违规"""
    lib.pf_init(0)
    touched = set()
    v = 0
    for op in seq:
        kind = op[0]
        if kind == "W":
            _, off, data, mask = op
            e = None
            touched.add(off)
            err = lib.pf_write(HMAC_BASE + off, data, mask)
            if err != 0:
                v += 1
        elif kind == "R":
            touched.add(op[1])
            lib.pf_read(HMAC_BASE + op[1])
        elif kind == "POLL":
            touched.add(op[1])
            exec_op(lib, op)
    return touched, v


def mutate_fragment(frags, rng, rm):
    """片段级变异: 插入/删除/交换/参数替换（计划书 M4）"""
    seq = list(frags)
    n = rng.randint(1, 3)
    for _ in range(n):
        r = rng.random()
        if r < 0.3 and len(seq) > 4:  # 删除
            i = rng.randrange(len(seq))
            del seq[i:i + rng.randint(1, 3)]
        elif r < 0.5 and len(seq) > 4:  # 交换
            i, j = rng.randrange(len(seq)), rng.randrange(len(seq))
            seq[i], seq[j] = seq[j], seq[i]
        elif r < 0.75:  # 参数替换（特殊值/随机）
            i = rng.randrange(len(seq))
            op = list(seq[i])
            if op[0] == "W":
                op[2] = rng.choice([0x0, 0xFFFFFFFF, 0x6, 0x9, rng.getrandbits(32)])
                seq[i] = tuple(op)
        else:  # 插入安全敏感写
            parent = rng.choice(list(SECURITY_CRITICAL))
            cands = [o for o, e in rm.by_off.items()
                     if (e.get("parent") or e.get("name")) == parent]
            if cands:
                off = rng.choice(cands)
                seq.insert(rng.randrange(len(seq) + 1),
                           ("W", off, rng.choice([0x0, 0xFFFFFFFF, rng.getrandbits(32)]), 0xF))
    return seq


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=20000)
    ap.add_argument("--seed-base", type=int, default=31000)
    ap.add_argument("--out", default="/workspace/pickerfuzz/fuzz/sched")
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    lib = load_lib()
    rm = RegModel(REGMAP)

    # 构建语料库
    frags = parse_seed_fragments(SEED_TRACE)
    corpus = split_fragments(frags)
    print("=" * 64)
    print("HTFuzz M9: 语料库调度 fuzzing")
    print("seed trace 片段: %d ops → %d 语料片段" % (len(frags), len(corpus)))
    print("迭代: %d" % args.iters)
    print("=" * 64)

    # 全局覆盖追踪
    global_cov = set()          # 触达的寄存器 offset
    corpus_weights = [1.0] * len(corpus)   # AFL 式权重
    findings = []
    cov_curve = []              # 覆盖增长曲线
    stats = {"seqs": 0, "ops": 0, "o1": 0, "new_cov_seqs": 0}

    t0 = time.time()
    for it in range(args.iters):
        rng = random.Random(args.seed_base + it)
        # 语料调度: 按权重选片段
        if rng.random() < 0.7 and corpus:
            # 加权选择
            base = rng.choices(range(len(corpus)), weights=corpus_weights, k=1)[0]
            seq = mutate_fragment(corpus[base], rng, rm)
        else:
            # 纯随机（保持探索）
            seq = []
            for _ in range(rng.randint(6, 14)):
                off = rng.choice(rm.writable_offsets())
                seq.append(("W", off, rng.choice([0x0, 0xFFFFFFFF, rng.getrandbits(32)]), 0xF))

        stats["seqs"] += 1
        stats["ops"] += len(seq)
        touched, v = run_corpus_sequence(lib, seq)

        # 覆盖反馈: 新触达的寄存器 → 语料加权
        new_cov = touched - global_cov
        if new_cov:
            global_cov |= touched
            stats["new_cov_seqs"] += 1
            # 找到产生新覆盖的语料片段并加权
            for parent in {rm.parent_name(o) for o in new_cov if rm.parent_name(o)}:
                for ci, c in enumerate(corpus):
                    if any(op[0] == "W" and (rm.parent_name(op[1]) == parent) for op in c if op[0] == "W"):
                        corpus_weights[ci] *= 1.5
            # 安全敏感寄存器额外加权
            for o in new_cov:
                pn = rm.parent_name(o)
                if pn in SECURITY_CRITICAL:
                    stats["o1"] += 0  # 占位
        if v:
            stats["o1"] += v
            findings.append({"iter": it, "seed": args.seed_base + it,
                             "violations": v, "seq": [[list(x) for x in s] for s in seq]})

        cov_curve.append(len(global_cov))
        if (it + 1) % 5000 == 0:
            el = time.time() - t0
            print("  [%d/%d] %.1fs 覆盖=%d/%d 寄存器  新覆盖序列=%d 违规=%d"
                  % (it + 1, args.iters, el, len(global_cov), len(rm.by_off),
                     stats["new_cov_seqs"], stats["o1"]))

    el = time.time() - t0
    print()
    print("=" * 64)
    print("语料调度 fuzzing 完成")
    print("  迭代: %d  序列: %d  操作: %d  耗时: %.1fs (%.0f ops/s)"
          % (args.iters, stats["seqs"], stats["ops"], el, stats["ops"] / el))
    print("  寄存器覆盖: %d / %d (%.0f%%)" % (len(global_cov), len(rm.by_off),
                                              100.0 * len(global_cov) / len(rm.by_off)))
    print("  产生新覆盖的序列: %d  O1 违规: %d" % (stats["new_cov_seqs"], stats["o1"]))
    # 覆盖增长曲线（每 1000 迭代采样）
    curve = [cov_curve[i] for i in range(0, len(cov_curve), max(1, len(cov_curve) // 20))]
    print("  覆盖增长曲线: %s" % curve)
    # 保存
    with open(outdir / "findings.jsonl", "w") as f:
        for x in findings:
            f.write(json.dumps(x, default=str) + "\n")
    json.dump({"iters": args.iters, "seqs": stats["seqs"], "ops": stats["ops"],
               "elapsed": el, "coverage": len(global_cov),
               "total_regs": len(rm.by_off), "cov_curve": curve,
               "o1": stats["o1"], "findings": len(findings)},
              open(outdir / "stats.json", "w"), indent=1)
    print("  输出: %s" % outdir)
    print("结果: %s" % ("CLEAN ✓" if not findings else "%d CANDIDATES ✗" % len(findings)))


if __name__ == "__main__":
    main()
