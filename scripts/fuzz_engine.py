#!/usr/bin/env python3
"""
HTFuzz 核心引擎 — 基于 hjson 规格的 TL-UL 序列变异器
=========================================================
按新项目计划书方向: hjson 规格 oracle + 元变关系（不做 golden diff）

架构:
  seed trace (TL-UL log) + regmap (hjson 解析)
       │
       ▼
  变异引擎 (本文件)
  - M1 字段位翻转: 对 CFG/CMD 等控制寄存器的合法字段做位翻转
  - M2 非法访问: 对 ro/wo 寄存器做反向访问 (读 wo / 写 ro)
  - M3 序列乱序: 打乱 seed 序列中的独立事务 (保持 CFG 先于 CMD 约束可配置)
  - M4 边界值: 字段 min/max/边界注入 (digest_size=0xF, key_length=0x3F)
  - M5 窗口越界: MSG_FIFO 窗口外地址访问
  - M6 状态机违规: 未 start 直接 process / process 后继续写 FIFO
       │
       ▼
  C 数组固件 (pickerfuzz_seq_N.h) → 固件回放 + 内嵌 oracle
"""

import json
import random
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

HMAC_BASE = 0x41110000
HMAC_LIMIT = 0x41112000

# TL-UL opcodes
OP_PUT_FULL = 0
OP_PUT_PARTIAL = 1
OP_GET = 4


@dataclass
class TlulTxn:
    """单条 TL-UL 事务"""
    cycle: int
    op: int          # 0=PutFull 1=PutPartial 4=Get
    addr: int
    data: int
    mask: int = 0xF
    src: int = 0
    size: int = 2
    # D 通道响应 (seed 中记录)
    d_op: int = -1
    d_data: int = 0
    d_err: int = 0
    # 特殊标记: wait_done = 固件回放时自旋等待 INTR_STATE.hmac_done
    wait_done: bool = False

    @property
    def is_write(self):
        return self.op in (OP_PUT_FULL, OP_PUT_PARTIAL)

    def to_c(self):
        if self.wait_done:
            # 特殊编码: op=0xF 表示 wait_done（addr/data 无意义）
            return "{0x00000000u, 0x00000000u, 0x0000u, 15u}"
        return ("{0x%08xu, 0x%08xu, 0x%04xu, %du}" %
                (self.addr, self.data, self.mask, self.op))


@dataclass
class RegMap:
    """hjson 解析出的寄存器映射"""
    entries: list = field(default_factory=list)
    by_offset: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path):
        rm = cls()
        rm.entries = json.load(open(path))
        for e in rm.entries:
            if e["kind"] == "reg":
                rm.by_offset[e["offset"]] = e
            elif e["kind"] == "multireg":
                for i in range(e["count"]):
                    rm.by_offset[e["offset"] + i * e["stride"]] = {
                        "name": "%s[%d]" % (e["name"], i),
                        "fields": e.get("fields", []),
                        "swaccess": e.get("swaccess"),
                        "multireg_parent": e["name"],
                    }
            elif e["kind"] == "window":
                rm.by_offset[e["offset"]] = e
        return rm

    def lookup(self, offset):
        return self.by_offset.get(offset)

    def name_of(self, offset):
        e = self.lookup(offset)
        return e["name"] if e else "UNK_%x" % offset

    def swaccess_of(self, offset):
        e = self.lookup(offset)
        if e is None:
            return None
        if e.get("kind") == "window":
            return e.get("swaccess")
        return e.get("swaccess") or (e["fields"][0].get("swaccess") if e.get("fields") else None)


def parse_bits(bits):
    if ":" in bits:
        hi, lo = bits.split(":")
        return int(hi), int(lo)
    b = int(bits)
    return b, b


def parse_seed_trace(path, regmap=None):
    """解析 TL-UL trace → TlulTxn 列表（A/D 配对）"""
    txns = []
    pending = None
    with open(path) as f:
        for line in f:
            ma = re.match(r"\[TLUL\] (\d+) A op=(\d) addr=([0-9a-f]+) "
                          r"data=([0-9a-f]+) mask=([0-9a-f]+) src=([0-9a-f]+) size=(\d)", line)
            if ma:
                if pending:
                    txns.append(pending)
                pending = TlulTxn(
                    cycle=int(ma.group(1)), op=int(ma.group(2)),
                    addr=int(ma.group(3), 16), data=int(ma.group(4), 16),
                    mask=int(ma.group(5), 16), src=int(ma.group(6), 16),
                    size=int(ma.group(7)))
                continue
            md = re.match(r"\[TLUL\] (\d+) D op=(\d) data=([0-9a-f]+) dst=([0-9a-f]+) err=(\d)", line)
            if md and pending:
                pending.d_op = int(md.group(2))
                pending.d_data = int(md.group(3), 16)
                pending.d_err = int(md.group(5))
                txns.append(pending)
                pending = None
    if pending:
        txns.append(pending)
    return txns


# ---------------------------------------------------------------------------
# 变异器
# ---------------------------------------------------------------------------

class Mutator:
    def __init__(self, regmap, seed_txns, rng=None):
        self.rm = regmap
        self.seed = seed_txns
        self.rng = rng or random.Random(0xC0FFEE)

    # --- M1: 控制寄存器字段位翻转 ---
    def mut_bitflip(self, n=8):
        out = []
        ctrl_offs = [o for o, e in self.rm.by_offset.items()
                     if e.get("name") in ("CFG", "CMD", "INTR_ENABLE", "INTR_TEST",
                                          "MSG_LENGTH_LOWER", "MSG_LENGTH_UPPER")]
        for _ in range(n):
            off = self.rng.choice(ctrl_offs)
            e = self.rm.by_offset[off]
            flds = e.get("fields", [])
            if not flds:
                continue
            f = self.rng.choice(flds)
            hi, lo = parse_bits(f["bits"])
            bit = self.rng.randint(lo, hi)
            # 找 seed 中该寄存器最近一次写的值作为基底
            base = 0
            for t in reversed(self.seed):
                if t.is_write and t.addr - HMAC_BASE == off:
                    base = t.data
                    break
            data = base ^ (1 << bit)
            out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + off, data))
        return out

    # --- M2: 非法访问方向 ---
    def mut_illegal_dir(self, n=8):
        out = []
        for _ in range(n):
            off = self.rng.choice(list(self.rm.by_offset.keys()))
            acc = self.rm.swaccess_of(off)
            if acc in ("ro", "rw1c"):
                # 写 ro/rw1c（合法但语义特殊——rw1c 写1清零，测试写 0/1/全F）
                data = self.rng.choice([0x0, 0x1, 0xFFFFFFFF])
                out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + off, data))
            elif acc == "wo":
                # 读 wo
                out.append(TlulTxn(0, OP_GET, HMAC_BASE + off, 0))
            elif acc is None:
                # 未映射 offset（窗口内空洞）
                out.append(TlulTxn(0, self.rng.choice([OP_GET, OP_PUT_FULL]),
                                   HMAC_BASE + off, 0xDEADBEEF))
        return out

    # --- M3: 序列乱序（保持 CFG 在最前的约束可选） ---
    def mut_reorder(self, n=4):
        out = []
        for _ in range(n):
            seq = list(self.seed)
            if not seq:
                continue
            # 随机交换 2-5 对事务
            for _ in range(self.rng.randint(2, 5)):
                i, j = self.rng.randrange(len(seq)), self.rng.randrange(len(seq))
                seq[i], seq[j] = seq[j], seq[i]
            out.extend(seq)
        return out

    # --- M4: 字段边界值 ---
    def mut_boundary(self, n=8):
        out = []
        specials = [
            (0x10, 0x00000000),  # CFG 全 0
            (0x10, 0x0000FFFF),  # CFG 全 1（digest_size=0xF 非法, key_length=0x3F 非法）
            (0x10, 0x0000003F),  # digest_size=0x7 非法
            (0x10, 0x00003E00),  # key_length=0x1F 非法
            (0x14, 0x0000000F),  # CMD 全部命令同时置位
            (0x14, 0x00000002),  # 仅 process（未 start）
            (0x14, 0x00000004),  # 仅 stop
            (0x14, 0x00000008),  # 仅 continue
            (0xE4, 0xFFFFFFFF),  # MSG_LENGTH_LOWER max
            (0xE8, 0xFFFFFFFF),  # MSG_LENGTH_UPPER max
            (0xE4, 0x00000001),  # MSG_LENGTH=1（非 512 对齐）
            (0xE4, 0x000001FF),  # MSG_LENGTH=511（非对齐边界）
        ]
        self.rng.shuffle(specials)
        for off, data in specials[:n]:
            out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + off, data))
        return out

    # --- M5: 窗口越界 ---
    def mut_window_oob(self, n=6):
        out = []
        oob_addrs = [
            HMAC_LIMIT,              # 窗口结束
            HMAC_LIMIT + 0x100,      # 窗口外
            HMAC_BASE - 4,           # 窗口前
            HMAC_BASE + 0x0FFC,      # MSG_FIFO 最后一字
            HMAC_BASE + 0x0FF8,
            0x41111000 + 0x1000,     # MSG_FIFO 结束
        ]
        for _ in range(n):
            a = self.rng.choice(oob_addrs)
            out.append(TlulTxn(0, self.rng.choice([OP_GET, OP_PUT_FULL, OP_PUT_PARTIAL]),
                               a, self.rng.choice([0, 0xFFFFFFFF, 0xA5A5A5A5])))
        return out

    # --- M6: 状态机违规序列 ---
    def mut_fsm_violation(self):
        out = []
        # V1: 未 start 直接 process
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x2))       # CMD=process
        out.append(TlulTxn(0, OP_GET, HMAC_BASE + 0x18, 0))              # STATUS
        # V2: process 后继续写 MSG_FIFO
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x10, 0x422))     # CFG
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x1))       # start
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x1000, 0x41424344))
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x2))       # process
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x1000, 0x45464748))  # 违规写
        out.append(TlulTxn(0, OP_GET, HMAC_BASE + 0x18, 0))
        # V3: 双重 start
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x1))
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x1))
        out.append(TlulTxn(0, OP_GET, HMAC_BASE + 0x1C, 0))              # ERR_CODE
        # V4: process 期间改 CFG
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x10, 0x422))
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x1))
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x10, 0x500))     # 违规改 CFG
        out.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x2))
        out.append(TlulTxn(0, OP_GET, HMAC_BASE + 0x1C, 0))
        return out

    # --- M7: 元变关系对（同输入不同路径 → 同输出） ---
    def mut_metamorphic_pair(self):
        """生成一对序列: A) 一次性写满 FIFO 再 process; B) 分批写 FIFO 再 process
        两者对同一消息应产生相同 digest (O3 oracle)
        每条路径 process 后轮询 INTR_STATE.hmac_done 再读 digest"""
        msg = [0x63636363, 0x63636363, 0x63636363, 0x63636363,
               0x63636363, 0x63636363, 0x63636363, 0x63636363]  # 32B 'c'
        # done 轮询事务（op=4 读 INTR_STATE，固件回放时自旋等待 bit0）
        def wait_done():
            return TlulTxn(0, OP_GET, HMAC_BASE + 0x0, 0, wait_done=True)

        seq_a = [TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x10, 0x422),
                 TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x1)]
        seq_a += [TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x1000, w) for w in msg]
        seq_a += [TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0xE4, 256),   # 256 bit
                  TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x2),
                  wait_done()]
        seq_a += [TlulTxn(0, OP_GET, HMAC_BASE + 0xA4 + 4 * i, 0) for i in range(8)]

        seq_b = [TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x10, 0x422),
                 TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x1)]
        # 分两批写，中间轮询 STATUS
        for w in msg[:4]:
            seq_b.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x1000, w))
        seq_b.append(TlulTxn(0, OP_GET, HMAC_BASE + 0x18, 0))
        for w in msg[4:]:
            seq_b.append(TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x1000, w))
        seq_b += [TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0xE4, 256),
                  TlulTxn(0, OP_PUT_FULL, HMAC_BASE + 0x14, 0x2),
                  wait_done()]
        seq_b += [TlulTxn(0, OP_GET, HMAC_BASE + 0xA4 + 4 * i, 0) for i in range(8)]
        return seq_a + seq_b


MUTATIONS = {
    "bitflip":   lambda m: m.mut_bitflip(8),
    "illegal":   lambda m: m.mut_illegal_dir(8),
    "reorder":   lambda m: m.mut_reorder(2),
    "boundary":  lambda m: m.mut_boundary(8),
    "window":    lambda m: m.mut_window_oob(6),
    "fsm":       lambda m: m.mut_fsm_violation(),
    "meta":      lambda m: m.mut_metamorphic_pair(),
}


# ---------------------------------------------------------------------------
# C 代码生成
# ---------------------------------------------------------------------------

C_TEMPLATE = """// Auto-generated by fuzz_engine.py — HTFuzz mutation @@MTYPE@@
// seed=@@SEED@@  mut_id=@@MUT_ID@@
#include "ot_secfuzz.h"

#define PF_N_TXN @@N_TXN@@
// txn: {addr, data, mask, op}  op: 0=PutFull 1=PutPartial 4=Get
static const uint32_t pf_txn[PF_N_TXN][4] = {
@@TXN_ROWS@@
};

OTTF_DEFINE_TEST_CONFIG();
bool test_main(void) {
    FUZZ_STEP(@@MUT_ID@@, "PICKERFUZZ @@MTYPE@@", "hjson-spec oracle");
    uint32_t hb = HMAC_BASE;
    uint32_t anomalies = 0;
    for (uint32_t i = 0; i < PF_N_TXN; i++) {
        uint32_t addr = pf_txn[i][0];
        uint32_t data = pf_txn[i][1];
        uint32_t op   = pf_txn[i][3];
        if (op == 15) {
            // wait_done: 自旋等待 INTR_STATE.hmac_done (bit0)，然后写1清零
            uint32_t spin = 0;
            while ((rd(hb + 0x0) & 0x1) == 0 && spin < 2000000u) spin++;
            wr(hb + 0x0, 0x1);  // rw1c 清 done
            if (spin >= 2000000u) {
                LOG_INFO("  [O4] timeout waiting hmac_done");
                anomalies++;
            }
        } else if (op == 4) {
            uint32_t rdv = rd(addr);
            // O1-lite: 读回值必须是 known（非全1总线悬空特征）
            if (rdv == 0xFFFFFFFFu && (addr & 0xFFF) != 0x008) {
                LOG_INFO("  [O1] read-all-ones @0x%08x (off=0x%03x)", addr,
                         (unsigned)(addr - hb));
                anomalies++;
            }
        } else {
            wr(addr, data);
        }
    }
    // O2: 标准序列后跑一次参考 HMAC，比对 NIST digest
    // (回放 seed 的正常流程并检查 digest)
    @@O2_BLOCK@@
    if (anomalies == 0) FUZZ_PASS(@@MUT_ID@@, "no anomaly");
    else FUZZ_FAIL(@@MUT_ID@@, "anomaly detected");
    fuzz_print_summary();
    return anomalies == 0;
}
"""

O2_BLOCK = """
    // --- O2: NIST 参考值检查 ---
    // CFG=sha_en|SHA256|key256, start, 写 32B 'a', process, 等 done, 读 DIGEST
    wr(hb + 0x10, 0x422);
    wr(hb + 0x14, 0x1);
    for (int w = 0; w < 8; w++) wr(hb + 0x1000, 0x61616161u);
    wr(hb + 0xE4, 256);
    wr(hb + 0x14, 0x2);
    uint32_t spin = 0;
    while ((rd(hb + 0x18) & 0x1) == 0 && spin < 100000) spin++;  // 等 idle
    uint32_t dig0 = rd(hb + 0xA4);
    // SHA256("a"*32) = 3ba3f5f4... 第一个词（大端词序）
    if (dig0 != 0x3ba3f5f4u && dig0 != 0xf4f5a33bu) {
        LOG_INFO("  [O2] digest mismatch: got=0x%08x", dig0);
        anomalies++;
    }
"""


def gen_c(mtype, mut_id, txns, seed_name="hmac_smoketest", with_o2=False):
    rows = "\n".join("    %s," % t.to_c() for t in txns)
    o2 = O2_BLOCK if with_o2 else "    // (O2 skipped for this mutation)"
    # 用占位符替换避免 % 格式化冲突（模板里有 printf 的 %08x）
    body = (C_TEMPLATE
            .replace("@@MTYPE@@", mtype)
            .replace("@@MUT_ID@@", str(mut_id))
            .replace("@@N_TXN@@", str(len(txns)))
            .replace("@@TXN_ROWS@@", rows)
            .replace("@@SEED@@", seed_name)
            .replace("@@O2_BLOCK@@", o2))
    return body


def main():
    import argparse
    ap = argparse.ArgumentParser(description="HTFuzz mutation engine")
    ap.add_argument("--regmap", default="/workspace/pickerfuzz/traces/hmac_regmap.json")
    ap.add_argument("--seed", default="/workspace/pickerfuzz/traces/hmac_smoketest_tlul.log")
    ap.add_argument("--out", default="/workspace/pickerfuzz/fuzz/out")
    ap.add_argument("--mutations", default="bitflip,illegal,boundary,window,fsm,meta")
    ap.add_argument("--seed-num", type=int, default=1, help="random seed")
    args = ap.parse_args()

    rng = random.Random(args.seed_num)
    rm = RegMap.load(args.regmap)
    seed = parse_seed_trace(args.seed, rm)
    mut = Mutator(rm, seed, rng)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = []
    mid = 1
    for mtype in args.mutations.split(","):
        if mtype not in MUTATIONS:
            continue
        txns = MUTATIONS[mtype](mut)
        with_o2 = (mtype == "meta")  # 元变序列后跑 O2
        c = gen_c(mtype, mid, txns, with_o2=with_o2)
        fname = "pickerfuzz_%s_%d" % (mtype, mid)
        (outdir / (fname + ".c")).write_text(c)
        manifest.append({"id": mid, "type": mtype, "target": fname,
                         "n_txn": len(txns)})
        print("[engine] %s -> %s.c (%d txns)" % (mtype, fname, len(txns)))
        mid += 1

    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print("[engine] manifest.json written (%d mutations)" % len(manifest))


if __name__ == "__main__":
    main()
