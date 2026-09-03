#!/usr/bin/env python3
"""
HTFuzz M6-O1: hjson 规格 checker（完整版）
=============================================
五条规格规则（全部来自 hmac_regmap.json 的 swaccess/resval 元数据）:
  R1 复位值: 复位后读值 == 规格 resval
  R2 RO 不可写: 写 ro 寄存器 → 回读不变
  R3 W1C 语义: 写 1 清零、写 0 无效
  R4 REGWEN 锁: regwen=0 时受锁寄存器写被忽略
  R5 字段写掩码: 写掩码外的字节不可改（通过 a_mask 驱动）

执行: 通过 ctypes 调 per-IP HMAC DUT（pf_* API）
"""

import ctypes
import json
import sys
from pathlib import Path

LIB = "/workspace/HTFuzz/perip/hmac/obj_so/liblibpf_hmac.so"
REGMAP = "/workspace/HTFuzz/traces/hmac_regmap.json"

HMAC_BASE = 0x41110000


def load_lib():
    # 先编译成共享库（如果没有）
    lib = ctypes.CDLL(LIB)
    lib.pf_init.argtypes = [ctypes.c_uint]
    lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    lib.pf_write.restype = ctypes.c_int
    lib.pf_read.argtypes = [ctypes.c_uint32]
    lib.pf_read.restype = ctypes.c_uint32
    lib.pf_poll.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int]
    lib.pf_poll.restype = ctypes.c_int
    lib.pf_reset.argtypes = []
    lib.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.pf_sig_read.restype = ctypes.c_uint32
    return lib


def parse_bits(bits):
    if ":" in bits:
        hi, lo = map(int, bits.split(":"))
        return hi, lo
    b = int(bits)
    return b, b


def resval_of(field):
    rv = field.get("resval")
    if rv is None:
        return 0
    if isinstance(rv, str):
        if rv.lower() in ("false", "0"):
            return 0
        if rv.lower() in ("true",):
            return 1
        try:
            return int(rv, 0)
        except ValueError:
            return 0
    return int(rv)


class SpecChecker:
    def __init__(self, lib, regmap_path):
        self.lib = lib
        self.regmap = json.load(open(regmap_path))
        self.violations = []
        self.checks = 0

    def log(self, rule, reg, detail):
        self.violations.append({"rule": rule, "reg": reg, "detail": detail})
        print("  [O1-VIOLATION] %s: %s — %s" % (rule, reg, detail))

    def reg_by_name(self, name):
        for e in self.regmap:
            if e.get("name") == name:
                return e
        return None

    # R1: 复位值检查
    def check_reset_values(self):
        print("[R1] 复位值检查 (resval)")
        self.lib.pf_init(0)
        for e in self.regmap:
            if e["kind"] != "reg":
                continue
            for f in e.get("fields", []):
                hi, lo = parse_bits(f["bits"])
                width = hi - lo + 1
                if width < 32:
                    continue  # 只查整字可读的
                expect = 0
                # 组合该寄存器所有字段的 resval
                for f2 in e["fields"]:
                    h2, l2 = parse_bits(f2["bits"])
                    expect |= (resval_of(f2) & ((1 << (h2 - l2 + 1)) - 1)) << l2
                val = self.lib.pf_read(e["offset"])
                self.checks += 1
                if val != expect:
                    self.log("R1-resval", e["name"],
                             "read=0x%08x expect=0x%08x" % (val, expect))
        print("  %d 寄存器检查完成" % self.checks)

    # R2: RO 不可写
    def check_ro_immutable(self):
        print("[R2] RO 寄存器不可写")
        self.lib.pf_init(0)
        for e in self.regmap:
            if e["kind"] != "reg":
                continue
            acc = e.get("swaccess")
            if acc != "ro":
                continue
            before = self.lib.pf_read(e["offset"])
            self.lib.pf_write(e["offset"], 0xA5A5A5A5)
            after = self.lib.pf_read(e["offset"])
            self.checks += 1
            if after != before:
                self.log("R2-ro-immutable", e["name"],
                         "before=0x%08x after-write=0x%08x" % (before, after))
        print("  %d RO 寄存器检查完成" % self.checks)

    # R3: W1C 语义（INTR_STATE）
    def check_w1c(self):
        print("[R3] W1C 语义 (INTR_STATE)")
        self.lib.pf_init(0)
        e = self.reg_by_name("INTR_STATE")
        if not e:
            return
        # 用 INTR_TEST 置位 hmac_done（bit0），再 W1C 清除
        te = self.reg_by_name("INTR_TEST")
        self.lib.pf_write(te["offset"], 0x1, 0xF)   # INTR_TEST.hmac_done=1
        state = self.lib.pf_read(e["offset"])
        self.checks += 1
        if not (state & 0x1):
            self.log("R3-w1c-setup", "INTR_STATE",
                     "INTR_TEST 置位后 state=0x%08x (bit0 应为 1)" % state)
        else:
            self.lib.pf_write(e["offset"], 0x1, 0xF)   # W1C: 写 1 清零
            state2 = self.lib.pf_read(e["offset"])
            self.checks += 1
            if state2 & 0x1:
                self.log("R3-w1c-clear", "INTR_STATE",
                         "写 1 后 state=0x%08x (bit0 应清零)" % state2)
            # 写 0 应无效
            self.lib.pf_write(te["offset"], 0x1, 0xF)
            self.lib.pf_write(e["offset"], 0x0, 0xF)   # 写 0
            state3 = self.lib.pf_read(e["offset"])
            self.checks += 1
            if not (state3 & 0x1):
                self.log("R3-w1c-write0", "INTR_STATE",
                         "写 0 后 state=0x%08x (bit0 不应被清)" % state3)
            self.lib.pf_write(e["offset"], 0x1, 0xF)   # 清理
        self.lib.pf_write(te["offset"], 0x0, 0xF)
        print("  W1C 检查完成")

    # R4: REGWEN 锁（hmac 无 regwen，验证 CFG 在 hash 进行中是否被锁——
    # hmac 的保护是 cfg_block: hash 进行中 CFG 写被忽略）
    def check_cfg_block(self):
        print("[R4] CFG 运行中锁定 (cfg_block 语义)")
        self.lib.pf_init(0)
        cfg_off = self.reg_by_name("CFG")["offset"]
        cmd_off = self.reg_by_name("CMD")["offset"]
        # 启动 hash
        self.lib.pf_write(cfg_off, 0x422, 0xF)
        self.lib.pf_write(cmd_off, 0x1, 0xF)   # start
        # hash 进行中尝试改 CFG
        self.lib.pf_write(cfg_off, 0x500, 0xF)
        # 读回（等 idle 后）
        self.lib.pf_poll(0x18, 0x1, 0x1, 100000)
        cfg_after = self.lib.pf_read(cfg_off)
        self.checks += 1
        # 规格语义: start 后 CFG 应保持 0x422（0x500 写被忽略）
        if cfg_after != 0x422:
            self.log("R4-cfg-block", "CFG",
                     "hash 进行中写 0x500 后 CFG=0x%08x (应保持 0x422)" % cfg_after)
        print("  CFG block 检查完成")

    # R5: 字节写掩码（用 INTR_STATE——PERMIT=0001 只允许 byte0 写，
    # 其他寄存器如 MSG_LENGTH PERMIT=1111 要求全字写，子字写会 wr_err 拒绝）
    def check_write_mask(self):
        print("[R5] 字节写掩码 (INTR_STATE, PERMIT=0001)")
        self.lib.pf_init(0)
        e = self.reg_by_name("INTR_STATE")
        te = self.reg_by_name("INTR_TEST")
        off, teoff = e["offset"], te["offset"]
        # INTR_TEST 置 bit0 和 bit1（hmac_done, fifo_empty）
        self.lib.pf_write(teoff, 0x3, 0xF)
        base = self.lib.pf_read(off)
        self.checks += 1
        if base != 0x3:
            self.log("R5-setup", "INTR_STATE", "INTR_TEST=3 后 state=0x%08x (expect 0x3)" % base)
        # W1C 只写 byte0（mask=0x1）清 bit0
        self.lib.pf_write(off, 0x1, 0x1)
        after = self.lib.pf_read(off)
        self.checks += 1
        expect = 0x2
        if after != expect:
            self.log("R5-write-mask", "INTR_STATE",
                     "mask=0x1 W1C 后 =0x%08x (expect 0x%08x)" % (after, expect))
        # 清理
        self.lib.pf_write(off, 0x3, 0xF)
        self.lib.pf_write(teoff, 0x0, 0xF)
        print("  写掩码检查完成")

    def run_all(self):
        print("=" * 60)
        print("HTFuzz O1: hjson 规格 checker")
        print("=" * 60)
        self.check_reset_values()
        self.check_ro_immutable()
        self.check_w1c()
        self.check_cfg_block()
        self.check_write_mask()
        print()
        print("=" * 60)
        print("O1 汇总: %d 检查, %d 违规" % (self.checks, len(self.violations)))
        for v in self.violations:
            print("  - [%s] %s: %s" % (v["rule"], v["reg"], v["detail"]))
        print("结果: %s" % ("CLEAN ✓" if not self.violations else "VIOLATIONS FOUND ✗"))
        return len(self.violations)


def main():
    lib = load_lib()
    chk = SpecChecker(lib, REGMAP)
    n = chk.run_all()
    sys.exit(0 if n == 0 else 1)


if __name__ == "__main__":
    main()
