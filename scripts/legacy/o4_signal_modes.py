#!/usr/bin/env python3
"""
HTFuzz M6-O4: 信号转移模式（移植 HTFuzz Layer 2/3）
==========================================================
值域分桶: zero / one / all-ones / small / large / special / other
四模式检测:
  P1 constancy: 序列全程恒定的信号（若名字含安全关键词 → 可疑）
  P2 stuck-at:  某操作后应变化但恒定（如 hash_start 后 done 信号不变）
  P3 post-zeroize-residue: wipe 后信号应归零/全F 但残留其他值
  P4 special-value-lock: 特殊值（MuBi 6/9, lc 5/10）出现后信号被"锁死"
关键词加权: zeroize/clear/lock/valid/trigger/done/idle
"""

import ctypes
import json
import sys

LIB = "/workspace/HTFuzz/perip/hmac/obj_so/liblibpf_hmac.so"

# 特殊值表（计划书 M3: 从 pkg 自动提取；此处预置 hmac 相关）
SPECIAL_VALUES = {6: "MuBi4True", 9: "MuBi4False", 5: "LC_On", 10: "LC_Off"}
KEYWORDS = ["zeroize", "wipe", "clear", "lock", "valid", "trigger", "done", "idle", "block", "start"]


def load_lib():
    lib = ctypes.CDLL(LIB)
    lib.pf_init.argtypes = [ctypes.c_uint]
    lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    lib.pf_read.argtypes = [ctypes.c_uint32]
    lib.pf_read.restype = ctypes.c_uint32
    lib.pf_poll.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int]
    lib.pf_sig_count.restype = ctypes.c_int
    lib.pf_sig_name.argtypes = [ctypes.c_int]
    lib.pf_sig_name.restype = ctypes.c_char_p
    lib.pf_sig_words.argtypes = [ctypes.c_int]
    lib.pf_sig_words.restype = ctypes.c_int
    lib.pf_sig_value.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.pf_sig_value.restype = ctypes.c_uint32
    lib.pf_snap_count.restype = ctypes.c_int
    lib.pf_snap_value.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lib.pf_snap_value.restype = ctypes.c_uint32
    return lib


def bucket(v):
    """值域分桶"""
    if v == 0:
        return "zero"
    if v == 1:
        return "one"
    if v == 0xFFFFFFFF:
        return "all-ones"
    if v < 0x100:
        return "small"
    if v > 0xFFFF0000:
        return "large"
    if v in SPECIAL_VALUES:
        return "special"
    return "other"


def keyword_weight(name):
    """信号名关键词加权"""
    low = name.lower()
    return sum(2 for k in KEYWORDS if k in low)


def collect_trace(lib):
    """跑一个含完整操作类型的序列，每个 op 后拍快照"""
    lib.pf_init(0)
    n_sig = lib.pf_sig_count()
    sig_names = [lib.pf_sig_name(i).decode() for i in range(n_sig)]
    sig_words = [lib.pf_sig_words(i) for i in range(n_sig)]

    trace = []  # [(op_desc, snapshot_dict)]

    def snap(desc):
        s = {}
        for i in range(n_sig):
            s[sig_names[i]] = [lib.pf_sig_value(i, w) for w in range(sig_words[i])]
        trace.append((desc, s))

    snap("reset")
    # 操作序列: 覆盖配置/启动/写数据/处理/完成/wipe
    lib.pf_write(0x10, 0x422, 0xF); snap("write CFG")
    lib.pf_write(0x24, 0xDEADBEEF, 0xF); snap("write KEY[0]")
    lib.pf_write(0x14, 0x1, 0xF); snap("CMD start")
    for w in range(8):
        lib.pf_write(0x1000, 0x61616161, 0xF)
    snap("write MSG_FIFO x8")
    lib.pf_write(0xE4, 256, 0xF); snap("write MSG_LENGTH")
    lib.pf_write(0x14, 0x2, 0xF); snap("CMD process")
    lib.pf_poll(0x0, 0x1, 0x1, 100000); snap("poll done")
    lib.pf_write(0x0, 0x1, 0xF); snap("W1C INTR_STATE")
    lib.pf_write(0x20, 0xFFFFFFFF, 0xF); snap("WIPE_SECRET")
    return trace, sig_names, sig_words


def analyze(trace, sig_names, sig_words):
    findings = []

    # 每个信号的时间序列（按快照）
    series = {}
    for name in sig_names:
        series[name] = [dict_snap[name] for _, dict_snap in trace]

    for name, vals in series.items():
        w = keyword_weight(name)
        # 单字信号分析（多字信号取第一个字做模式分析）
        v0 = [x[0] for x in vals]
        buckets = [bucket(x) for x in v0]

        # P1 constancy: 全程恒定
        if len(set(v0)) == 1 and len(v0) > 3:
            findings.append(("P1-constancy", name, v0[0], w,
                             "全程恒定 0x%08x" % v0[0]))

        # P2 stuck-at: WIPE_SECRET 后应变化的信号仍恒定
        wipe_idx = next((i for i, (d, _) in enumerate(trace) if "WIPE" in d), None)
        if wipe_idx is not None and w > 0:
            before = v0[wipe_idx - 1] if wipe_idx > 0 else None
            after = v0[wipe_idx]
            if before is not None and before == after and before not in (0, 0xFFFFFFFF):
                findings.append(("P2-stuck-at", name, after, w,
                                 "wipe 后未变化 0x%08x" % after))

        # P3 post-zeroize-residue: wipe 后残留非 0/全F 值
        if wipe_idx is not None:
            after_wipe = v0[wipe_idx]
            if after_wipe not in (0, 0xFFFFFFFF) and w >= 4:
                findings.append(("P3-residue", name, after_wipe, w,
                                 "wipe 后残留 0x%08x" % after_wipe))

        # P4 special-value-lock: 特殊值出现后恒定
        for i, b in enumerate(buckets):
            if b == "special" and i < len(v0) - 1 and all(x == v0[i] for x in v0[i:]):
                findings.append(("P4-special-lock", name, v0[i], w,
                                 "特殊值 0x%08x (%s) 后锁死" % (v0[i], SPECIAL_VALUES.get(v0[i], "?"))))
                break

    # 按关键词权重排序（高权重优先报告）
    findings.sort(key=lambda f: -f[3])
    return findings


def main():
    lib = load_lib()
    print("=" * 60)
    print("HTFuzz O4: 信号转移模式")
    print("=" * 60)
    trace, sig_names, sig_words = collect_trace(lib)
    print("采集: %d 快照 × %d 信号" % (len(trace), len(sig_names)))
    findings = analyze(trace, sig_names, sig_words)
    print()
    print("--- 模式发现（按关键词权重排序）---")
    for mode, name, val, w, desc in findings[:20]:
        print("  [%s] %s (w=%d): %s" % (mode, name, w, desc))
    print()
    n_high = sum(1 for f in findings if f[3] >= 4)
    print("O4 汇总: %d 发现, %d 高权重（需人工/LLM 分诊）" % (len(findings), n_high))
    print("说明: P1 constancy 对状态寄存器是正常行为；高权重 + P2/P3 才是候选")
    # 保存 JSON
    out = [{"mode": m, "signal": n, "value": "0x%08x" % v, "weight": w, "desc": d}
           for m, n, v, w, d in findings]
    json.dump(out, open("/workspace/HTFuzz/fuzz/o4_findings.json", "w"), indent=1)
    print("详情: fuzz/o4_findings.json")


if __name__ == "__main__":
    main()
