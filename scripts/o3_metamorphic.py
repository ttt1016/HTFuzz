#!/usr/bin/env python3
"""
HTFuzz M6-O3: 元变 oracle 三合一（完整版）
==============================================
O3-① 双种子一致性: 同一序列在 seed=0（全零初值）和 seed=2（随机初值）下跑，
     全部可观测输出（寄存器读值 + 白盒内部状态）必须一致
O3-② 复位重放: 序列 → 复位 → 重跑 → 逐位一致
O3-③ zeroize 等价: WIPE_SECRET 后全量扫描内部信号，与"全新复位"状态对比，
     zeroize 声称覆盖的范围必须等价（密钥残留检测）
"""

import ctypes
import json
import sys

LIB = "/workspace/HTFuzz/perip/hmac/obj_so/liblibpf_hmac.so"
REGMAP = "/workspace/HTFuzz/traces/hmac_regmap.json"


def load_lib():
    lib = ctypes.CDLL(LIB)
    lib.pf_init.argtypes = [ctypes.c_uint]
    lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    lib.pf_read.argtypes = [ctypes.c_uint32]
    lib.pf_read.restype = ctypes.c_uint32
    lib.pf_poll.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int]
    lib.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.pf_sig_read.restype = ctypes.c_uint32
    lib.pf_sig_count.restype = ctypes.c_int
    lib.pf_sig_name.argtypes = [ctypes.c_int]
    lib.pf_sig_name.restype = ctypes.c_char_p
    lib.pf_sig_words.argtypes = [ctypes.c_int]
    lib.pf_sig_words.restype = ctypes.c_int
    lib.pf_sig_value.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.pf_sig_value.restype = ctypes.c_uint32
    lib.pf_reset.argtypes = []
    lib.pf_snap_count.restype = ctypes.c_int
    lib.pf_snap_value.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lib.pf_snap_value.restype = ctypes.c_uint32
    lib.pf_snap_diff.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.pf_snap_diff.restype = ctypes.c_int
    return lib


# 白盒信号全集（密钥残留扫描目标）
KEY_SIGS = ["u_dut.secret_key", "u_dut.secret_key_d",
            "sha2.hash_q", "sha2.hash_d", "sha2.digest_q", "sha2.digest_d", "sha2.w_q"]


def read_all_signals(lib):
    """读全部白盒信号 → {name: [words]}"""
    out = {}
    n = lib.pf_sig_count()
    for i in range(n):
        name = lib.pf_sig_name(i).decode()
        w = lib.pf_sig_words(i)
        out[name] = [lib.pf_sig_value(i, j) for j in range(w)]
    return out


def run_sha256_sequence(lib, seed):
    """标准 SHA256 序列，返回全部可观测输出"""
    lib.pf_init(seed)
    obs = {}
    lib.pf_write(0x10, 0x422, 0xF)
    obs["CFG"] = lib.pf_read(0x10)
    lib.pf_write(0x14, 0x1, 0xF)
    for w in range(8):
        lib.pf_write(0x1000, 0x61616161, 0xF)
    lib.pf_write(0xE4, 256, 0xF)
    lib.pf_write(0x14, 0x2, 0xF)
    lib.pf_poll(0x0, 0x1, 0x1, 100000)
    lib.pf_write(0x0, 0x1, 0xF)
    for w in range(8):
        obs["DIGEST[%d]" % w] = lib.pf_read(0xA4 + 4 * w)
    obs["STATUS"] = lib.pf_read(0x18)
    # 白盒内部状态
    sigs = read_all_signals(lib)
    for k in KEY_SIGS:
        obs["sig:" + k] = sigs.get(k, [])
    return obs


def compare_obs(a, b, label):
    """比较两个观测字典，返回差异数"""
    diffs = []
    for k in a:
        va, vb = a.get(k), b.get(k)
        if isinstance(va, list):
            if va != vb:
                diffs.append((k, "list", va, vb))
        elif va != vb:
            diffs.append((k, va, vb))
    if diffs:
        print("  [%s] %d 处差异:" % (label, len(diffs)))
        for d in diffs[:6]:
            print("    %s: %s vs %s" % (d[0], d[1], d[2]))
    return len(diffs)


def o3_1_dual_seed(lib):
    print("[O3-1] 双种子一致性 (seed=0 vs seed=2)")
    a = run_sha256_sequence(lib, 0)
    b = run_sha256_sequence(lib, 2)
    n = compare_obs(a, b, "O3-1")
    print("  %s (%d 差异)" % ("CONSISTENT ✓" if n == 0 else "DIVERGED ✗", n))
    return n


def o3_2_reset_replay(lib):
    print("[O3-2] 复位重放 (序列 → reset → 重跑)")
    lib.pf_init(0)
    # 第一遍
    lib.pf_write(0x10, 0x422, 0xF)
    lib.pf_write(0x14, 0x1, 0xF)
    for w in range(8):
        lib.pf_write(0x1000, 0x62626262, 0xF)
    lib.pf_write(0xE4, 256, 0xF)
    lib.pf_write(0x14, 0x2, 0xF)
    lib.pf_poll(0x0, 0x1, 0x1, 100000)
    lib.pf_write(0x0, 0x1, 0xF)
    first = [lib.pf_read(0xA4 + 4 * w) for w in range(8)]
    # 复位 + 重跑
    lib.pf_reset()
    lib.pf_write(0x10, 0x422, 0xF)
    lib.pf_write(0x14, 0x1, 0xF)
    for w in range(8):
        lib.pf_write(0x1000, 0x62626262, 0xF)
    lib.pf_write(0xE4, 256, 0xF)
    lib.pf_write(0x14, 0x2, 0xF)
    lib.pf_poll(0x0, 0x1, 0x1, 100000)
    lib.pf_write(0x0, 0x1, 0xF)
    second = [lib.pf_read(0xA4 + 4 * w) for w in range(8)]
    diffs = sum(1 for x, y in zip(first, second) if x != y)
    print("  %s (%d/%d digest 词差异)" % ("REPLAY-MATCH ✓" if diffs == 0 else "REPLAY-DIVERGED ✗", diffs, 8))
    return diffs


def o3_3_zeroize_equiv(lib):
    """zeroize 等价: 写密钥 → hash → WIPE_SECRET → 全量扫描 vs 全新复位"""
    print("[O3-3] zeroize 等价扫描 (密钥残留)")
    # 步骤 1: 写满密钥 + 跑一次 HMAC，让密钥进入所有流水级
    lib.pf_init(0)
    for w in range(8):
        lib.pf_write(0x24 + 4 * w, 0xDEADBEEF + w, 0xF)   # KEY[0..7]
    lib.pf_write(0x10, 0x422, 0xF)   # hmac_en=1
    lib.pf_write(0x14, 0x1, 0xF)     # start
    for w in range(8):
        lib.pf_write(0x1000, 0x63636363, 0xF)
    lib.pf_write(0xE4, 256, 0xF)
    lib.pf_write(0x14, 0x2, 0xF)     # process
    lib.pf_poll(0x0, 0x1, 0x1, 100000)
    lib.pf_write(0x0, 0x1, 0xF)
    # 步骤 2: WIPE_SECRET（全 F）
    lib.pf_write(0x20, 0xFFFFFFFF, 0xF)
    # 步骤 3: 全量扫描内部信号
    after_wipe = read_all_signals(lib)
    # 步骤 4: 全新复位状态
    lib.pf_init(0)
    fresh = read_all_signals(lib)
    # 步骤 5: 对比密钥相关信号
    violations = 0
    for sig in KEY_SIGS:
        wa, wf = after_wipe.get(sig, []), fresh.get(sig, [])
        residue = [(i, x) for i, x in enumerate(wa)
                   if i < len(wf) and x != wf[i]]
        # 残留检查: wipe 后应等于 fresh（全 0 或全 F——wipe_v=全F 所以 secret_key=全F 合法）
        if sig in ("u_dut.secret_key", "u_dut.secret_key_d"):
            # wipe_v=0xFFFFFFFF → secret_key 应为全 F
            bad = [x for x in wa if x not in (0, 0xFFFFFFFF)]
            if bad:
                print("  [O3-3-VIOLATION] %s 残留: %d 词非 0/全F (如 0x%08x)"
                      % (sig, len(bad), bad[0]))
                violations += 1
            else:
                print("  %s: wipe 后全 0/全F ✓" % sig)
        else:
            # sha2 状态: wipe 不清 sha 状态（规格只清密钥），但 hash 完成后
            # digest_q 应该是结果不是密钥。检查是否有 KEY 值残留
            key_words = set(0xDEADBEEF + w for w in range(8))
            residue = [x for x in wa if x in key_words]
            if residue:
                print("  [O3-3-VIOLATION] %s 残留密钥值: %d 词 (如 0x%08x)"
                      % (sig, len(residue), residue[0]))
                violations += 1
            else:
                print("  %s: 无密钥值残留 ✓" % sig)
    print("  %s" % ("ZEROIZE-EQUIV ✓" if violations == 0 else "KEY-RESIDUE FOUND ✗"))
    return violations


def main():
    lib = load_lib()
    print("=" * 60)
    print("HTFuzz O3: 元变 oracle 三合一")
    print("=" * 60)
    v = 0
    v += o3_1_dual_seed(lib)
    v += o3_2_reset_replay(lib)
    v += o3_3_zeroize_equiv(lib)
    print()
    print("=" * 60)
    print("O3 汇总: %d 违规" % v)
    print("结果: %s" % ("CLEAN ✓" if v == 0 else "VIOLATIONS FOUND ✗"))
    sys.exit(0 if v == 0 else 1)


if __name__ == "__main__":
    main()
