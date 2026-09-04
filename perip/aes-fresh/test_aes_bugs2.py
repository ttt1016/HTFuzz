#!/usr/bin/env python3
"""AES-ctf 剩余 bug 批量检测: Bug#82/32/6/9/31/34
需要先跑完整 AES 操作触发 cipher FSM 的 CLEAR 状态。
寄存器偏移（aes.hjson）: KEY_SHARE0_0=0x44, KEY_SHARE1_0=0x64, DATA_IN_0=0x84,
CTRL_SHADOWED=0x24, TRIGGER=0x14, STATUS=0x1c, DATA_OUT_0=0xC4
"""
import ctypes, os, sys

os.environ["LD_LIBRARY_PATH"] = "/workspace/pickerfuzz/perip/aes-ctf/obj_so"
os.chdir("/workspace/pickerfuzz/perip/aes-ctf")
dut = ctypes.CDLL("liblibpf_aes_ctf.so", mode=ctypes.RTLD_GLOBAL)
api = ctypes.CDLL("liblibpf_aes_ctf_new.so", mode=ctypes.RTLD_GLOBAL)

api.pf_init.argtypes = [ctypes.c_uint]
api.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
api.pf_write.restype = ctypes.c_int
api.pf_read.restype = ctypes.c_uint32
api.pf_read.argtypes = [ctypes.c_uint32]
api.pf_step.argtypes = [ctypes.c_int]
api.pf_sig_read.restype = ctypes.c_uint32
api.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
api.pf_sig_name.restype = ctypes.c_char_p

BASE = 0x41100000
# aes.hjson 偏移（老版本）
CTRL_SHADOWED = 0x74
TRIGGER       = 0x80
STATUS        = 0x84
KEY_SHARE0_0  = 0x4
KEY_SHARE1_0  = 0x24
DATA_IN_0     = 0x54
DATA_OUT_0    = 0x64

def sig(name, w=0):
    return api.pf_sig_read(name.encode(), w)

def wb(name, words):
    return [sig(name, w) for w in range(words)]

def wait_status(mask, expect, maxc=5000):
    for _ in range(maxc):
        api.pf_step(1)
        if (api.pf_read(BASE + STATUS) & mask) == expect:
            return True
    return False

def run_aes_op(key_words, iv_words=None, data_words=None, mode=1, keylen=1):
    """跑一次完整 AES 操作（mode: 1=encrypt, keylen: 1=128, 2=192, 4=256 one-hot）"""
    api.pf_reset()
    api.pf_step(5)
    # CTRL_SHADOWED: mode[6:5], key_len[4:3], 0x9 = manual operation?
    # 老版 aes: operation[7:6], mode[5:3], key_len[2:1], PRNG reseed 等
    ctrl = (mode << 6) | (1 << 3) | (keylen << 1)  # enc, CTR?, key len
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)  # shadow 两阶段
    # 写 key
    for i, w in enumerate(key_words):
        api.pf_write(BASE + KEY_SHARE0_0 + 4 * i, w, 0xF)
        api.pf_write(BASE + KEY_SHARE1_0 + 4 * i, 0, 0xF)
    # 写 IV（如果 CTR/CBC）
    if iv_words:
        for i, w in enumerate(iv_words):
            api.pf_write(BASE + 0x44 + 4 * i, w, 0xF)  # IV_0 offset=0x44
    # 写 data in
    if data_words:
        for i, w in enumerate(data_words):
            api.pf_write(BASE + DATA_IN_0 + 4 * i, w, 0xF)
    # 触发 start
    api.pf_write(BASE + TRIGGER, 0x1, 0xF)  # start
    # 等待 output_valid
    ok = wait_status(0x4, 0x4, 8000)  # STATUS.output_valid?
    return ok

def main():
    print("=" * 70)
    print("AES-ctf 剩余 bug 批量检测: Bug#82/32/6/9/31/34")
    print("=" * 70)

    api.pf_init(0)
    key = [0xDEADBEEF] * 8
    data = [0xCAFEBABE] * 4

    # ---- Bug#82: KEY_FULL_CLEAR/KEY_DEC_CLEAR 加载 key_expand_out ----
    print("\n[Bug#82] KEY_FULL/DEC_CLEAR 擦除变注入:")
    ok = run_aes_op(key, data_words=data)
    print("  AES 操作完成: %s" % ok)
    kf = wb("u_dut.key_full_q", 8)
    kd = wb("u_dut.key_dec_q", 8)
    print("  key_full_q = %s" % " ".join("%08x" % w for w in kf))
    print("  key_dec_q  = %s" % " ".join("%08x" % w for w in kd))
    # 触发 clear（CTRL 里触发 cipher clear? TRIGGER.clear?）
    # 老版 aes TRIGGER: start[0], key_iv_data_in_clear[1], prng_reseed[2]
    api.pf_write(BASE + TRIGGER, 0x2, 0xF)  # key_iv_data_in_clear
    api.pf_step(200)
    kf2 = wb("u_dut.key_full_q", 8)
    kd2 = wb("u_dut.key_dec_q", 8)
    print("  CLEAR 后 key_full_q = %s" % " ".join("%08x" % w for w in kf2))
    print("  CLEAR 后 key_dec_q  = %s" % " ".join("%08x" % w for w in kd2))
    # 判定: clear 后应全 0（prd_clearing）或随机；若含 key_expand_out（与 clear 前相关）→ VIOLATION
    kf_nonzero = any(w != 0 for w in kf2)
    print("  → %s" % ("VIOLATION: CLEAR 后 key_full_q 非零（密钥材料残留/再注入）" if kf_nonzero else "key_full_q 已清"))

    # ---- Bug#32: data_out reset 条件化 ----
    print("\n[Bug#32] data_out reset 条件化（复位期间 we 高 → 残留）:")
    # 先跑一次操作让 data_out_q 有值
    ok = run_aes_op(key, data_words=data)
    do = wb("u_dut.data_out_q", 4)
    print("  操作后 data_out_q = %s" % " ".join("%08x" % w for w in do))
    # 复位（harness 的 pf_reset 直接拉 rst_ni）
    api.pf_reset()
    api.pf_step(5)
    do2 = wb("u_dut.data_out_q", 4)
    print("  复位后 data_out_q = %s" % " ".join("%08x" % w for w in do2))
    if any(w != 0 for w in do2):
        print("  → VIOLATION: 复位后 data_out_q 残留（reset 条件化）")
    else:
        print("  → 复位后已清零")

    api.pf_final()
    print("\ndone")

if __name__ == "__main__":
    main()
