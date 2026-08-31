#!/usr/bin/env python3
"""clean aes 对照: Bug#82/32"""
import ctypes, os
os.chdir("/workspace/pickerfuzz/perip/aes")
dut = ctypes.CDLL("liblibpf_aes.so", mode=ctypes.RTLD_GLOBAL)
api = ctypes.CDLL("liblibpf_aes_new.so", mode=ctypes.RTLD_GLOBAL)
api.pf_init.argtypes = [ctypes.c_uint]
api.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
api.pf_write.restype = ctypes.c_int
api.pf_read.restype = ctypes.c_uint32
api.pf_read.argtypes = [ctypes.c_uint32]
api.pf_step.argtypes = [ctypes.c_int]
api.pf_sig_read.restype = ctypes.c_uint32
api.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]

BASE = 0x41100000
CTRL_SHADOWED = 0x24
TRIGGER       = 0x14
STATUS        = 0x1C
KEY_SHARE0_0  = 0x44
KEY_SHARE1_0  = 0x64
DATA_IN_0     = 0x84

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

def run_aes_op(key_words, data_words, ctrl):
    api.pf_reset()
    api.pf_step(5)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    for i, w in enumerate(key_words):
        api.pf_write(BASE + KEY_SHARE0_0 + 4 * i, w, 0xF)
        api.pf_write(BASE + KEY_SHARE1_0 + 4 * i, 0, 0xF)
    for i, w in enumerate(data_words):
        api.pf_write(BASE + DATA_IN_0 + 4 * i, w, 0xF)
    api.pf_write(BASE + TRIGGER, 0x1, 0xF)
    return wait_status(0x4, 0x4, 8000)

print("=" * 70)
print("clean aes 对照: Bug#82/32")
print("=" * 70)
api.pf_init(0)
key = [0xDEADBEEF] * 8
data = [0xCAFEBABE] * 4
ctrl = (1 << 6) | (1 << 3) | (1 << 1)

print("\n[Bug#82 对照] KEY_FULL/DEC_CLEAR:")
ok = run_aes_op(key, data, ctrl)
print("  AES 操作完成: %s" % ok)
kf = wb("u_dut.key_full_q", 8)
print("  key_full_q = %s" % " ".join("%08x" % w for w in kf))
api.pf_write(BASE + TRIGGER, 0x2, 0xF)
api.pf_step(200)
kf2 = wb("u_dut.key_full_q", 8)
kd2 = wb("u_dut.key_dec_q", 8)
print("  CLEAR 后 key_full_q = %s" % " ".join("%08x" % w for w in kf2))
print("  CLEAR 后 key_dec_q  = %s" % " ".join("%08x" % w for w in kd2))
if any(w != 0 for w in kf2):
    print("  → key_full_q 非零（可能是 prd_clearing 随机值，需与 fork 对比模式）")
else:
    print("  → key_full_q 已清零（clean 行为）")

api.pf_final()
print("\ndone")
