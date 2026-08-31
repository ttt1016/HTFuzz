#!/usr/bin/env python3
"""AES-ctf Bug#6/9: key_expand 注入 → O2 NIST SP800-38A AES-128 比对"""
import ctypes, os
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

BASE = 0x41100000
CTRL_SHADOWED = 0x74
TRIGGER       = 0x80
STATUS        = 0x84
KEY_SHARE0_0  = 0x4
KEY_SHARE1_0  = 0x24
DATA_IN_0     = 0x54
DATA_OUT_0    = 0x64

# NIST SP800-38A F.1.1 AES-128 ECB
NIST_KEY  = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]
NIST_PT   = [0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a]
NIST_CT   = [0x3ad77bb4, 0x0d7a3660, 0xa89ecaf3, 0x2466ef97]

def sig(name, w=0):
    return api.pf_sig_read(name.encode(), w)

def main():
    print("=" * 70)
    print("AES-ctf Bug#6/9: key_expand 注入 → NIST AES-128 比对")
    print("=" * 70)
    api.pf_init(0)
    api.pf_reset()
    api.pf_step(5)
    # masking PRNG reseed（SecMasking=1 必需）
    api.pf_write(BASE + TRIGGER, 0x8, 0xF)
    for _ in range(2000):
        api.pf_step(20)
        if api.pf_read(BASE + STATUS) & 0x1:
            break

    # CTRL_SHADOWED 位布局: operation[1:0], mode[7:2], key_len[10:8]
    # CIPH_FWD=01, AES_ECB=000001, AES_128=001
    ctrl = 0b01 | (0b000001 << 2) | (0b001 << 8) | (1 << 15)  # + manual_operation
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)

    for i, w in enumerate(NIST_KEY):
        api.pf_write(BASE + KEY_SHARE0_0 + 4 * i, w, 0xF)
        api.pf_write(BASE + KEY_SHARE1_0 + 4 * i, 0, 0xF)
    for i, w in enumerate(NIST_PT):
        api.pf_write(BASE + DATA_IN_0 + 4 * i, w, 0xF)

    api.pf_write(BASE + TRIGGER, 0x1, 0xF)
    ok = False
    for _ in range(8000):
        api.pf_step(1)
        st = api.pf_read(BASE + STATUS)
        if st & 0x8:  # output_valid = bit3
            ok = True
            break
    print("操作完成: %s  STATUS=0x%x" % (ok, api.pf_read(BASE + STATUS)))

    ct = [api.pf_read(BASE + DATA_OUT_0 + 4 * i) for i in range(4)]
    print("密文 = %s" % " ".join("%08x" % w for w in ct))
    print("NIST = %s" % " ".join("%08x" % w for w in NIST_CT))
    if ct == NIST_CT:
        print("→ O2 PASS: 密文与 NIST 一致（key_expand 正常）")
    else:
        print("→ O2 VIOLATION: 密文与 NIST 不一致（key_expand 注入生效）")
        # 白盒: key_full_q 第一轮
        kf = [sig("u_dut.key_full_q", w) for w in range(8)]
        print("key_full_q = %s" % " ".join("%08x" % w for w in kf))

    api.pf_final()

if __name__ == "__main__":
    main()
