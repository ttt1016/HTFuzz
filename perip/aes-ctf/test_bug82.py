#!/usr/bin/env python3
"""AES-ctf Bug#82: KEY_FULL_CLEAR/KEY_DEC_CLEAR 加载 key_expand_out（密钥材料）
检测: 完整 AES 操作 → 触发 key_iv_data_in_clear → 白盒读 key_full_q/key_dec_q
  fork:  CLEAR 后 key_full_q = key_expand_out（密钥材料，与 key 相关）
  clean: CLEAR 后 key_full_q = prd_clearing_key（随机/零，与 key 无关）
"""
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

def sig(name, w=0):
    return api.pf_sig_read(name.encode(), w)

def wb(name, words):
    return [sig(name, w) for w in range(words)]

def main():
    print("=" * 70)
    print("AES-ctf Bug#82: KEY_FULL/DEC_CLEAR 擦除变注入")
    print("=" * 70)
    api.pf_init(0)
    api.pf_reset()
    api.pf_step(5)

    # prng reseed
    api.pf_write(BASE + TRIGGER, 0x8, 0xF)
    for _ in range(2000):
        api.pf_step(20)
        if api.pf_read(BASE + STATUS) & 0x1:
            break

    # CTRL: FWD + ECB + 128 + manual
    ctrl = 0b01 | (0b000001 << 2) | (0b001 << 8) | (1 << 15)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_step(3)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_step(3)

    # key = 0xDEADBEEF ×4（特征值，便于识别残留）
    key = [0xDEADBEEF] * 4
    for i, w in enumerate(key):
        api.pf_write(BASE + KEY_SHARE0_0 + 4 * i, w, 0xF)
        api.pf_write(BASE + KEY_SHARE1_0 + 4 * i, 0, 0xF)
    data = [0xCAFEBABE] * 4
    for i, w in enumerate(data):
        api.pf_write(BASE + DATA_IN_0 + 4 * i, w, 0xF)

    # start
    api.pf_write(BASE + TRIGGER, 0x1, 0xF)
    ok = False
    for _ in range(4000):
        api.pf_step(20)
        if api.pf_read(BASE + STATUS) & 0x8:
            ok = True
            break
    print("AES 操作完成: %s" % ok)

    kf_before = wb("u_dut.key_full_q", 8)
    kd_before = wb("u_dut.key_dec_q", 8)
    print("CLEAR 前 key_full_q = %s" % " ".join("%08x" % w for w in kf_before))
    print("CLEAR 前 key_dec_q  = %s" % " ".join("%08x" % w for w in kd_before))

    # 触发 key_iv_data_in_clear
    api.pf_write(BASE + TRIGGER, 0x2, 0xF)
    api.pf_step(400)

    kf_after = wb("u_dut.key_full_q", 8)
    kd_after = wb("u_dut.key_dec_q", 8)
    print("CLEAR 后 key_full_q = %s" % " ".join("%08x" % w for w in kf_after))
    print("CLEAR 后 key_dec_q  = %s" % " ".join("%08x" % w for w in kd_after))

    # 判定: clean 的 KEY_FULL_CLEAR/KEY_DEC_CLEAR 加载 prd_clearing_key（独立 LFSR 随机）
    # fork 加载 key_expand_out（密钥扩展输出）
    # 决定性特征: fork 下 CLEAR 后 key_dec_q == key_full_q（同一 key_expand_out 填充两个寄存器）
    # clean 下两者是独立随机值，不可能完全相同
    print("\n=== 判定 ===")
    nonzero = any(w != 0 for w in kf_after)
    same = (kd_after == kf_after)
    print("CLEAR 后 key_dec_q == key_full_q ? %s" % same)
    if nonzero and same:
        print("→ VIOLATION: Bug#82 确认！")
        print("  CLEAR 后 key_full_q 与 key_dec_q 被同一密钥材料（key_expand_out）填充")
        print("  注入: KEY_FULL_CLEAR: key_full_d = key_expand_out; KEY_DEC_CLEAR: key_dec_d = key_expand_out")
        print("  clean: 两者应加载独立的 prd_clearing_key（LFSR 随机，不可能相同）")
        print("  → SEC_CM: KEY.SEC_WIPE 失效，密钥材料在擦除操作中被写入密钥寄存器")
    elif nonzero:
        print("→ key_full_q 非零但 key_dec_q != key_full_q（可能是 prd_clearing 随机）")
    else:
        print("→ 已清零")

    api.pf_final()

if __name__ == "__main__":
    main()
