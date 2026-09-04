#!/usr/bin/env python3
"""AES-ctf Bug#32: data_out reset 条件化（!rst_ni && data_out_we != SP2V_HIGH）
检测: 跑 AES 操作，在 data_out_we=SP2V_HIGH 的拍拉低复位 → data_out_q 应清零
  fork:  复位被 we 阻止 → data_out_q 残留密文
  clean: 无条件复位 → data_out_q = 0
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
api.pf_reset_at_we.restype = ctypes.c_int
api.pf_reset_at_we.argtypes = [ctypes.c_char_p]

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
    print("AES-ctf Bug#32: data_out reset 条件化")
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

    ctrl = 0b01 | (0b000001 << 2) | (0b001 << 8) | (1 << 15)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_step(3)
    api.pf_write(BASE + CTRL_SHADOWED, ctrl, 0xF)
    api.pf_step(3)
    for i, w in enumerate([0xDEADBEEF] * 4):
        api.pf_write(BASE + KEY_SHARE0_0 + 4 * i, w, 0xF)
        api.pf_write(BASE + KEY_SHARE1_0 + 4 * i, 0, 0xF)
    for i, w in enumerate([0xCAFEBABE] * 4):
        api.pf_write(BASE + DATA_IN_0 + 4 * i, w, 0xF)

    # start，等 output_valid（此时 data_out_we 会脉冲）
    api.pf_write(BASE + TRIGGER, 0x1, 0xF)
    ok = False
    for _ in range(4000):
        api.pf_step(20)
        if api.pf_read(BASE + STATUS) & 0x8:
            ok = True
            break
    print("AES 操作完成: %s" % ok)

    do_before = wb("u_dut.data_out_q", 4)
    print("复位前 data_out_q = %s" % " ".join("%08x" % w for w in do_before))

    # 重新跑一次操作，在 data_out_we 高的拍精确复位
    api.pf_write(BASE + TRIGGER, 0x1, 0xF)
    hit = api.pf_reset_at_we(b"u_dut.data_out_we")
    print("在 data_out_we=HIGH 时复位: %s" % bool(hit))

    do_after = wb("u_dut.data_out_q", 4)
    print("复位后 data_out_q = %s" % " ".join("%08x" % w for w in do_after))

    print("\n=== 判定 ===")
    if hit and any(w != 0 for w in do_after):
        print("→ VIOLATION: Bug#32 确认！")
        print("  data_out_we=HIGH 期间复位，data_out_q 残留密文（应清零）")
        print("  注入: if (!rst_ni && data_out_we != SP2V_HIGH) data_out_q <= 0;")
        print("  clean: if (!rst_ni) data_out_q <= 0;（无条件复位）")
        print("  → 攻击者在输出更新瞬间触发复位可保留旧密文（CWE-1259/449）")
    elif hit:
        print("→ 复位后 data_out_q 已清零（clean 行为）")
    else:
        print("→ 未捕获 data_out_we 脉冲（时序窗口问题）")

    api.pf_final()

if __name__ == "__main__":
    main()
