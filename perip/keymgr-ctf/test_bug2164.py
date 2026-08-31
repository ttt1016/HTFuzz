#!/usr/bin/env python3
"""keymgr Bug#21/64 检测: 直接白盒读 u_ctrl.key_o（key_output_ctrl 输出）
sig 编号:
  6  = state_q
  8  = key_state_q[cdi][share][word]  idx = (word<<8)|(share<<4)|cdi
  35 = u_ctrl.key_o.key[share][word]  idx = (share<<8)|word
  36 = u_ctrl.key_o.valid
  37 = stage_sel_o
  38 = invalid_stage_sel_o
  39 = lfsr[63:32]
"""
import ctypes, os

BASE = os.path.dirname(os.path.abspath(__file__))
dut = ctypes.CDLL(os.path.join(BASE, "obj_so/liblibpf_keymgr_ctf.so"), mode=ctypes.RTLD_GLOBAL)
api = ctypes.CDLL(os.path.join(BASE, "obj_so/libpf_keymgr_ctf_api.so"), mode=ctypes.RTLD_GLOBAL)

api.pf_init.restype = None
api.pf_reset.restype = None
api.pf_step.argtypes = [ctypes.c_int]
api.pf_sig_read.restype = ctypes.c_uint32
api.pf_sig_read.argtypes = [ctypes.c_int, ctypes.c_int]

STATES = {
    0b1101100001: "StCtrlReset",
    0b1110010010: "StCtrlEntropyReseed",
    0b0011110100: "StCtrlRandom",
    0b0110101111: "StCtrlRootKey",
    0b0100000100: "StCtrlInit",
    0b1000011101: "StCtrlCreatorRootKey",
    0b0001001010: "StCtrlOwnerIntKey",
    0b1101111110: "StCtrlOwnerKey",
    0b1010101000: "StCtrlDisabled",
    0b0000110011: "StCtrlWipe",
    0b1011000111: "StCtrlInvalid",
}

def state_name(v):
    return STATES.get(v & 0x3FF, "Unknown(0x%x)" % (v & 0x3FF))

def main():
    print("=" * 70)
    print("keymgr Bug#21/64: StCtrlInvalid key exposure (u_ctrl.key_o whitebox)")
    print("=" * 70)

    api.pf_init()
    api.pf_reset()
    api.pf_step(20)

    st = api.pf_sig_read(6, 0)
    inv_sel = api.pf_sig_read(38, 0)
    stage = api.pf_sig_read(37, 0)
    print("\nstate=%s invalid_stage_sel=%d stage_sel=%d" % (
        state_name(st), inv_sel, stage))

    # key_state_q
    ks = {}
    for cdi in range(2):
        for share in range(2):
            words = [api.pf_sig_read(8, (word << 8) | (share << 4) | cdi)
                     for word in range(8)]
            ks[(cdi, share)] = words
            print("key_state_q[cdi=%d][share=%d] = %s" % (
                cdi, share, " ".join("%08x" % w for w in words)))

    # u_ctrl.key_o（key_output_ctrl 直接输出）
    print()
    for share in range(2):
        words = [api.pf_sig_read(35, (share << 8) | word) for word in range(8)]
        print("u_ctrl.key_o.key[share=%d] = %s" % (
            share, " ".join("%08x" % w for w in words)))
    print("u_ctrl.key_o.valid = %d" % api.pf_sig_read(36, 0))
    print("lfsr[63:32] = 0x%08x" % api.pf_sig_read(39, 0))

    # 多次采样
    print("\n=== 多次采样 u_ctrl.key_o（间隔 50 拍）===")
    samples = []
    for i in range(5):
        api.pf_step(50)
        k0 = [api.pf_sig_read(35, word) for word in range(8)]
        k1 = [api.pf_sig_read(35, (1 << 8) | word) for word in range(8)]
        samples.append((k0, k1))
        print("sample %d share0 = %s" % (i, " ".join("%08x" % w for w in k0)))
        print("sample %d share1 = %s" % (i, " ".join("%08x" % w for w in k1)))

    # 判定
    print("\n=== 判定 ===")
    st = api.pf_sig_read(6, 0)
    in_invalid = (st & 0x3FF) == 0b1011000111

    s0 = [k[0] for k in samples]
    s1 = [k[1] for k in samples]
    share0_matches_ks = all(k == ks[(0, 0)] for k in s0)
    share1_matches_ks = all(k == ks[(0, 1)] for k in s1)
    changing = any(samples[i] != samples[0] for i in range(1, len(samples)))

    if in_invalid:
        print("状态: StCtrlInvalid ✓  invalid_stage_sel=%d" % inv_sel)
        if share0_matches_ks and share1_matches_ks:
            print("u_ctrl.key_o == key_state_q（未掩码密钥直接输出）")
            print("→ VIOLATION: Bug#21/64 注入确认！")
            print("  注入代码: if(invalid_stage_sel_o && state==StCtrlInvalid)")
            print("            key_o.key[i] = key_state_q[cdi_sel_o][i]  (跳过 entropy XOR)")
            print("  clean 行为: key_o.key = {EntropyRounds{entropy_i[i]}} (LFSR 随机掩码)")
        elif changing:
            print("u_ctrl.key_o 随 LFSR 变化 → entropy 掩码正常 → 安全")
        else:
            print("u_ctrl.key_o 恒定: share0==key_state_q? %s  share1==key_state_q? %s" % (
                share0_matches_ks, share1_matches_ks))
    else:
        print("状态: %s（非 Invalid）" % state_name(st))

    print("\ndone")

if __name__ == "__main__":
    main()
