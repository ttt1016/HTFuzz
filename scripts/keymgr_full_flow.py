#!/usr/bin/env python3
"""
keymgr 完整 key derivation 流程 fuzzing —— 走完 6 个操作状态后触发异常路径

流程:
  Init(Advance) → CreatorRootKey(Advance) → OwnerIntKey(Advance) → OwnerKey
  每阶段: 写 binding/salt/key_version → CONTROL_SHADOWED(op=Advance, shadow 2次) → START
  最终: GenSwOut → 读 SW_SHARE0_OUTPUT（派生密钥）
  异常路径: 在各阶段触发 sideload_clear / invalid key_version / wipe

用法:
  python3 keymgr_full_flow.py perip/keymgr-ctf keymgr traces/keymgr_regmap.json
"""

import os
import sys

PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")
OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")

# 寄存器偏移（从 reg_pkg.sv 提取）
R = {
    "intr_state": 0x0,
    "cfg_regwen": 0x10,
    "start": 0x14,
    "control_shadowed": 0x18,
    "sideload_clear": 0x1C,
    "sw_binding_regwen": 0x28,
    "sealing_sw_binding_0": 0x2C,
    "sealing_sw_binding_7": 0x48,
    "attest_sw_binding_0": 0x4C,
    "salt_0": 0x6C,
    "salt_7": 0x88,
    "key_version": 0x8C,
    "sw_share0_output_0": 0xA8,
    "sw_share1_output_0": 0xC8,
    "op_status": 0xEC,
}

# 操作编码
OP_ADVANCE = 0
OP_GEN_ID = 1
OP_GEN_SW_OUT = 2
OP_GEN_HW_OUT = 3

# 状态编码（sparse FSM）
ST = {
    "Reset": 0b1101100001,
    "EntropyReseed": 0b1110010010,
    "Random": 0b0011110100,
    "RootKey": 0b0110101111,
    "Init": 0b0100000100,
    "CreatorRootKey": 0b1000011101,
    "OwnerIntKey": 0b0001001010,
    "OwnerKey": 0b1101111110,
    "Disabled": 0b1010101000,
    "Invalid": 0b1011000111,
}


def load_dut(dut_dir, module):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from llm_agent import DutHandle

    return DutHandle(dut_dir, module)


def wait_op_done(dut, max_wait=500):
    """等 op_status done"""
    for _ in range(max_wait // 10):
        dut.step(10)
        st = dut.read(R["op_status"])
        val = st.get("value", 0) if isinstance(st, dict) else st
        if val & 0x1:  # done bit
            return val
    return 0


def read_sw_output(dut):
    """读 SW_SHARE0_OUTPUT 8 words"""
    out = []
    for i in range(8):
        r = dut.read(0xA8 + i * 4)
        val = r.get("value", 0) if isinstance(r, dict) else r
        out.append(val)
    return out


def keymgr_full_flow(dut, verbose=True):
    """执行完整 key derivation 流程，返回每阶段状态"""
    stages = []

    def log(stage, state):
        try:
            v = int(state) if isinstance(state, str) else state
            stages.append({"stage": stage, "state": hex(v)})
            if verbose:
                print(f"  [{stage}] state={hex(v)}")
        except (ValueError, TypeError):
            stages.append({"stage": stage, "state": str(state)})
            if verbose:
                print(f"  [{stage}] state={state}")

    def read_state():
        for name in dut.sigs:
            if "state" in name.lower():
                return dut.sig_read(name)
        return {"words": [0]}

    dut.reset()
    dut.step(20)

    # === 阶段 0: Reset → EntropyReseed → Random → RootKey（硬件自动）===
    dut.step(100)  # 等硬件完成初始状态转移
    st = read_state()
    log("after_reset", int(st["words"][0], 0) if st.get("words") else 0)

    # === 阶段 1: Init（写 binding/salt/version + Advance）===
    # 解锁 CFG
    dut.write(R.get("cfg_regwen", 0x10), 1)
    dut.step(2)
    # 写 SEALING_SW_BINDING (8 words)
    for i in range(8):
        dut.write(0x2C + i * 4, 0xDEADBEEF + i)
    # 写 SALT (8 words)
    for i in range(8):
        dut.write(0x6C + i * 4, 0xCAFEBABE + i)
    # 写 KEY_VERSION
    dut.write(0x8C, 0x1)
    dut.step(5)
    # Advance: CONTROL_SHADOWED = op=0, cdi=0, dest=0 → 0x0（shadow 写两次）
    shadow_write(dut, R["control_shadowed"], 0x0)
    # START
    dut.write(R["start"], 1)
    st = wait_op_done(dut)
    st_state = read_state()
    log("after_init_advance", int(st_state["words"][0], 0) if st_state.get("words") else 0)

    # === 阶段 2: CreatorRootKey → Advance → OwnerIntKey ===
    # 更新 binding/salt（可选，用不同值）
    for i in range(8):
        dut.write(0x2C + i * 4, 0x12345678 + i)
    dut.write(0x8C, 0x2)
    shadow_write(dut, R["control_shadowed"], 0x0)  # Advance again
    dut.write(R["start"], 1)
    st = wait_op_done(dut)
    st_state = read_state()
    log("after_creator_advance", int(st_state["words"][0], 0) if st_state.get("words") else 0)

    # === 阶段 3: OwnerIntKey → Advance → OwnerKey ===
    dut.write(0x8C, 0x3)
    shadow_write(dut, R["control_shadowed"], 0x0)
    dut.write(R["start"], 1)
    st = wait_op_done(dut)
    st_state = read_state()
    log("after_owner_advance", int(st_state["words"][0], 0) if st_state.get("words") else 0)

    # === 阶段 4: GenSwOut（生成软件输出密钥）===
    shadow_write(dut, R["control_shadowed"], 0x2)  # op=GenSwOut, cdi=0
    dut.write(R["start"], 1)
    st = wait_op_done(dut)
    sw_out = read_sw_output(dut)
    log("gen_sw_out", st)
    if verbose:
        print(f"  [SW_OUTPUT] {[hex(x) for x in sw_out[:4]]}")

    # === 异常路径 1: sideload_clear（清 sideload 密钥）===
    dut.write(R.get("sideload_clear", 0x1C), 0x1)
    dut.step(20)

    # === 异常路径 2: 在 OwnerKey 状态触发 Advance with invalid key_version ===
    dut.write(0x8C, 0xFFFFFFFF)  # invalid version
    shadow_write(dut, R["control_shadowed"], 0x0)
    dut.write(R["start"], 1)
    st = wait_op_done(dut)
    st_state = read_state()
    log("after_invalid_advance", int(st_state["words"][0], 0) if st_state.get("words") else 0)

    # === 异常路径 3: sideload_clear + wipe ===
    dut.write(R.get("sideload_clear", 0x1C), 0xF)
    dut.step(50)
    st_state = read_state()
    log("after_sideload_clear", int(st_state["words"][0], 0) if st_state.get("words") else 0)

    return stages


def shadow_write(dut, addr, value):
    """shadow 寄存器写：写两次相同值"""
    dut.write(addr, value)
    dut.step(2)
    dut.write(addr, value)
    dut.step(2)


verbose = True


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("dut_dir")
    ap.add_argument("module")
    ap.add_argument("regmap_path")
    args = ap.parse_args()

    print("=== keymgr 完整 key derivation 流程 fuzzing ===")
    dut = load_dut(args.dut_dir, args.module)

    # 白盒信号
    print(f"白盒信号: {list(dut.sigs.keys())[:10]}")

    # 执行完整流程
    keymgr_full_flow(dut)

    # 关键观测：各阶段状态 + 密钥残留
    print("\n=== 关键白盒信号观测 ===")
    for sig in ["u_dut.key_state_q", "u_dut.key_state_d", "u_dut.trng_state_q"]:
        for name in dut.sigs:
            if sig.split(".")[-1] in name:
                v = dut.sig_read(name)
                nz = [(i, w) for i, w in enumerate(v.get("words", [])) if w != "0x0"]
                print(f"  {name}: {'非零 ' + str(nz[:4]) if nz else '全零'}")
                break

    # 检查 StCtrlInvalid 后密钥是否清零（Bug#21/64）
    print("\n=== StCtrlInvalid 密钥暴露检查 ===")
    for sig in ["u_dut.key_state_q", "u_dut.trng_state_q"]:
        tail = sig.split(".")[-1]
        for name in dut.sigs:
            if tail in name:
                v = dut.sig_read(name)
                nz = [(i, w) for i, w in enumerate(v.get("words", [])) if w != "0x0"]
                if nz:
                    print(f"  [LEAK?] {name}: 非零 {nz[:4]}")
                else:
                    print(f"  [ok] {name}: 全零")
                break


if __name__ == "__main__":
    main()
