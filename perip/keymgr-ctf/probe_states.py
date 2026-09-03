#!/usr/bin/env python3
"""keymgr 状态机探测: 驱动到 StCtrlInvalid"""
import ctypes, os

BASE = os.path.dirname(os.path.abspath(__file__))
dut = ctypes.CDLL(os.path.join(BASE, "obj_so/liblibpf_keymgr_ctf.so"), mode=ctypes.RTLD_GLOBAL)
api = ctypes.CDLL(os.path.join(BASE, "obj_so/libpf_keymgr_ctf_api.so"), mode=ctypes.RTLD_GLOBAL)

api.pf_init.restype = None
api.pf_reset.restype = None
api.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
api.pf_write.restype = None
api.pf_read.restype = ctypes.c_uint32
api.pf_read.argtypes = [ctypes.c_uint32]
api.pf_step.argtypes = [ctypes.c_int]
api.pf_sig_read.restype = ctypes.c_uint32
api.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]

# sparse 编码
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

CFG_REGWEN        = 0x10
CFG_SHADOWED      = 0x14
CONTROL           = 0x18
CONTROL_SHADOWED  = 0x1C

api.pf_init()
api.pf_reset()
api.pf_step(20)
st = api.pf_sig_read(b"state", 0)
print("after reset: %s (0x%x)" % (state_name(st), st))

# 读寄存器看写入是否生效
print("\nCFG_REGWEN = 0x%x" % api.pf_read(CFG_REGWEN))
api.pf_write(CFG_SHADOWED, 0x9)
api.pf_step(5)
print("CFG_SHADOWED readback = 0x%x" % api.pf_read(CFG_SHADOWED))
api.pf_write(CONTROL_SHADOWED, 0x0)
api.pf_write(CONTROL, 0x1)
api.pf_step(20)
print("CONTROL readback = 0x%x" % api.pf_read(CONTROL))

for i in range(15):
    api.pf_step(200)
    st = api.pf_sig_read(b"state", 0)
    print("step %d: %s" % (i, state_name(st)))
