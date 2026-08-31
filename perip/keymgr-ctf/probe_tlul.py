#!/usr/bin/env python3
"""TLUL 通路探测"""
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
api.pf_sig_read.argtypes = [ctypes.c_int, ctypes.c_int]

api.pf_init()
api.pf_reset()
api.pf_step(20)

# INTR_STATE @0x0: 读应为 0
v = api.pf_read(0x0)
print("INTR_STATE = 0x%x (期望 0x0)" % v)
# INTR_ENABLE @0x4
v = api.pf_read(0x4)
print("INTR_ENABLE = 0x%x (期望 0x0)" % v)
# CFG_REGWEN @0x10: 复位值 1
v = api.pf_read(0x10)
print("CFG_REGWEN = 0x%x (期望 0x1)" % v)
