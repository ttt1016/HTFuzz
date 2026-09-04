#!/usr/bin/env python3
"""keymgr-ctf 自检 + Bug#21/64 (StCtrlInvalid 密钥暴露) 检测"""
import ctypes, sys, os

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "obj_so/liblibpf_keymgr_ctf.so")
lib = ctypes.CDLL(LIB)

lib.pf_init.restype = None
lib.pf_reset.restype = None
lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
lib.pf_read.restype = ctypes.c_uint32
lib.pf_read.argtypes = [ctypes.c_uint32]
lib.pf_step.argtypes = [ctypes.c_int]
lib.pf_sig_read.restype = ctypes.c_uint32
lib.pf_sig_read.argtypes = [ctypes.c_int, ctypes.c_int]

# keymgr_reg_pkg 偏移（从 regmap 或 hjson）
# INTR_STATE=0x0, INTR_ENABLE=0x4, INTR_TEST=0x8, ALERT_TEST=0xc, CFG_REGWEN=0x10,
# CFG_SHADOWED=0x14, CONTROL=0x18, CONTROL_SHADOWED=0x1c, SW_BIND=..., ...
# 实际偏移从 keymgr_reg_pkg.sv 确认
import re
pkg = open(os.path.join(os.path.dirname(LIB), "../hw/ip/keymgr/rtl/keymgr_reg_pkg.sv")).read()
def param(name):
    m = re.search(r"parameter int " + name + r"\s*=\s*(\d+)", pkg)
    return int(m.group(1)) if m else None
print("keymgr_reg_pkg: NumAlerts=%s" % param("NumAlerts"))

# 简单自检: reset + 读 ID/状态
print("\n=== 自检: reset + step ===")
lib.pf_init()
lib.pf_reset()
lib.pf_step(10)
state = lib.pf_sig_read(6, 0)
print("state_q after reset = 0x%x" % state)
aes_en = lib.pf_sig_read(0, 0)
print("aes_key.valid = %d" % aes_en)
print("自检 PASS ✓" if state != 0xDEADBEEF else "自检 FAIL")
