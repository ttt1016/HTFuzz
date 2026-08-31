#!/usr/bin/env python3
"""AES-ctf Bug#81 精确检测: KEY_SHARE0 写后读回（q 直通）"""
import ctypes

lib = ctypes.CDLL("/workspace/pickerfuzz/perip/aes-ctf/obj_so/liblibpf_aes_ctf.so")
lib.pf_init.argtypes = [ctypes.c_uint]
lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
lib.pf_write.restype = ctypes.c_int
lib.pf_read.argtypes = [ctypes.c_uint32]
lib.pf_read.restype = ctypes.c_uint32
BASE = 0x41100000

print("[Bug#81 检测] KEY_SHARE0 写后读回（q 直通）:")
lib.pf_init(0)
lib.pf_write(BASE + 0x4, 0xDEADBEEF, 0xF)   # KEY_SHARE0_0
val = lib.pf_read(BASE + 0x4)
print("  写 0xDEADBEEF → 读回 %s" % hex(val))
if val == 0xDEADBEEF:
    print("  *** [O1-VIOLATION] 密钥可读回 (Bug#81: SW_UNREADABLE 失效) ***")
else:
    print("  → 不可读回（读回值可能是 hw2reg 回写值）")

# 也测 KEY_SHARE1 和 DATA_IN
for name, off in [("KEY_SHARE1_0", 0x24), ("DATA_IN_0", 0x54)]:
    lib.pf_write(BASE + off, 0xCAFEBABE, 0xF)
    v = lib.pf_read(BASE + off)
    print("  %s 写 0xCAFEBABE → 读回 %s %s" % (name, hex(v),
          "*** 可读回! ***" if v == 0xCAFEBABE else ""))
lib.pf_final()
