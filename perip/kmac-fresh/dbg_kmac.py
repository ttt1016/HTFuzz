#!/usr/bin/env python3
"""kmac 手动操作调试: 触发 KMAC 看掩码信号"""
import ctypes, os, json
os.chdir("/workspace/pickerfuzz/perip/kmac-ctf")
lib = ctypes.CDLL("./obj_so/liblibpf_kmac_ctf.so", mode=ctypes.RTLD_GLOBAL)
lib.pf_init.argtypes = [ctypes.c_uint]
lib.pf_init.restype = ctypes.c_int
lib.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
lib.pf_write.restype = ctypes.c_int
lib.pf_read.restype = ctypes.c_uint32
lib.pf_read.argtypes = [ctypes.c_uint32]
lib.pf_step.argtypes = [ctypes.c_int]
lib.pf_sig_value.restype = ctypes.c_uint32
lib.pf_sig_value.argtypes = [ctypes.c_int, ctypes.c_int]
lib.pf_sig_name.restype = ctypes.c_char_p
lib.pf_sig_name.argtypes = [ctypes.c_int]
lib.pf_sig_words.restype = ctypes.c_int
lib.pf_sig_words.argtypes = [ctypes.c_int]
lib.pf_init(0)
n = int(lib.pf_sig_count())
names = [lib.pf_sig_name(i).decode() for i in range(n)]
print("sigs:", names)
rm = json.load(open("/workspace/pickerfuzz/traces/kmac_regmap.json"))
offs = {}
for e in rm:
    if isinstance(e, dict) and e.get("name") and e.get("offset") is not None:
        off = e["offset"]
        offs[e["name"]] = int(off, 0) if isinstance(off, str) else off
print("regs:", list(offs.keys())[:12])
BASE = 0x41110000
cfg_off = offs.get("CFG_SHADOWED")
print("CFG_SHADOWED =", hex(cfg_off))
# CFG: kstrength=L256(1)<<1 | mode=SHA3(0)<<4 | msg_mask(1<<20) | entropy_ready(1<<24)
cfg_val = (1 << 1) | (0 << 4) | (1 << 20) | (1 << 24)
lib.pf_write(BASE + cfg_off, cfg_val, 0xF)
lib.pf_step(3)
lib.pf_write(BASE + cfg_off, cfg_val, 0xF)
lib.pf_step(3)
print("CFG readback = 0x%x" % lib.pf_read(BASE + cfg_off))
# CMD.start
for k, v in offs.items():
    if "CMD" in k.upper():
        lib.pf_write(BASE + v, 0x1, 0xF)
        print("cmd:", k)
        break
lib.pf_step(20)
# 写 MSG
for k, v in offs.items():
    if "MSG" in k.upper():
        for w in range(4):
            lib.pf_write(BASE + v + 4 * w, 0xA5A5A5A5, 0xF)
            lib.pf_step(2)
        print("msg:", k)
        break
lib.pf_step(100)
# 读掩码信号
for i, nm in enumerate(names):
    if "mask" in nm:
        words = lib.pf_sig_words(i)
        vals = [lib.pf_sig_value(i, w) for w in range(words)]
        print("%s = %s" % (nm, " ".join("%08x" % v for v in vals)))
