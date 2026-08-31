#!/usr/bin/env python3
"""生成 ibex filelist（pkg 优先 + wrapper 最后）"""
import os
base = "/workspace/pickerfuzz/perip/ibex-ctf"
# ibex_core.f 顺序
core_f = os.path.join(base, "hw/ibex/rtl/ibex_core.f")
files = []
for line in open(core_f):
    line = line.strip()
    if line and not line.startswith("//") and line.endswith(".sv"):
        files.append("hw/ibex/rtl/" + line)
# 补充缺失模块
extra = ["hw/ibex/rtl/ibex_dummy_instr.sv", "hw/ibex/rtl/ibex_pmp.sv",
         "hw/ibex/rtl/ibex_csr.sv", "hw/ibex/rtl/ibex_wb_stage.sv"]
for e in extra:
    if e not in files:
        files.append(e)
# wrapper 最后
files.append("rtl_wrapper/ibex_mini_tb.sv")
out = os.path.join(base, "filelist_ibex.f")
with open(out, "w") as f:
    f.write("\n".join(files) + "\n")
print("filelist_ibex.f:", len(files), "files")
