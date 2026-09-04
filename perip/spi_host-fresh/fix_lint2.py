#!/usr/bin/env python3
"""修 wrapper cio_sd_o 引用 + filelist subreg_pkg 顺序"""
import os
os.chdir("/workspace/pickerfuzz/perip/spi_host-ctf")

# 1) wrapper: assign sd_in = cio_sd_o → sd_out（cio_sd_o 是 DUT 内部端口名）
s = open("rtl_wrapper/spi_host_perip_tb.sv").read()
s = s.replace("assign sd_in = cio_sd_o;", "assign sd_in = sd_out;")
open("rtl_wrapper/spi_host_perip_tb.sv", "w").write(s)

# 2) filelist: prim_subreg_pkg.sv 必须在 prim_subreg.sv / prim_subreg_arb.sv 之前
lines = open("filelist.f").read().split("\n")
pkg_line = "hw/ip/prim/rtl/prim_subreg_pkg.sv"
lines = [l for l in lines if l != pkg_line]
# 找到第一个 prim_subreg.sv 的位置，插到它前面
for i, l in enumerate(lines):
    if l.endswith("prim_subreg.sv"):
        lines.insert(i, pkg_line)
        break
else:
    lines.insert(0, pkg_line)
open("filelist.f", "w").write("\n".join(lines))
print("修复完成")
