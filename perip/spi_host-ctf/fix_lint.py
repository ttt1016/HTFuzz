#!/usr/bin/env python3
"""修 spi_host wrapper: sd_in 声明 + 回环；filelist: prim_subreg_pkg 提前"""
import os
os.chdir("/workspace/pickerfuzz/perip/spi_host-ctf")

# 1) filelist: prim_subreg_pkg 提前到 tlul_pkg 前
lines = [l for l in open("filelist.f").read().split("\n") if l]
if "hw/ip/prim/rtl/prim_subreg_pkg.sv" not in lines:
    idx = lines.index("hw/ip/tlul/rtl/tlul_pkg.sv")
    lines.insert(idx, "hw/ip/prim/rtl/prim_subreg_pkg.sv")
open("filelist.f", "w").write("\n".join(lines))

# 2) wrapper: sd_in 声明 + 回环
s = open("rtl_wrapper/spi_host_perip_tb.sv").read()
if "logic [3:0]  sd_in;" not in s:
    s = s.replace(
        "  top_racl_pkg::racl_policy_vec_t racl_policies;",
        "  logic [3:0]  sd_in;\n  top_racl_pkg::racl_policy_vec_t racl_policies;")
if "assign sd_in" not in s:
    s = s.replace(
        "  assign alert_rx = '0;",
        "  assign alert_rx = '0;\n  // 全双工回环: sd_i = sd_o（主机模式自测）\n  assign sd_in = sd_out;")
open("rtl_wrapper/spi_host_perip_tb.sv", "w").write(s)
print("修复完成")
