#!/usr/bin/env python3
"""sram_ctrl wrapper 参数修正"""
p = "/workspace/pickerfuzz/perip/sram_ctrl-ctf/rtl_wrapper/sram_ctrl_perip_tb.sv"
s = open(p).read()
s = s.replace("    .RamBaseAddr(32'h0000_0000)\n", "    .InstrExec(1'b0)\n")
s = s.replace("  logic [prim_alert_pkg::NumAlerts-1:0] alert_tx_dummy;\n", "")
open(p, "w").write(s)
print("参数修正完成")
