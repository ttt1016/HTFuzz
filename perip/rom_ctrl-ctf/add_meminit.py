#!/usr/bin/env python3
"""rom_ctrl wrapper 加 MemInitFile 参数"""
p = "/workspace/pickerfuzz/perip/rom_ctrl-ctf/rtl_wrapper/rom_ctrl_perip_tb.sv"
s = open(p).read()
if "MemInitFile" not in s:
    old = """  rom_ctrl #(
    .SecDisableScrambling(1'b1)  // 简化: 关闭扰码（避免 mem 初始化复杂度）
  ) u_dut ("""
    new = """  rom_ctrl #(
    .SecDisableScrambling(1'b1),  // 简化: 关闭扰码
    .MemInitFile("rom.mem")
  ) u_dut ("""
    assert old in s, "rom_ctrl instance anchor not found"
    s = s.replace(old, new)
    open(p, "w").write(s)
    print("MemInitFile 已加")
else:
    print("已存在")
