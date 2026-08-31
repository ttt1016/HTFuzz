#!/usr/bin/env python3
"""修 ibex wrapper 的 string 声明问题"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/rtl_wrapper/ibex_mini_tb.sv"
s = open(p).read()
old = """  // 程序加载: initial 块从 +prog= 文件加载（hex 每行一个 32bit 字）
  initial begin
    for (int i = 0; i < IMemWords; i++) imem[i] = 32'h00000013;  // nop (addi x0,x0,0)
    for (int i = 0; i < DMemWords; i++) dmem[i] = 32'b0;
    string progfile;
    if ($value$plusargs("prog=%s", progfile)) begin
      $readmemh(progfile, imem);
    end
  end"""
new = """  // 程序加载: initial 块从 prog.hex 加载（hex 每行一个 32bit 字）
  initial begin
    for (int i = 0; i < IMemWords; i++) imem[i] = 32'h00000013;  // nop (addi x0,x0,0)
    for (int i = 0; i < DMemWords; i++) dmem[i] = 32'b0;
    if ($test$plusargs("prog")) begin
      $readmemh("prog.hex", imem);
    end
  end"""
assert old in s, "anchor not found"
s = s.replace(old, new)
open(p, "w").write(s)
print("string 声明已移除")
