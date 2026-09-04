#!/usr/bin/env python3
"""修 csrng TB 的 for 循环"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = """      // 简单探测: 读全部寄存器空间前 0x100
      for (int a = 0; a < 0x100; a += 4) begin
        tl_read(32'h0 + a, rdata);
        if (rdata != 32'hFFFFFFFF)
          $display("[MAP] @0x%03x = %08x", a, rdata);
      end"""

new = """      // 简单探测: 读寄存器空间
      for (int a = 0; a < 64; a += 4) begin
        tl_read(32'h0 + a[31:0], rdata);
        if (rdata != 32'hFFFFFFFF)
          $display("[MAP] @0x%03x = %08x", a, rdata);
      end"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("loop fixed")
else:
    print("pattern not found")
