#!/usr/bin/env python3
"""修 csrng TB: cs_aes_halt 字段"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = """  assign cs_aes_halt_i = '{cs_aes_halt_ack: 1'b0, cs_aes_halt_req: 1'b0};"""
new = """  assign cs_aes_halt_i.cs_aes_halt_ack = 1'b0;"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("cs_aes_halt fixed")
else:
    print("pattern not found")
