#!/usr/bin/env python3
"""修 csrng TB: csrng_cmd_i 赋值（老版字段名）"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = """    csrng_cmd_i = '{default: '{cs_req: 1'b0, cs_aes_halt_req: 1'b0, genbits_vld: 1'b0, genbits_fips: 1'b0, genbits_bus: '0, cmd_sts: 1'b0}};"""
new = """    csrng_cmd_i = '{default: '{csrng_req_valid: 1'b0, csrng_req_bus: '0, genbits_ready: 1'b0}};"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("cmd_i fields fixed")
else:
    print("pattern not found")
