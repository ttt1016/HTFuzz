#!/usr/bin/env python3
"""修 csrng TB: es_bus_valid 移除"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = """  assign entropy_src_hw_if_i = '{es_ack: 1'b1, es_bus_valid: 1'b1, es_bits: esrng_lfsr_q, es_fips: 4'hF};"""
new = """  assign entropy_src_hw_if_i = '{es_ack: 1'b1, es_bits: esrng_lfsr_q, es_fips: 4'hF};"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("es_bus_valid removed")
else:
    # 检查是否已修
    if "es_bus_valid" not in s:
        print("already fixed")
    else:
        print("pattern not found, checking...")
        import re
        for i, line in enumerate(s.splitlines(), 1):
            if "es_bus_valid" in line:
                print(f"  line {i}: {line.strip()}")
