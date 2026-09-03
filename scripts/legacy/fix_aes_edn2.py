#!/usr/bin/env python3
"""修 edn_rsp_t 字段（只有 edn_ack/edn_fips/edn_bus）"""
path = "/workspace/HTFuzz/perip/aes-ctf/rtl_wrapper/aes_perip_tb.sv"
src = open(path).read()
old = """    edn_i.csrng_req_ready = 1'b1;
    edn_i.csrng_rsp_ack   = 1'b1;
    edn_i.genbits_valid   = 1'b1;
    edn_i.genbits_fips    = 1'b1;
    edn_i.genbits_bus     = edn_lfsr_q;"""
new = """    edn_i.edn_ack         = 1'b1;
    edn_i.edn_fips        = 1'b1;
    edn_i.edn_bus         = edn_lfsr_q;"""
assert old in src, "edn fields pattern not found"
src = src.replace(old, new)
open(path, "w").write(src)
print("edn fields fixed")
