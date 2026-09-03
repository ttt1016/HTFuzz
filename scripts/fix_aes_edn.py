#!/usr/bin/env python3
"""修 aes-ctf wrapper: EDN auto-ack（AES PRNG 初始化需要 entropy）"""
path = "/workspace/HTFuzz/perip/aes-ctf/rtl_wrapper/aes_perip_tb.sv"
src = open(path).read()
old = """  edn_pkg::edn_rsp_t edn_i;
  assign edn_i = 0;"""
new = """  edn_pkg::edn_rsp_t edn_i;
  // auto-ack EDN: 持续提供 entropy（PRNG 初始化需要，否则 AES 永远非 idle）
  logic [31:0] edn_lfsr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) edn_lfsr_q <= 32'hDEADBEEF;
    else         edn_lfsr_q <= {edn_lfsr_q[30:0], edn_lfsr_q[31]^edn_lfsr_q[21]^edn_lfsr_q[1]^edn_lfsr_q[0]};
  end
  always_comb begin
    edn_i                 = edn_pkg::EDN_RSP_DEFAULT;
    edn_i.edn_fips        = 1'b1;
    edn_i.edn_bus         = edn_lfsr_q;
    edn_i.csrng_req_ready = 1'b1;
    edn_i.csrng_rsp_ack   = 1'b1;
    edn_i.genbits_valid   = 1'b1;
    edn_i.genbits_fips    = 1'b1;
    edn_i.genbits_bus     = edn_lfsr_q;
  end"""
assert old in src, "edn tie-off not found"
src = src.replace(old, new)
open(path, "w").write(src)
print("edn auto-ack added")
