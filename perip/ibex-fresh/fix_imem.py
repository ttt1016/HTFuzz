#!/usr/bin/env python3
"""修 ibex imem rdata 时序（改组合输出）"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/rtl_wrapper/ibex_mini_tb.sv"
s = open(p).read()
old = """  logic [31:0] imem_addr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      instr_gnt <= 1'b0; instr_rvalid <= 1'b0; instr_rdata <= 32'b0; imem_addr_q <= 32'b0;
    end else begin
      instr_gnt    <= instr_req;
      instr_rvalid <= instr_gnt;  // gnt 后一拍 rvalid
      if (instr_req && !instr_gnt) imem_addr_q <= instr_addr;
      if (instr_gnt) instr_rdata <= imem[(imem_addr_q[31:2]) % IMemWords];
    end
  end"""
new = """  logic [31:0] imem_addr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      instr_gnt <= 1'b0; instr_rvalid <= 1'b0; imem_addr_q <= 32'b0;
    end else begin
      instr_gnt    <= instr_req;
      instr_rvalid <= instr_gnt;  // gnt 后一拍 rvalid
      if (instr_req && !instr_gnt) imem_addr_q <= instr_addr;
    end
  end
  // rdata 组合输出（rvalid 拍有效）
  always_comb begin
    instr_rdata = imem[(imem_addr_q[31:2]) % IMemWords];
  end"""
assert old in s, "imem anchor not found"
s = s.replace(old, new)
open(p, "w").write(s)
print("imem rdata 改组合完成")
