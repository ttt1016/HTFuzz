#!/usr/bin/env python3
"""删 ibex_controller.sv 的 illegal insn $display 块"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/hw/ibex/rtl/ibex_controller.sv"
s = open(p).read()
old = """  always_ff @(negedge clk_i) begin
    // print warning in case of decoding errors
    if ((ctrl_fsm_cs == DECODE) && instr_valid_i && !instr_fetch_err_i && illegal_insn_d) begin
      $display("%t: Illegal instruction (hart %0x) at PC 0x%h: 0x%h", $time, hart_id_i,
               pc_id_i, instr_is_compressed_i ? {16'b0, instr_compressed_i} : instr_i );
    end
  end"""
new = """  // illegal insn $display removed for standalone sim (no hart_id_i port)"""
assert old in s, "display anchor not found"
s = s.replace(old, new)
open(p, "w").write(s)
print("display 块已删")
