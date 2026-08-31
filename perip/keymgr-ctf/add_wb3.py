#!/usr/bin/env python3
"""给 keymgr wrapper 补 export 声明"""
P = "/workspace/pickerfuzz/perip/keymgr-ctf/rtl_wrapper/keymgr_perip_tb.sv"
s = open(P).read()

old = """  function automatic int pf_wb_op_start();
    return {31'h0, u_dut.u_ctrl.op_start_i};
  endfunction
  function automatic int pf_wb_ctrl_key_word(input int share, input int word);"""
new = """  function automatic int pf_wb_op_start();
    return {31'h0, u_dut.u_ctrl.op_start_i};
  endfunction
  export "DPI-C" function pf_wb_ctrl_key_word;
  export "DPI-C" function pf_wb_ctrl_key_valid;
  export "DPI-C" function pf_wb_stage_sel;
  export "DPI-C" function pf_wb_invalid_stage_sel;
  export "DPI-C" function pf_wb_lfsr_val;
  function automatic int pf_wb_ctrl_key_word(input int share, input int word);"""
assert old in s, "anchor not found"
s = s.replace(old, new)
open(P, "w").write(s)
print("exports added")
