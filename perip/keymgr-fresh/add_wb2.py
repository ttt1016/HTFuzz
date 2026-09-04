#!/usr/bin/env python3
"""给 keymgr wrapper 加 u_ctrl.key_o 白盒观测"""
P = "/workspace/pickerfuzz/perip/keymgr-ctf/rtl_wrapper/keymgr_perip_tb.sv"
s = open(P).read()

if "pf_wb_ctrl_key_word" not in s:
    old = """  function automatic int pf_wb_op_start();
    return {31'h0, u_dut.u_ctrl.op_start_i};
  endfunction"""
    new = """  function automatic int pf_wb_op_start();
    return {31'h0, u_dut.u_ctrl.op_start_i};
  endfunction
  function automatic int pf_wb_ctrl_key_word(input int share, input int word);
    return u_dut.u_ctrl.key_o.key[share][word];
  endfunction
  function automatic int pf_wb_ctrl_key_valid();
    return {31'h0, u_dut.u_ctrl.key_o.valid};
  endfunction
  function automatic int pf_wb_stage_sel();
    return {30'h0, u_dut.u_ctrl.stage_sel_o};
  endfunction
  function automatic int pf_wb_invalid_stage_sel();
    return {31'h0, u_dut.u_ctrl.invalid_stage_sel_o};
  endfunction
  function automatic int pf_wb_lfsr_val();
    return u_dut.lfsr[63:32];
  endfunction"""
    assert old in s, "anchor not found"
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("wrapper updated")
else:
    print("already present")
