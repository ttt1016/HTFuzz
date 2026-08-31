#!/usr/bin/env python3
"""给 keymgr wrapper 加白盒观测函数"""
import subprocess, os

P = "/workspace/pickerfuzz/perip/keymgr-ctf/rtl_wrapper/keymgr_perip_tb.sv"
s = open(P).read()

if "pf_wb_state_d" not in s:
    old = """  function automatic int pf_wb_cnt_err();
    return {31'h0, u_dut.u_ctrl.cnt_err};
  endfunction"""
    new = """  function automatic int pf_wb_cnt_err();
    return {31'h0, u_dut.u_ctrl.cnt_err};
  endfunction
  function automatic int pf_wb_state_d();
    return {22'h0, u_dut.u_ctrl.state_d};
  endfunction
  function automatic int pf_wb_inv_state();
    return {31'h0, u_dut.u_ctrl.inv_state};
  endfunction
  function automatic int pf_wb_advance_sel();
    return {31'h0, u_dut.u_ctrl.advance_sel};
  endfunction
  function automatic int pf_wb_op_start();
    return {31'h0, u_dut.u_ctrl.op_start_i};
  endfunction"""
    assert old in s, "anchor not found"
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("wrapper updated")
else:
    print("already present")
