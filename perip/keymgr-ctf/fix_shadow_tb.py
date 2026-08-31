#!/usr/bin/env python3
"""修 shadow_tb 端口连接"""
P = "/workspace/pickerfuzz/perip/keymgr-ctf/rtl_wrapper/shadow_tb.sv"
s = open(P).read()

old = """  logic [DW-1:0] wd, d, q, qs;
  logic we, de, qe, qre;
  logic err_update, err_storage;
  logic [AW-1:0] wr_data_err;

  prim_subreg_shadow #(
    .DW       ( DW ),
    .SwAccess ( prim_subreg_pkg::SwAccessRW ),
    .RESVAL   ( 8'hA5 )
  ) u_shadow (
    .clk_i, .rst_ni,
    .we, .wd,
    .de, .d,
    .qe, .q, .qs,
    .err_update, .err_storage,
    .wr_data_err
  );"""

new = """  logic [DW-1:0] wd, d, q, qs;
  logic we, de, qe, qre;
  logic err_update, err_storage;
  logic phase;
  logic [AW-1:0] wr_data_err;

  prim_subreg_shadow #(
    .DW       ( DW ),
    .SwAccess ( prim_subreg_pkg::SwAccessRW ),
    .RESVAL   ( 8'hA5 )
  ) u_shadow (
    .clk_i     (clk),
    .rst_ni    (rst_n),
    .we, .wd,
    .de, .d,
    .qe, .q, .qs,
    .phase,
    .err_update, .err_storage,
    .wr_data_err
  );"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("ports fixed")
else:
    print("pattern not found or already fixed")
