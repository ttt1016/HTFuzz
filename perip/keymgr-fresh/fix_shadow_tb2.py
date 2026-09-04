#!/usr/bin/env python3
"""修 shadow_tb 端口 v2（rst_shadowed_ni/re/ds）"""
P = "/workspace/pickerfuzz/perip/keymgr-ctf/rtl_wrapper/shadow_tb.sv"
s = open(P).read()

old = """  logic phase;
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

new = """  logic phase;
  logic re = 0;
  logic [DW-1:0] ds;

  prim_subreg_shadow #(
    .DW       ( DW ),
    .SwAccess ( prim_subreg_pkg::SwAccessRW ),
    .RESVAL   ( 8'hA5 )
  ) u_shadow (
    .clk_i     (clk),
    .rst_ni    (rst_n),
    .rst_shadowed_ni (rst_n),
    .re,
    .we, .wd,
    .de, .d,
    .qe, .q, .ds, .qs,
    .phase,
    .err_update, .err_storage
  );"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("ports fixed v2")
else:
    print("pattern not found")
