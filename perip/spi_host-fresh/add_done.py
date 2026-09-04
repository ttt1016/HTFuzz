#!/usr/bin/env python3
"""spi_host wrapper: 加 dbg_done_cnt 计数器"""
p = "/workspace/pickerfuzz/perip/spi_host-ctf/rtl_wrapper/spi_host_perip_tb.sv"
s = open(p).read()
if "dbg_done_cnt" not in s:
    old = """  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      dbg_regwe_cnt <= 16'h0;
      dbg_regre_cnt <= 16'h0;
    end else begin
      if (u_dut.u_reg.reg_we) dbg_regwe_cnt <= dbg_regwe_cnt + 16'h1;
      if (u_dut.u_reg.reg_re) dbg_regre_cnt <= dbg_regre_cnt + 16'h1;
    end
  end"""
    new = """  logic [15:0] dbg_done_cnt /*verilator public*/;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      dbg_regwe_cnt <= 16'h0;
      dbg_regre_cnt <= 16'h0;
      dbg_done_cnt <= 16'h0;
    end else begin
      if (u_dut.u_reg.reg_we) dbg_regwe_cnt <= dbg_regwe_cnt + 16'h1;
      if (u_dut.u_reg.reg_re) dbg_regre_cnt <= dbg_regre_cnt + 16'h1;
      if (cb_done) dbg_done_cnt <= dbg_done_cnt + 16'h1;
    end
  end"""
    assert old in s, "counter anchor not found"
    s = s.replace(old, new)
    open(p, "w").write(s)
    print("done 计数器已加")
else:
    print("已存在")
