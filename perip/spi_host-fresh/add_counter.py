#!/usr/bin/env python3
"""spi_host wrapper 加 reg_we/reg_re 观测计数器（verilator public）"""
p = "/workspace/pickerfuzz/perip/spi_host-ctf/rtl_wrapper/spi_host_perip_tb.sv"
s = open(p).read()
if "dbg_regwe_cnt" not in s:
    anchor = "  // 调试: 记录最近事务（C++ 可读）"
    assert anchor in s, "anchor not found"
    counter = """  // 调试: reg_we/reg_re 脉冲计数（public 供 C++ 观测）
  logic [15:0] dbg_regwe_cnt /*verilator public*/;
  logic [15:0] dbg_regre_cnt /*verilator public*/;
  initial begin
    dbg_regwe_cnt = 16'h0;
    dbg_regre_cnt = 16'h0;
  end
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      dbg_regwe_cnt <= 16'h0;
      dbg_regre_cnt <= 16'h0;
    end else begin
      if (u_dut.u_reg.reg_we) dbg_regwe_cnt <= dbg_regwe_cnt + 16'h1;
      if (u_dut.u_reg.reg_re) dbg_regre_cnt <= dbg_regre_cnt + 16'h1;
    end
  end

"""
    s = s.replace(anchor, counter + anchor)
    open(p, "w").write(s)
    print("regwe 计数器已加")
else:
    print("已存在")
