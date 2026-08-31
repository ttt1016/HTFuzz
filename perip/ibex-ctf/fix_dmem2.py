#!/usr/bin/env python3
"""gnt 拍直接用当拍 data 信号（排除锁存问题）"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/rtl_wrapper/ibex_mini_tb.sv"
s = open(p).read()
old = """      if (data_gnt) begin
        if (dmem_we_q) begin
          dmem[(dmem_addr_q[31:2]) % DMemWords] <= dmem_wdata_q;  // 全字写（简化）
          data_rdata <= 32'b0;
        end else begin
          data_rdata <= dmem[(dmem_addr_q[31:2]) % DMemWords];
        end
      end"""
new = """      if (data_gnt) begin
        // gnt 拍 req/we/addr/wdata 仍保持（ibex 协议），直接用当拍信号
        if (data_we) begin
          dmem[(data_addr[31:2]) % DMemWords] <= data_wdata;
          data_rdata <= 32'b0;
        end else begin
          data_rdata <= dmem[(data_addr[31:2]) % DMemWords];
        end
      end"""
assert old in s, "dmem gnt anchor not found"
s = s.replace(old, new)
open(p, "w").write(s)
print("gnt 拍用当拍信号完成")
