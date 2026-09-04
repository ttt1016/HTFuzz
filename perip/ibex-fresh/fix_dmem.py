#!/usr/bin/env python3
"""dmem 写改全字写（排除 be 问题）"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/rtl_wrapper/ibex_mini_tb.sv"
s = open(p).read()
old = """      if (data_gnt) begin
        if (dmem_we_q) begin
          if (dmem_be_q[0]) dmem[(dmem_addr_q[31:2]) % DMemWords][7:0]   <= dmem_wdata_q[7:0];
          if (dmem_be_q[1]) dmem[(dmem_addr_q[31:2]) % DMemWords][15:8]  <= dmem_wdata_q[15:8];
          if (dmem_be_q[2]) dmem[(dmem_addr_q[31:2]) % DMemWords][23:16] <= dmem_wdata_q[23:16];
          if (dmem_be_q[3]) dmem[(dmem_addr_q[31:2]) % DMemWords][31:24] <= dmem_wdata_q[31:24];
          data_rdata <= 32'b0;
        end else begin
          data_rdata <= dmem[(dmem_addr_q[31:2]) % DMemWords];
        end
      end"""
new = """      if (data_gnt) begin
        if (dmem_we_q) begin
          dmem[(dmem_addr_q[31:2]) % DMemWords] <= dmem_wdata_q;  // 全字写（简化）
          data_rdata <= 32'b0;
        end else begin
          data_rdata <= dmem[(dmem_addr_q[31:2]) % DMemWords];
        end
      end"""
assert old in s, "dmem write anchor not found"
s = s.replace(old, new)
open(p, "w").write(s)
print("dmem 改全字写完成")
