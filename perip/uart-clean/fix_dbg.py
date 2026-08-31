#!/usr/bin/env python3
"""clean uart TB 加调试打印"""
P = "/workspace/pickerfuzz/perip/uart-clean/rtl_wrapper/uart_core_tb.sv"
s = open(P).read()

old = """    for (int i = 0; i < 100; i++) begin
      @(posedge clk);
      if (lsio_trigger === 1'b1) stuck_cnt++;
    end"""

new = """    for (int i = 0; i < 100; i++) begin
      @(posedge clk);
      if (i == 50) begin
        $display("[DBG] tx_depth=%0d rx_depth=%0d tx_wm=%b rx_wm=%b tx_thresh=%0d rx_thresh=%0d",
                 u_dut.tx_fifo_depth, u_dut.rx_fifo_depth,
                 u_dut.event_tx_watermark, u_dut.event_rx_watermark,
                 u_dut.tx_watermark_thresh, u_dut.rx_watermark_thresh);
      end
      if (lsio_trigger === 1'b1) stuck_cnt++;
    end"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("debug added")
else:
    print("pattern not found")
