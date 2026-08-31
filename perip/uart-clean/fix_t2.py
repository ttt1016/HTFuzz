#!/usr/bin/env python3
"""clean uart TB: 加 T2 场景（TX FIFO 填满后 trigger 应变 0）"""
P = "/workspace/pickerfuzz/perip/uart-clean/rtl_wrapper/uart_core_tb.sv"
s = open(P).read()

old = """    $display("[T1] 空闲 100 拍: lsio_trigger=1 的拍数 = %0d / 100", stuck_cnt);
    $display("     （clean: 应为 0 —— 无 watermark 事件时 trigger 保持 0）");"""

new = """    $display("[T1] 空闲 100 拍: lsio_trigger=1 的拍数 = %0d / 100（tx_wm=1 属正常）", stuck_cnt);

    // T2: 填满 TX FIFO → tx_depth >= thresh → tx_wm=0, rx_wm=0 → trigger 应变 0
    int t2_zero = 0;
    for (int i = 0; i < 40; i++) begin
      reg2hw.wdata.qe = 1;
      reg2hw.wdata.q = 8'h41 + i[7:0];
      @(posedge clk);
      reg2hw.wdata.qe = 0;
      @(posedge clk);
    end
    for (int i = 0; i < 50; i++) begin
      @(posedge clk);
      if (lsio_trigger === 1'b0) t2_zero++;
    end
    $display("[T2] TX FIFO 填满后 50 拍: lsio_trigger=0 的拍数 = %0d / 50", t2_zero);
    $display("     （clean: tx_wm=0 且 rx_wm=0 → trigger 应为 0；fork: 恒 1）");"""

if old in s:
    s = s.replace(old, new)
else:
    print("T1 anchor not found")

old2 = """    if (stuck_cnt >= 90) begin
      $display("VIOLATION: Bug#1 确认！");
      $display("  lsio_trigger_o 在完全空闲时恒为 1（stuck-at-1）");
      $display("  注入: lsio_trigger_o <= 1'b1;（应 <= event_tx_watermark | event_rx_watermark）");
      $display("  → LSIO DMA 握手触发信号失效: DMA 在无数据时被持续触发");
      $display("  → 可导致 DMA 错误传输 / 系统级数据流破坏");
    end else if (stuck_cnt == 0) begin
      $display("SAFE: lsio_trigger 空闲时保持 0（watermark 逻辑正常）");
    end else begin
      $display("INCONCLUSIVE: 部分拍为 1（%0d/100）", stuck_cnt);
    end"""

new2 = """    if (t2_zero == 0) begin
      $display("VIOLATION: Bug#1 确认！");
      $display("  TX FIFO 填满后 lsio_trigger 仍恒 1（stuck-at-1）");
      $display("  注入: lsio_trigger_o <= 1'b1;（应 <= event_tx_watermark | event_rx_watermark）");
      $display("  clean: TX 满 → tx_wm=0, rx 空 → rx_wm=0 → trigger=0");
      $display("  → LSIO DMA 握手触发失效: DMA 在不该触发时被持续触发");
    end else begin
      $display("SAFE: lsio_trigger 跟随 watermark 事件（TX 满后变 0）");
    end"""

if old2 in s:
    s = s.replace(old2, new2)
else:
    print("verdict pattern not found")

open(P, "w").write(s)
print("done")
