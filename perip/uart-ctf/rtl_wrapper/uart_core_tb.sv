// PickerFuzz uart_core 单元 TB: Bug#1 检测（lsio_trigger_o stuck-at-1）
// 注入: fork 的 lsio_trigger_o 复位后恒 1（clean: event_tx_watermark | event_rx_watermark）
// 检测: 复位后无任何收发活动 → lsio_trigger_o 应为 0；fork 恒 1 → VIOLATION
module uart_core_tb;
  import uart_reg_pkg::*;

  logic clk = 0, rst_n = 0;
  always #5 clk = ~clk;

  logic rx = 1'b1;  // UART 空闲态为高
  logic tx;
  logic lsio_trigger;

  // 寄存器接口（直连 reg2hw 简化: 全 0 = 无中断使能、rxilvl=0）
  uart_reg2hw_t reg2hw;
  uart_hw2reg_t hw2reg;

  // 最小激励: 全部默认（无 watermark 事件）
  uart_core u_dut (
    .clk_i(clk),
    .rst_ni(rst_n),
    .rx(rx),
    .tx(tx),
    .lsio_trigger_o(lsio_trigger),
    .reg2hw(reg2hw),
    .hw2reg(hw2reg),
    .intr_tx_watermark_o(),
    .intr_tx_empty_o(),
    .intr_rx_watermark_o(),
    .intr_tx_done_o(),
    .intr_rx_overflow_o(),
    .intr_rx_frame_err_o(),
    .intr_rx_break_err_o(),
    .intr_rx_timeout_o(),
    .intr_rx_parity_err_o()
  );

  // 观察序列
  int stuck_cnt = 0;
  int t2_zero = 0;
  initial begin
    $display("======================================================================");
    $display("uart_core Bug#1: lsio_trigger_o stuck-at-1 检测");
    $display("======================================================================");

    // reg2hw 全 0（无配置、无 watermark 触发条件）
    reg2hw = 0;
    hw2reg = 0;

    rst_n = 0;
    repeat (3) @(posedge clk);
    rst_n = 1;

    // 空闲观察 100 拍（无任何收发活动）
    for (int i = 0; i < 100; i++) begin
      @(posedge clk);
      if (i == 50) begin
        $display("[DBG] tx_depth=%0d rx_depth=%0d tx_wm=%b rx_wm=%b tx_thresh=%0d rx_thresh=%0d",
                 u_dut.tx_fifo_depth, u_dut.rx_fifo_depth,
                 u_dut.event_tx_watermark, u_dut.event_rx_watermark,
                 u_dut.tx_watermark_thresh, u_dut.rx_thresh_val);
      end
      if (lsio_trigger === 1'b1) stuck_cnt++;
    end

    $display("[T1] 空闲 100 拍: lsio_trigger=1 的拍数 = %0d / 100（tx_wm=1 属正常）", stuck_cnt);

    // T2: 填满 TX FIFO → tx_depth >= thresh → tx_wm=0, rx_wm=0 → trigger 应变 0
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
    $display("     （clean: tx_wm=0 且 rx_wm=0 → trigger 应为 0；fork: 恒 1）");

    $display("\n======================================================================");
    $display("VERDICT");
    $display("======================================================================");
    if (t2_zero == 0) begin
      $display("VIOLATION: Bug#1 确认！");
      $display("  TX FIFO 填满后 lsio_trigger 仍恒 1（stuck-at-1）");
      $display("  注入: lsio_trigger_o <= 1'b1;（应 <= event_tx_watermark | event_rx_watermark）");
      $display("  clean: TX 满 → tx_wm=0, rx 空 → rx_wm=0 → trigger=0");
      $display("  → LSIO DMA 握手触发失效: DMA 在不该触发时被持续触发");
    end else begin
      $display("SAFE: lsio_trigger 跟随 watermark 事件（TX 满后变 0）");
    end
    $finish;
  end
endmodule
