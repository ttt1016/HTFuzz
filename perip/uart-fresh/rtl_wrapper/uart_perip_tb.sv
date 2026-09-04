// PickerFuzz per-IP wrapper — UART standalone DUT（完整 IP + TL 寄存器接口）
// Bug#1 目标: lsio_trigger_o stuck-at-1（clean = event_tx_wm | event_rx_wm）
module uart_perip_tb (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        cb_valid,
  input  logic [31:0] cb_addr,
  input  logic        cb_write,
  input  logic [31:0] cb_wdata,
  input  logic [3:0]  cb_wmask,
  output logic        cb_done,
  output logic [31:0] cb_rdata,
  output logic        cb_error,
  output logic        dbg_lsio_trigger
);

  import tlul_pkg::*;
  import top_racl_pkg::*;

  // TL-UL 驱动 FSM（同 hmac/csrng 模式）
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;

  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;

  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) drv_q <= DRV_IDLE;
    else begin
      unique case (drv_q)
        DRV_IDLE: if (cb_valid)        drv_q <= DRV_REQ;
        DRV_REQ:  if (tl_d2h.a_ready)  drv_q <= DRV_RESP;
        DRV_RESP: if (tl_d2h.d_valid)  drv_q <= DRV_IDLE;
        default:                       drv_q <= DRV_IDLE;
      endcase
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      req_addr_q  <= '0; req_write_q <= 1'b0; req_wdata_q <= '0; req_wmask_q <= '0;
    end else if (cb_valid && drv_q == DRV_IDLE) begin
      req_addr_q  <= cb_addr;  req_write_q <= cb_write;
      req_wdata_q <= cb_wdata; req_wmask_q <= cb_wmask;
    end
  end

  tlul_pkg::tl_h2d_t tl_a;
  always_comb begin
    tl_a                   = tlul_pkg::TL_H2D_DEFAULT;
    tl_a.a_valid           = (drv_q == DRV_REQ);
    tl_a.a_opcode          = req_write_q ? (req_wmask_q == 4'hF ? tlul_pkg::PutFullData : tlul_pkg::PutPartialData) : tlul_pkg::Get;
    tl_a.a_param           = '0;
    tl_a.a_size            = 2'b10;
    tl_a.a_mask            = req_write_q ? req_wmask_q : 4'hF;
    tl_a.a_source          = '0;
    tl_a.a_address         = req_addr_q;
    tl_a.a_data            = req_wdata_q;
    tl_a.a_user.instr_type = prim_mubi_pkg::MuBi4False;
    tl_a.a_user.cmd_intg   = tlul_pkg::get_cmd_intg(tl_a);
    tl_a.a_user.data_intg  = tlul_pkg::get_data_intg(req_wdata_q);
  end
  assign tl_h2d = tl_a;
  assign cb_done  = (drv_q == DRV_RESP) && tl_d2h.d_valid;
  assign cb_rdata = tl_d2h.d_data;
  assign cb_error = tl_d2h.d_error;

  // -------------------------------------------------------------------------
  // DUT: 完整 uart IP
  // -------------------------------------------------------------------------
  logic rx = 1'b1;  // UART 空闲态为高
  logic tx;
  logic lsio_trigger;

  uart_reg_pkg::uart_reg2hw_t reg2hw;
  uart_reg_pkg::uart_hw2reg_t hw2reg;

  logic cio_tx, cio_tx_en;
  logic [uart_reg_pkg::NumAlerts-1:0] alert_test;
  logic [top_pkg::TL_AIW-1:0] alert_req;
  prim_alert_pkg::alert_rx_t [uart_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [uart_reg_pkg::NumAlerts-1:0] alert_tx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;

  uart u_dut (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .tl_i(tl_h2d),
    .tl_o(tl_d2h),
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .racl_policies_i(racl_policies),
    .racl_error_o(racl_error),
    .lsio_trigger_o(lsio_trigger),
    .cio_rx_i(rx),
    .cio_tx_o(cio_tx),
    .cio_tx_en_o(cio_tx_en),
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

  logic dbg_lsio;
  assign dbg_lsio = lsio_trigger;  // 防剪除: 顶层输出口（Bug#1 目标信号）
  assign dbg_lsio = lsio_trigger;

  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
    alert_test = '0;
    alert_req = '0;
    racl_policies = '0;
  end
endmodule