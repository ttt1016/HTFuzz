// PickerFuzz per-IP wrapper — spi_host standalone DUT
// 复用 hmac_perip_tb 的 TL-UL 驱动 FSM；SPI 外部信号 tie-off（主机模式自环）
module spi_host_perip_tb (
  input  logic clk_i,
  input  logic rst_ni,
  input  logic        cb_valid,
  input  logic [31:0] cb_addr,
  input  logic        cb_write,
  input  logic [31:0] cb_wdata,
  input  logic [3:0]  cb_wmask,
  output logic        cb_done,
  output logic [31:0] cb_rdata,
  output logic        cb_error
);
  import tlul_pkg::*;

  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;

  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;
  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) drv_q <= DRV_IDLE;
    else unique case (drv_q)
      DRV_IDLE: if (cb_valid)        drv_q <= DRV_REQ;
      DRV_REQ:  if (tl_d2h.a_ready)  drv_q <= DRV_RESP;
      DRV_RESP: if (tl_d2h.d_valid)  drv_q <= DRV_IDLE;
      default:                       drv_q <= DRV_IDLE;
    endcase
  end
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      req_addr_q <= '0; req_write_q <= '0; req_wdata_q <= '0; req_wmask_q <= 4'hF;
    end else if (cb_valid && drv_q == DRV_IDLE) begin
      req_addr_q <= cb_addr; req_write_q <= cb_write;
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

  // ---- SPI 外部信号: 主机模式自环（sd 输出回环到输入）----
  logic        sck, sck_en;
  logic [0:0]  csb, csb_en;
  logic [3:0]  sd_out, sd_en;
  logic [3:0]  sd_in;
  // 全双工回环: sd_i = sd_o（自测模式）
  assign sd_in = sd_out;

  logic intr_error, intr_spi_event;
  prim_alert_pkg::alert_tx_t [spi_host_reg_pkg::NumAlerts-1:0] alert_tx;
  prim_alert_pkg::alert_rx_t [spi_host_reg_pkg::NumAlerts-1:0] alert_rx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;
  spi_device_pkg::passthrough_req_t passthrough_req;
  spi_device_pkg::passthrough_rsp_t passthrough_rsp;
  logic lsio_trigger;

  assign alert_rx = '0;
  assign racl_policies = '0;
  assign passthrough_req = spi_device_pkg::PASSTHROUGH_REQ_DEFAULT;

  spi_host #(
    .NumCS(1),
    .EnableRacl(1'b0)
  ) u_dut (
    .clk_i,
    .rst_ni,
    .tl_i        (tl_h2d),
    .tl_o        (tl_d2h),
    .alert_rx_i  (alert_rx),
    .alert_tx_o  (alert_tx),
    .racl_policies_i (racl_policies),
    .racl_error_o    (racl_error),
    .cio_sck_o    (sck),
    .cio_sck_en_o (sck_en),
    .cio_csb_o    (csb),
    .cio_csb_en_o (csb_en),
    .cio_sd_o     (sd_out),
    .cio_sd_en_o  (sd_en),
    .cio_sd_i     (sd_in),
    .passthrough_i (passthrough_req),
    .passthrough_o (passthrough_rsp),
    .lsio_trigger_o (lsio_trigger),
    .intr_error_o   (intr_error),
    .intr_spi_event_o (intr_spi_event)
  );


  // 调试: reg_we/reg_re 脉冲计数（public 供 C++ 观测）
  logic [15:0] dbg_regwe_cnt /*verilator public*/;
  logic [15:0] dbg_regre_cnt /*verilator public*/;
  initial begin
    dbg_regwe_cnt = 16'h0;
    dbg_regre_cnt = 16'h0;
  end
  logic [15:0] dbg_done_cnt /*verilator public*/;
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
  end

endmodule
