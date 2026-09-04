// PickerFuzz per-IP wrapper — entropy_src standalone DUT
// 复用 hmac_perip_tb 的 TL-UL 驱动 FSM；RNG 输入用 LFSR 模拟 AST
module entropy_src_perip_tb (
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

  // ---- RNG 模拟: 64bit LFSR 每拍出 4bit ----
  logic [63:0] lfsr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) lfsr_q <= 64'hACE1ACE5ACE9ACE3;
    else begin
      // Fibonacci LFSR taps
      lfsr_q <= {lfsr_q[62:0],
                 lfsr_q[63]^lfsr_q[62]^lfsr_q[60]^lfsr_q[59]};
    end
  end

  logic intr_es_entropy_valid, intr_es_health_test_failed, intr_es_observe_fifo_ready, intr_es_fatal_err;
  prim_mubi_pkg::mubi8_t otp_en_entropy_src_fw_read, otp_en_entropy_src_fw_over;
  prim_alert_pkg::alert_tx_t [entropy_src_reg_pkg::NumAlerts-1:0] alert_tx;
  prim_alert_pkg::alert_rx_t [entropy_src_reg_pkg::NumAlerts-1:0] alert_rx;
  entropy_src_pkg::entropy_src_hw_if_req_t es_hw_if_req;
  entropy_src_pkg::entropy_src_hw_if_rsp_t es_hw_if_rsp;
  entropy_src_pkg::entropy_src_rng_req_t rng_req;
  entropy_src_pkg::entropy_src_rng_rsp_t rng_rsp;
  entropy_src_pkg::cs_aes_halt_req_t cs_aes_halt_req;
  entropy_src_pkg::cs_aes_halt_rsp_t cs_aes_halt_rsp;
  entropy_src_pkg::entropy_src_xht_req_t xht_req;
  entropy_src_pkg::entropy_src_xht_rsp_t xht_rsp;

  assign otp_en_entropy_src_fw_read = prim_mubi_pkg::MuBi8True;
  assign otp_en_entropy_src_fw_over = prim_mubi_pkg::MuBi8True;
  assign alert_rx = '0;
  assign cs_aes_halt_rsp = '0;
  assign xht_rsp = {16'hffff, 1'b0, 2'b0};

  // RNG 响应: enable 时持续供数
  assign rng_rsp.rng_valid = rng_req.rng_enable;
  assign rng_rsp.rng_b     = lfsr_q[3:0];

  entropy_src u_dut (
    .clk_i,
    .rst_ni,
    .tl_i        (tl_h2d),
    .tl_o        (tl_d2h),
    .otp_en_entropy_src_fw_read_i (otp_en_entropy_src_fw_read),
    .otp_en_entropy_src_fw_over_i (otp_en_entropy_src_fw_over),
    .entropy_src_hw_if_i (es_hw_if_req),
    .entropy_src_hw_if_o (es_hw_if_rsp),
    .entropy_src_xht_i   (xht_req),
    .entropy_src_xht_o   (xht_rsp),
    .entropy_src_rng_i   (rng_rsp),
    .entropy_src_rng_o   (rng_req),
    .cs_aes_halt_i       (cs_aes_halt_rsp),
    .cs_aes_halt_o       (cs_aes_halt_req),
    .alert_rx_i  (alert_rx),
    .alert_tx_o  (alert_tx),
    .intr_es_entropy_valid_o        (intr_es_entropy_valid),
    .intr_es_health_test_failed_o   (intr_es_health_test_failed),
    .intr_es_observe_fifo_ready_o   (intr_es_observe_fifo_ready),
    .intr_es_fatal_err_o            (intr_es_fatal_err)
  );

  // es_hw_if_req 未接 CSRNG → tie-off（本 DUT 只测 FW_OV 路径和健康检查）
  assign es_hw_if_req = '0;
  assign xht_req = '0;

endmodule
