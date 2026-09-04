// PickerFuzz per-IP wrapper — sram_ctrl standalone DUT
module sram_ctrl_perip_tb (
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

  // 双 TL 口: ram 口走 cb，regs 口 tie-off
  tlul_pkg::tl_h2d_t ram_tl_h2d, regs_tl_h2d;
  tlul_pkg::tl_d2h_t ram_tl_d2h, regs_tl_d2h;
  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;
  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) drv_q <= DRV_IDLE;
    else unique case (drv_q)
      DRV_IDLE: if (cb_valid)         drv_q <= DRV_REQ;
      DRV_REQ:  if (ram_tl_d2h.a_ready) drv_q <= DRV_RESP;
      DRV_RESP: if (ram_tl_d2h.d_valid) drv_q <= DRV_IDLE;
      default:                          drv_q <= DRV_IDLE;
    endcase
  end
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      req_addr_q <= 0; req_write_q <= 0; req_wdata_q <= 0; req_wmask_q <= 4'hF;
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
    tl_a.a_param           = 0;
    tl_a.a_size            = 2'b10;
    tl_a.a_mask            = req_write_q ? req_wmask_q : 4'hF;
    tl_a.a_source          = 0;
    tl_a.a_address         = req_addr_q;
    tl_a.a_data            = req_wdata_q;
    tl_a.a_user.instr_type = prim_mubi_pkg::MuBi4False;
    tl_a.a_user.cmd_intg   = tlul_pkg::get_cmd_intg(tl_a);
    tl_a.a_user.data_intg  = tlul_pkg::get_data_intg(req_wdata_q);
  end
  assign ram_tl_h2d = tl_a;
  assign cb_done  = (drv_q == DRV_RESP) && ram_tl_d2h.d_valid;
  assign cb_rdata = ram_tl_d2h.d_data;
  assign cb_error = ram_tl_d2h.d_error;
  assign regs_tl_h2d = tlul_pkg::TL_H2D_DEFAULT;

  logic clk_otp, rst_otp_n;
  assign clk_otp = clk_i;
  assign rst_otp_n = rst_ni;

  // OTP key 握手: 立即 valid
  otp_ctrl_pkg::sram_otp_key_req_t sram_otp_key_o;
  otp_ctrl_pkg::sram_otp_key_rsp_t sram_otp_key_i;
  always_comb begin
    sram_otp_key_i = otp_ctrl_pkg::SRAM_OTP_KEY_RSP_DEFAULT;
    sram_otp_key_i.ack = sram_otp_key_o.req;
    sram_otp_key_i.key = 128'h0123456789ABCDEF0123456789ABCDEF;
    sram_otp_key_i.nonce = 64'h0123456789ABCDEF;
  end

  lc_ctrl_pkg::lc_tx_t lc_escalate_en, lc_hw_debug_en;
  assign lc_escalate_en = lc_ctrl_pkg::Off;
  assign lc_hw_debug_en = lc_ctrl_pkg::Off;
  prim_mubi_pkg::mubi8_t otp_en_sram_ifetch;
  assign otp_en_sram_ifetch = prim_mubi_pkg::MuBi8False;

  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;
  top_racl_pkg::racl_range_t [0:0] racl_ranges;
  assign racl_policies = 1;
  assign racl_ranges = 0;

  prim_ram_1p_pkg::ram_1p_cfg_t [0:0] cfg;
  prim_ram_1p_pkg::ram_1p_cfg_rsp_t [0:0] cfg_rsp;
  assign cfg = 0;

  sram_ctrl_pkg::sram_error_t sram_rerror;

  prim_alert_pkg::alert_rx_t [sram_ctrl_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  sram_ctrl #(
    .NumRamInst(1),
    .InstrExec(1'b0)
  ) u_dut (
    .clk_i, .rst_ni,
    .clk_otp_i (clk_otp),
    .rst_otp_ni (rst_otp_n),
    .ram_tl_i   (ram_tl_h2d),
    .ram_tl_o   (ram_tl_d2h),
    .regs_tl_i  (regs_tl_h2d),
    .regs_tl_o  (regs_tl_d2h),
    .alert_rx_i (alert_rx),
    .alert_tx_o (),
    .racl_policies_i (racl_policies),
    .racl_error_o    (racl_error),
    .racl_policy_sel_ranges_ram_i (racl_ranges),
    .lc_escalate_en_i (lc_escalate_en),
    .lc_hw_debug_en_i (lc_hw_debug_en),
    .otp_en_sram_ifetch_i (otp_en_sram_ifetch),
    .sram_otp_key_o (sram_otp_key_o),
    .sram_otp_key_i (sram_otp_key_i),
    .cfg_i    (cfg),
    .cfg_rsp_o (cfg_rsp),
    .sram_rerror_o (sram_rerror)
  );

endmodule
