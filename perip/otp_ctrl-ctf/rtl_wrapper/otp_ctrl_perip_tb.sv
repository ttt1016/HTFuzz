// PickerFuzz per-IP wrapper — OTP_CTRL standalone DUT
module otp_ctrl_perip_tb (
  input  logic        clk_i,
  input  logic        rst_ni,
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
  import otp_ctrl_pkg::*;
  import otp_ctrl_reg_pkg::*;
  import prim_mubi_pkg::*;
  import lc_ctrl_pkg::*;

  // TL 驱动 FSM
  tlul_pkg::tl_h2d_t tl_h2d, tl_a;
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
      req_addr_q <= '0; req_write_q <= 1'b0; req_wdata_q <= '0; req_wmask_q <= '0;
    end else if (cb_valid && drv_q == DRV_IDLE) begin
      req_addr_q <= cb_addr; req_write_q <= cb_write;
      req_wdata_q <= cb_wdata; req_wmask_q <= cb_wmask;
    end
  end

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

  // ---------------------------------------------------------------------------
  // DUT: otp_ctrl（tie-off: edn/lc/pwr/flash/sram/otbn key 接口）
  // ---------------------------------------------------------------------------
  edn_pkg::edn_req_t edn_req;
  edn_pkg::edn_rsp_t edn_rsp;
  logic edn_fips;
  always_ff @(posedge clk_i) edn_fips <= !edn_fips;
  assign edn_rsp.edn_ack = edn_req.edn_req;
  assign edn_rsp.edn_fips = edn_fips;
  assign edn_rsp.edn_bus = {edn_fips, ~edn_fips, 30'h5A5A5A5};

  logic intr_done, intr_err;
  prim_alert_pkg::alert_rx_t [otp_ctrl_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [otp_ctrl_reg_pkg::NumAlerts-1:0] alert_tx;

  pwrmgr_pkg::pwr_otp_req_t pwr_otp_in;
  pwrmgr_pkg::pwr_otp_rsp_t pwr_otp_out;
  assign pwr_otp_in.otp_init = 1'b1;

  lc_ctrl_pkg::lc_tx_t lc_creator_seed_sw_rw_en, lc_owner_seed_sw_rw_en;
  lc_ctrl_pkg::lc_tx_t lc_seed_hw_rd_en, lc_escalate_en, lc_check_byp_en;

  lc_otp_program_req_t lc_prog_in;
  lc_otp_program_rsp_t lc_prog_out;
  assign lc_prog_in.req = 1'b0;

  otp_ctrl_pkg::flash_otp_key_req_t flash_key_in;
  otp_ctrl_pkg::flash_otp_key_rsp_t flash_key_out;
  otp_ctrl_pkg::sram_otp_key_req_t [otp_ctrl_reg_pkg::NumSramKeyReqSlots-1:0] sram_key_in;
  otp_ctrl_pkg::sram_otp_key_rsp_t [otp_ctrl_reg_pkg::NumSramKeyReqSlots-1:0] sram_key_out;
  otp_ctrl_pkg::otbn_otp_key_req_t otbn_key_in;
  otp_ctrl_pkg::otbn_otp_key_rsp_t otbn_key_out;

  logic fips_q;
  initial fips_q = 1'b0;
  always_ff @(posedge clk_i) fips_q <= ~fips_q;

  otp_ctrl u_dut (
    .clk_i(clk_i), .rst_ni(rst_ni),
    .edn_o(edn_req),
    .edn_i('{edn_ack: 1'b1, edn_fips: fips_q, edn_bus: {fips_q, ~fips_q, 30'hA5A5A5}}),
    .core_tl_i(tl_h2d), .core_tl_o(tl_d2h),
    .intr_otp_operation_done_o(intr_done),
    .intr_otp_error_o(intr_err),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .pwr_otp_i(pwr_otp_in), .pwr_otp_o(pwr_otp_out),
    .lc_otp_program_i(lc_prog_in), .lc_otp_program_o(lc_prog_out),
    .lc_creator_seed_sw_rw_en_i(lc_ctrl_pkg::On),
    .lc_owner_seed_sw_rw_en_i(lc_ctrl_pkg::On),
    .lc_seed_hw_rd_en_i(lc_ctrl_pkg::On),
    .lc_escalate_en_i(lc_ctrl_pkg::Off),
    .lc_check_byp_en_i(lc_ctrl_pkg::Off),
    .otp_lc_data_o(),
    .otp_keymgr_key_o(),
    .flash_otp_key_i('{data_req: 1'b0, addr_req: 1'b0}),
    .flash_otp_key_o(flash_key_out),
    .sram_otp_key_i('{default: '{req: 1'b0}}),
    .sram_otp_key_o(sram_key_out),
    .otbn_otp_key_i('{req: 1'b0}),
    .otbn_otp_key_o(otbn_key_out)
  );

  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end

  // 防剪除
  logic unused_otp;
  assign unused_otp = ^{intr_done, intr_err, pwr_otp_out.otp_done,
                        lc_prog_out, flash_key_out, sram_key_out, otbn_key_out};
endmodule
