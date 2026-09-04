// PickerFuzz per-IP wrapper — otp_ctrl standalone DUT
module otp_ctrl_perip_tb (
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
  import otp_ctrl_pkg::*;
  import otp_ctrl_part_pkg::*;
  import prim_mubi_pkg::*;
  import prim_alert_pkg::*;
  import edn_pkg::*;
  import pwrmgr_pkg::*;
  import lc_ctrl_pkg::*;

  // EDN 时钟 1/2 分频
  logic clk_edn, rst_edn_n;
  logic div_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) div_q <= 1'b0;
    else div_q <= ~div_q;
  end
  assign clk_edn = div_q;
  assign rst_edn_n = rst_ni;

  // TL-UL core 口驱动 FSM
  tlul_pkg::tl_h2d_t core_tl_h2d;
  tlul_pkg::tl_d2h_t core_tl_d2h;
  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;
  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) drv_q <= DRV_IDLE;
    else unique case (drv_q)
      DRV_IDLE: if (cb_valid)           drv_q <= DRV_REQ;
      DRV_REQ:  if (core_tl_d2h.a_ready) drv_q <= DRV_RESP;
      DRV_RESP: if (core_tl_d2h.d_valid) drv_q <= DRV_IDLE;
      default:                           drv_q <= DRV_IDLE;
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
  assign core_tl_h2d = tl_a;
  assign cb_done  = (drv_q == DRV_RESP) && core_tl_d2h.d_valid;
  assign cb_rdata = core_tl_d2h.d_data;
  assign cb_error = core_tl_d2h.d_error;

  // EDN 模拟
  logic [31:0] lfsr_q;
  always_ff @(posedge clk_edn or negedge rst_edn_n) begin
    if (!rst_edn_n) lfsr_q <= 32'hdeadbeef;
    else lfsr_q <= {lfsr_q[30:0], lfsr_q[31] ^ lfsr_q[21] ^ lfsr_q[1] ^ lfsr_q[0]};
  end
  edn_req_t edn_req;
  edn_rsp_t edn_rsp;
  assign edn_rsp.edn_ack  = edn_req.edn_req;
  assign edn_rsp.edn_fips = 1'b1;
  assign edn_rsp.edn_bus  = lfsr_q;

  // lc tie-off（全部 On = 权限放开）
  lc_tx_t lc_creator_seed_sw_rw_en, lc_owner_seed_sw_rw_en, lc_seed_hw_rd_en;
  lc_tx_t lc_escalate_en, lc_check_byp_en;
  assign lc_creator_seed_sw_rw_en = On;
  assign lc_owner_seed_sw_rw_en   = On;
  assign lc_seed_hw_rd_en         = On;
  assign lc_escalate_en           = Off;
  assign lc_check_byp_en          = Off;

  // pwrmgr tie-off
  pwr_otp_req_t pwr_otp_i;
  pwr_otp_rsp_t pwr_otp_o;
  assign pwr_otp_i.otp_init = 1'b1;

  // lc_otp_program tie-off
  lc_otp_program_req_t lc_otp_program_i;
  lc_otp_program_rsp_t lc_otp_program_o;
  assign lc_otp_program_i.req = 1'b0;
  assign lc_otp_program_i.state = lc_ctrl_state_pkg::LcStRaw;
  assign lc_otp_program_i.count = lc_ctrl_state_pkg::LcCnt0;

  // flash/sram/otbn key 请求 tie-off
  flash_otp_key_req_t flash_otp_key_i;
  flash_otp_key_rsp_t flash_otp_key_o;
  assign flash_otp_key_i.data_req = 1'b0;
  assign flash_otp_key_i.addr_req = 1'b0;
  sram_otp_key_req_t [otp_ctrl_reg_pkg::NumSramKeyReqSlots-1:0] sram_otp_key_i;
  sram_otp_key_rsp_t [otp_ctrl_reg_pkg::NumSramKeyReqSlots-1:0] sram_otp_key_o;
  assign sram_otp_key_i = '0;
  otbn_otp_key_req_t otbn_otp_key_i;
  otbn_otp_key_rsp_t otbn_otp_key_o;
  assign otbn_otp_key_i.req = 1'b0;

  // OTP macro 模拟：ready=1，读返回内存数据，写立即完成
  otp_ctrl_macro_pkg::otp_ctrl_macro_req_t otp_macro_o;
  otp_ctrl_macro_pkg::otp_ctrl_macro_rsp_t otp_macro_i;
  logic [otp_ctrl_macro_pkg::OtpWidth-1:0] macro_mem [otp_ctrl_macro_pkg::OtpDepth];
  logic macro_rvalid_q;
  otp_ctrl_macro_pkg::otp_macro_data_t macro_rdata_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      macro_rvalid_q <= 1'b0;
      macro_rdata_q <= '0;
    end else begin
      macro_rvalid_q <= 1'b0;
      if (otp_macro_o.valid && otp_macro_o.cmd == otp_ctrl_macro_pkg::Read) begin
        macro_rvalid_q <= 1'b1;
        for (int k = 0; k < otp_ctrl_macro_pkg::OtpIfWidth/otp_ctrl_macro_pkg::OtpWidth; k++) begin
          macro_rdata_q[k*otp_ctrl_macro_pkg::OtpWidth +: otp_ctrl_macro_pkg::OtpWidth] <= macro_mem[otp_macro_o.addr + k];
        end
      end else if (otp_macro_o.valid && otp_macro_o.cmd == otp_ctrl_macro_pkg::Write) begin
        for (int k = 0; k < otp_ctrl_macro_pkg::OtpIfWidth/otp_ctrl_macro_pkg::OtpWidth; k++) begin
          macro_mem[otp_macro_o.addr + k] <= otp_macro_o.wdata[k*otp_ctrl_macro_pkg::OtpWidth +: otp_ctrl_macro_pkg::OtpWidth];
        end
      end
    end
  end
  assign otp_macro_i.ready = 1'b1;
  assign otp_macro_i.rvalid = macro_rvalid_q;
  assign otp_macro_i.rdata = macro_rdata_q;
  assign otp_macro_i.err = otp_ctrl_macro_pkg::NoError;
  assign otp_macro_i.fatal_lc_fsm_err = 1'b0;
  assign otp_macro_i.fatal_alert = 1'b0;
  assign otp_macro_i.recov_alert = 1'b0;

  prim_alert_pkg::alert_rx_t [otp_ctrl_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  logic intr_otp_operation_done, intr_otp_error;
  otp_broadcast_t otp_broadcast;

  otp_ctrl u_dut (
    .clk_i,
    .rst_ni,
    .clk_edn_i       (clk_edn),
    .rst_edn_ni      (rst_edn_n),
    .edn_o           (edn_req),
    .edn_i           (edn_rsp),
    .core_tl_i       (core_tl_h2d),
    .core_tl_o       (core_tl_d2h),
    .intr_otp_operation_done_o (intr_otp_operation_done),
    .intr_otp_error_o          (intr_otp_error),
    .alert_rx_i      (alert_rx),
    .alert_tx_o      (),
    .pwr_otp_i       (pwr_otp_i),
    .pwr_otp_o       (pwr_otp_o),
    .lc_otp_program_i (lc_otp_program_i),
    .lc_otp_program_o (lc_otp_program_o),
    .lc_creator_seed_sw_rw_en_i (lc_creator_seed_sw_rw_en),
    .lc_owner_seed_sw_rw_en_i   (lc_owner_seed_sw_rw_en),
    .lc_seed_hw_rd_en_i         (lc_seed_hw_rd_en),
    .lc_escalate_en_i           (lc_escalate_en),
    .lc_check_byp_en_i          (lc_check_byp_en),
    .otp_lc_data_o   (),
    .otp_keymgr_key_o (),
    .flash_otp_key_i  (flash_otp_key_i),
    .flash_otp_key_o  (flash_otp_key_o),
    .sram_otp_key_i   (sram_otp_key_i),
    .sram_otp_key_o   (sram_otp_key_o),
    .otbn_otp_key_i   (otbn_otp_key_i),
    .otbn_otp_key_o   (otbn_otp_key_o),
    .otp_macro_o      (otp_macro_o),
    .otp_macro_i      (otp_macro_i),
    .otp_broadcast_o  (otp_broadcast)
  );

endmodule
