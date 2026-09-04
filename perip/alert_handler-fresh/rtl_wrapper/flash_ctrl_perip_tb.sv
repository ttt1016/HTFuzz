// PickerFuzz per-IP wrapper — flash_ctrl standalone DUT
module flash_ctrl_perip_tb (
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
  import flash_ctrl_pkg::*;
  import flash_ctrl_reg_pkg::*;
  import prim_mubi_pkg::*;
  import prim_alert_pkg::*;
  import otp_ctrl_pkg::*;
  import pwrmgr_pkg::*;
  import lc_ctrl_pkg::*;
  import ast_pkg::*;

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

  // prim_tl / mem_tl tie-off
  tlul_pkg::tl_h2d_t prim_tl_i, mem_tl_i;
  tlul_pkg::tl_d2h_t prim_tl_o, mem_tl_o;
  assign prim_tl_i = tlul_pkg::TL_H2D_DEFAULT;
  assign mem_tl_i  = tlul_pkg::TL_H2D_DEFAULT;

  // lc tie-off（权限放开）
  lc_tx_t lc_creator_seed_sw_rw_en, lc_owner_seed_sw_rw_en, lc_iso_part_sw_rd_en;
  lc_tx_t lc_iso_part_sw_wr_en, lc_seed_hw_rd_en, lc_escalate_en, lc_nvm_debug_en;
  assign lc_creator_seed_sw_rw_en = On;
  assign lc_owner_seed_sw_rw_en   = On;
  assign lc_iso_part_sw_rd_en     = On;
  assign lc_iso_part_sw_wr_en     = On;
  assign lc_seed_hw_rd_en         = On;
  assign lc_escalate_en           = Off;
  assign lc_nvm_debug_en          = Off;

  // OTP key 响应模拟：立即 ack + 固定密钥
  flash_otp_key_req_t otp_o;
  flash_otp_key_rsp_t otp_i;
  logic otp_ack_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) otp_ack_q <= 1'b0;
    else otp_ack_q <= otp_o.data_req | otp_o.addr_req;
  end
  assign otp_i.data_ack = otp_ack_q;
  assign otp_i.addr_ack = otp_ack_q;
  assign otp_i.key = 128'h0f1571c9b98f203e8fe9a3cb32c4ab07;
  assign otp_i.seed_valid = 1'b1;

  // RMA tie-off
  lc_tx_t rma_req_i;
  lc_ctrl_pkg::lc_flash_rma_seed_t rma_seed_i;
  lc_tx_t rma_ack_o;
  assign rma_req_i = Off;
  assign rma_seed_i = '0;

  // JTAG tie-off
  logic cio_tck, cio_tms, cio_tdi, cio_tdo_en, cio_tdo;
  assign cio_tck = 1'b0;
  assign cio_tms = 1'b0;
  assign cio_tdi = 1'b0;

  // AST obs tie-off
  ast_obs_ctrl_t obs_ctrl_i;
  assign obs_ctrl_i = '0;
  logic [7:0] fla_obs;

  // 模拟端口 tie-off
  prim_mubi_pkg::mubi4_t scanmode_i, flash_bist_enable_i;
  logic scan_en_i, scan_rst_ni, flash_power_down_h_i, flash_power_ready_h_i;
  wire [1:0] flash_test_mode_a_io;
  wire flash_test_voltage_h_io;
  assign scanmode_i = MuBi4False;
  assign scan_en_i = 1'b0;
  assign scan_rst_ni = 1'b1;
  assign flash_bist_enable_i = MuBi4False;
  assign flash_power_down_h_i = 1'b1;  // 1 = 不掉电
  assign flash_power_ready_h_i = 1'b1;
  assign flash_test_mode_a_io = 2'b00;
  assign flash_test_voltage_h_io = 1'b0;

  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  logic intr_corr_err, intr_prog_empty, intr_prog_lvl, intr_rd_full, intr_rd_lvl, intr_op_done;

  flash_ctrl u_dut (
    .clk_i,
    .rst_ni,
    .lc_creator_seed_sw_rw_en_i (lc_creator_seed_sw_rw_en),
    .lc_owner_seed_sw_rw_en_i   (lc_owner_seed_sw_rw_en),
    .lc_iso_part_sw_rd_en_i     (On),
    .lc_iso_part_sw_wr_en_i     (On),
    .lc_seed_hw_rd_en_i         (lc_seed_hw_rd_en),
    .lc_escalate_en_i           (lc_escalate_en),
    .lc_nvm_debug_en_i          (lc_nvm_debug_en),
    .core_tl_i       (core_tl_h2d),
    .core_tl_o       (core_tl_d2h),
    .prim_tl_i       (prim_tl_i),
    .prim_tl_o       (prim_tl_o),
    .mem_tl_i        (mem_tl_i),
    .mem_tl_o        (mem_tl_o),
    .otp_o           (otp_o),
    .otp_i           (otp_i),
    .rma_req_i       (rma_req_i),
    .rma_seed_i      ('0),
    .rma_ack_o       (rma_ack_o),
    .pwrmgr_o        (),
    .keymgr_o        (),
    .cio_tck_i       (cio_tck),
    .cio_tms_i       (cio_tms),
    .cio_tdi_i       (1'b0),
    .cio_tdo_en_o    (cio_tdo_en),
    .cio_tdo_o       (cio_tdo),
    .intr_corr_err_o   (),
    .intr_prog_empty_o (),
    .intr_prog_lvl_o   (),
    .intr_rd_full_o    (),
    .intr_rd_lvl_o     (),
    .intr_op_done_o    (),
    .alert_rx_i        (alert_rx),
    .alert_tx_o        (),
    .obs_ctrl_i        ('0),
    .fla_obs_o         (),
    .scan_en_i         (scan_en_i),
    .scanmode_i        (scanmode_i),
    .scan_rst_ni       (rst_ni),
    .flash_bist_enable_i (MuBi4False),
    .flash_power_down_h_i (flash_power_down_h_i),
    .flash_power_ready_h_i (flash_power_ready_h_i),
    .flash_test_mode_a_io (flash_test_mode_a_io),
    .flash_test_voltage_h_io (flash_test_voltage_h_io)
  );

endmodule
