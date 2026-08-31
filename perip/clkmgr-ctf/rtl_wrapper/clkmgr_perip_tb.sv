// PickerFuzz per-IP wrapper — clkmgr standalone DUT
module clkmgr_perip_tb (
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

  // 多时钟域：全部由 clk_i 派生（同频，简化）
  logic clk_main, clk_io, clk_usb, clk_aon;
  logic rst_main_n, rst_io_n, rst_usb_n, rst_aon_n;
  logic rst_io_div2_n, rst_io_div4_n;
  logic rst_root_n, rst_root_main_n, rst_root_io_n, rst_root_io_div2_n, rst_root_io_div4_n, rst_root_usb_n;
  logic rst_shadowed_n;

  assign clk_main = clk_i;
  assign clk_io = clk_i;
  assign clk_usb = clk_i;
  assign clk_aon = clk_i;
  assign rst_main_n = rst_ni;
  assign rst_io_n = rst_ni;
  assign rst_usb_n = rst_ni;
  assign rst_aon_n = rst_ni;
  assign rst_io_div2_n = rst_ni;
  assign rst_io_div4_n = rst_ni;
  assign rst_root_n = rst_ni;
  assign rst_root_main_n = rst_ni;
  assign rst_root_io_n = rst_ni;
  assign rst_root_io_div2_n = rst_ni;
  assign rst_root_io_div4_n = rst_ni;
  assign rst_root_usb_n = rst_ni;
  assign rst_shadowed_n = rst_ni;

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
  assign tl_h2d = tl_a;
  assign cb_done  = (drv_q == DRV_RESP) && tl_d2h.d_valid;
  assign cb_rdata = tl_d2h.d_data;
  assign cb_error = tl_d2h.d_error;

  prim_alert_pkg::alert_rx_t [clkmgr_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  pwrmgr_pkg::pwr_clk_req_t pwr_i;
  pwrmgr_pkg::pwr_clk_rsp_t pwr_o;
  assign pwr_i.main_ip_clk_en = 1; assign pwr_i.io_ip_clk_en = 1; assign pwr_i.usb_ip_clk_en = 1; // pwrmgr 全时钟使能

  prim_mubi_pkg::mubi4_t scanmode_i;
  assign scanmode_i = prim_mubi_pkg::MuBi4False;

  prim_mubi_pkg::mubi4_t [3:0] idle_i;
  assign idle_i = {4{prim_mubi_pkg::MuBi4True}};  // 全部 idle

  lc_ctrl_pkg::lc_tx_t lc_hw_debug_en_i;
  assign lc_hw_debug_en_i = lc_ctrl_pkg::Off;

  lc_ctrl_pkg::lc_tx_t lc_clk_byp_req_i, lc_clk_byp_ack_o;
  assign lc_clk_byp_req_i = lc_ctrl_pkg::Off;

  prim_mubi_pkg::mubi4_t io_clk_byp_req_o, io_clk_byp_ack_i;
  prim_mubi_pkg::mubi4_t all_clk_byp_req_o, all_clk_byp_ack_i;
  assign io_clk_byp_ack_i = prim_mubi_pkg::MuBi4False;
  assign all_clk_byp_ack_i = prim_mubi_pkg::MuBi4False;

  prim_mubi_pkg::mubi4_t calib_rdy_i;
  assign calib_rdy_i = prim_mubi_pkg::MuBi4True;

  prim_mubi_pkg::mubi4_t div_step_down_req_i;
  assign div_step_down_req_i = prim_mubi_pkg::MuBi4False;

  prim_mubi_pkg::mubi4_t jitter_en_o;
  clkmgr_pkg::clkmgr_cg_en_t cg_en_o;
  clkmgr_pkg::clkmgr_out_t clocks_o;

  clkmgr u_dut (
    .clk_i,
    .rst_ni,
    .rst_shadowed_ni (rst_shadowed_n),
    .clk_main_i      (clk_main),
    .rst_main_ni     (rst_main_n),
    .clk_io_i        (clk_io),
    .rst_io_ni       (rst_io_n),
    .clk_usb_i       (clk_usb),
    .rst_usb_ni      (rst_usb_n),
    .clk_aon_i       (clk_aon),
    .rst_aon_ni      (rst_aon_n),
    .rst_io_div2_ni  (rst_io_div2_n),
    .rst_io_div4_ni  (rst_io_div4_n),
    .rst_root_ni     (rst_root_n),
    .rst_root_main_ni(rst_root_main_n),
    .rst_root_io_ni  (rst_root_io_n),
    .rst_root_io_div2_ni (rst_root_io_div2_n),
    .rst_root_io_div4_ni (rst_root_io_div4_n),
    .rst_root_usb_ni (rst_root_usb_n),
    .tl_i       (tl_h2d),
    .tl_o       (tl_d2h),
    .alert_rx_i (alert_rx),
    .alert_tx_o (),
    .pwr_i      (pwr_i),
    .pwr_o      (pwr_o),
    .scanmode_i (scanmode_i),
    .idle_i     (idle_i),
    .lc_hw_debug_en_i (lc_hw_debug_en_i),
    .lc_clk_byp_req_i (lc_clk_byp_req_i),
    .lc_clk_byp_ack_o (lc_clk_byp_ack_o),
    .io_clk_byp_req_o (io_clk_byp_req_o),
    .io_clk_byp_ack_i (io_clk_byp_ack_i),
    .all_clk_byp_req_o(all_clk_byp_req_o),
    .all_clk_byp_ack_i(all_clk_byp_ack_i),
    .hi_speed_sel_o   (),
    .calib_rdy_i      (calib_rdy_i),
    .jitter_en_o      (jitter_en_o),
    .div_step_down_req_i (div_step_down_req_i),
    .cg_en_o          (cg_en_o),
    .clocks_o         (clocks_o)
  );

endmodule
