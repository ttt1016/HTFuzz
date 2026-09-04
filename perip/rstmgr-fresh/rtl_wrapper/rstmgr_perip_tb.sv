// PickerFuzz per-IP wrapper — rstmgr standalone DUT
module rstmgr_perip_tb (
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
  import rstmgr_pkg::*;

  // 多时钟域：全部由 clk_i 派生（同频简化）
  logic clk_aon, clk_io_div4, clk_main, clk_io, clk_io_div2, clk_usb, clk_por;
  logic rst_por_n;
  assign clk_aon = clk_i; assign clk_io_div4 = clk_i; assign clk_main = clk_i;
  assign clk_io = clk_i; assign clk_io_div2 = clk_i; assign clk_usb = clk_i;
  assign clk_por = clk_i;
  assign rst_por_n = rst_ni;

  logic [PowerDomains-1:0] por_n_i;
  assign por_n_i = {PowerDomains{rst_ni}};

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

  prim_alert_pkg::alert_rx_t [rstmgr_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  pwrmgr_pkg::pwr_rst_req_t pwr_i;
  pwrmgr_pkg::pwr_rst_rsp_t pwr_o;
  always_comb begin
    pwr_i.rst_lc_req = '0;
    pwr_i.rst_sys_req = '0;
    pwr_i.rstreqs = '0;
    pwr_i.reset_cause = pwrmgr_pkg::ResetUndefined;
  end

  prim_mubi_pkg::mubi4_t sw_rst_req_o;
  alert_handler_pkg::alert_crashdump_t alert_dump_i;
  assign alert_dump_i = alert_handler_pkg::ALERT_CRASHDUMP_DEFAULT;
  rv_core_ibex_pkg::cpu_crash_dump_t cpu_dump_i;
  always_comb begin
    cpu_dump_i = '0;
  end

  logic scan_rst_ni;
  assign scan_rst_ni = 1'b1;
  prim_mubi_pkg::mubi4_t scanmode_i;
  assign scanmode_i = prim_mubi_pkg::MuBi4False;

  rstmgr_rst_en_t rst_en_o;
  rstmgr_out_t resets_o;

  rstmgr u_dut (
    .clk_i,
    .rst_ni,
    .clk_aon_i    (clk_aon),
    .clk_io_div4_i(clk_io_div4),
    .clk_main_i   (clk_main),
    .clk_io_i     (clk_io),
    .clk_io_div2_i(clk_io_div2),
    .clk_usb_i    (clk_usb),
    .clk_por_i    (clk_por),
    .rst_por_ni   (rst_por_n),
    .por_n_i      (por_n_i),
    .tl_i       (tl_h2d),
    .tl_o       (tl_d2h),
    .alert_rx_i (alert_rx),
    .alert_tx_o (),
    .pwr_i      (pwr_i),
    .pwr_o      (pwr_o),
    .sw_rst_req_o (sw_rst_req_o),
    .alert_dump_i (alert_dump_i),
    .cpu_dump_i   (cpu_dump_i),
    .scan_rst_ni  (scan_rst_ni),
    .scanmode_i   (scanmode_i),
    .rst_en_o     (rst_en_o),
    .resets_o     (resets_o)
  );

endmodule
