// PickerFuzz per-IP wrapper — pwrmgr standalone DUT
module pwrmgr_perip_tb (
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

  // 慢时钟（1/4 分频模拟 AON 域）
  logic clk_slow, clk_lc, clk_esc;
  logic rst_slow_n, rst_lc_n, rst_esc_n, rst_main_n;
  int div_cnt;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) div_cnt <= '0;
    else div_cnt <= (div_cnt == 3) ? 0 : div_cnt + 1;
  end
  assign clk_slow = (div_cnt < 2);  // 半周期慢时钟
  assign clk_lc = clk_i;
  assign clk_esc = clk_i;
  assign rst_slow_n = rst_ni;
  assign rst_lc_n = rst_ni;
  assign rst_esc_n = rst_ni;
  assign rst_main_n = rst_ni;

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

  // 电源/时钟/复位握手模拟（AST/RTC 响应恒 ready）
  pwrmgr_pkg::pwr_ast_req_t ast_req;
  pwrmgr_pkg::pwr_ast_rsp_t ast_rsp;
  pwrmgr_pkg::pwr_rst_req_t rst_req;
  pwrmgr_pkg::pwr_rst_rsp_t rst_rsp;
  pwrmgr_pkg::pwr_clk_req_t clk_req;
  pwrmgr_pkg::pwr_clk_rsp_t clk_rsp;
  pwrmgr_pkg::pwr_otp_req_t otp_req;
  pwrmgr_pkg::pwr_otp_rsp_t otp_rsp;
  lc_ctrl_pkg::pwr_lc_req_t lc_req;
  lc_ctrl_pkg::pwr_lc_rsp_t lc_rsp;
  pwrmgr_pkg::pwr_flash_t flash_rsp;
  rv_core_ibex_pkg::cpu_pwrmgr_t cpu_rsp;
  lc_ctrl_pkg::lc_tx_t fetch_en, lc_hw_debug_en, lc_dft_en;

  assign ast_rsp = 1;   // 所有 ready 拉高
  assign rst_rsp = 1;
  assign clk_rsp = 1;
  assign otp_rsp = 1;
  assign lc_rsp = 1;
  assign flash_rsp = '0;
  assign cpu_rsp = '0;
  assign lc_hw_debug_en = lc_ctrl_pkg::Off;
  assign lc_dft_en = lc_ctrl_pkg::Off;

  logic [pwrmgr_reg_pkg::NumWkups-1:0] wakeups;
  logic [pwrmgr_reg_pkg::NumRstReqs-1:0] rstreqs;
  assign wakeups = '0;
  assign rstreqs = '0;

  logic [pwrmgr_reg_pkg::NumAlerts-1:0] alert_tx, alert_rx_unused;
  prim_alert_pkg::alert_rx_t [pwrmgr_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = '0;

  logic intr_wakeup, intr_reset_done;

  pwrmgr u_dut (
    .clk_i, .rst_ni,
    .clk_slow_i (clk_slow),
    .clk_lc_i   (clk_lc),
    .clk_esc_i  (clk_esc),
    .rst_slow_ni (rst_slow_n),
    .rst_lc_ni   (rst_lc_n),
    .rst_esc_ni  (rst_esc_n),
    .rst_main_ni (rst_main_n),
    .tl_i        (tl_h2d),
    .tl_o        (tl_d2h),
    .alert_rx_i  (alert_rx),
    .alert_tx_o  (alert_tx),
    .pwr_ast_i   (ast_rsp),
    .pwr_ast_o   (ast_req),
    .pwr_rst_i   (rst_rsp),
    .pwr_rst_o   (rst_req),
    .pwr_clk_i   (clk_rsp),
    .pwr_clk_o   (clk_req),
    .pwr_otp_i   (otp_rsp),
    .pwr_otp_o   (otp_req),
    .pwr_lc_i    (lc_rsp),
    .pwr_lc_o    (lc_req),
    .pwr_flash_i (flash_rsp),
    .pwr_cpu_i   (cpu_rsp),
    .fetch_en_o  (fetch_en),
    .lc_hw_debug_en_i (lc_hw_debug_en),
    .lc_dft_en_i      (lc_dft_en),
    .wakeups_i   (wakeups),
    .rstreqs_i   (rstreqs),
    .intr_wakeup_o        (intr_wakeup)
  );

endmodule
