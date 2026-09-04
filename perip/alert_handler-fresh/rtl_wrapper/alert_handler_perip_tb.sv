// PickerFuzz per-IP wrapper — alert_handler standalone DUT
module alert_handler_perip_tb (
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
  import alert_handler_pkg::*;
  import prim_mubi_pkg::*;
  import prim_alert_pkg::*;
  import prim_esc_pkg::*;
  import edn_pkg::*;

  // 双时钟：clk_edn 1/2 分频
  logic clk_edn, rst_edn_n;
  logic div_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) div_q <= 1'b0;
    else div_q <= ~div_q;
  end
  assign clk_edn = div_q;
  assign rst_edn_n = rst_ni;

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

  localparam int NAlerts = alert_handler_reg_pkg::NAlerts;
  localparam int N_ESC_SEV = alert_handler_reg_pkg::N_ESC_SEV;

  // LPG tie-off（全部使能 = MuBi4True）
  mubi4_t [alert_handler_reg_pkg::NLpg-1:0] lpg_cg_en, lpg_rst_en;
  assign lpg_cg_en = {alert_handler_reg_pkg::NLpg{MuBi4True}};
  assign lpg_rst_en = {alert_handler_reg_pkg::NLpg{MuBi4True}};

  // alert_tx 输入模拟：全部空闲（ping 响应由 receiver 自动回）
  alert_tx_t [NAlerts-1:0] alert_tx_i;
  assign alert_tx_i = '0;

  // EDN 响应模拟：立即 ack + 随机数据（LFSR）
  logic [31:0] lfsr_q;
  always_ff @(posedge clk_edn or negedge rst_edn_n) begin
    if (!rst_edn_n) lfsr_q <= 32'h12345678;
    else lfsr_q <= {lfsr_q[30:0], lfsr_q[31] ^ lfsr_q[21] ^ lfsr_q[1] ^ lfsr_q[0]};
  end
  edn_req_t edn_req;
  edn_rsp_t edn_rsp;
  assign edn_rsp.edn_ack   = edn_req.edn_req;
  assign edn_rsp.edn_fips  = 1'b1;
  assign edn_rsp.edn_bus   = lfsr_q;

  // escalation rx 模拟：空闲响应（resp_p=0, resp_n=1），sender ping 能得到 ok
  esc_rx_t [N_ESC_SEV-1:0] esc_rx_i;
  assign esc_rx_i = {N_ESC_SEV{prim_esc_pkg::ESC_RX_DEFAULT}};
  esc_tx_t [N_ESC_SEV-1:0] esc_tx_o;

  logic intr_classa, intr_classb, intr_classc, intr_classd;
  alert_crashdump_t crashdump;

  alert_handler u_dut (
    .clk_i,
    .rst_ni,
    .rst_shadowed_ni (rst_ni),
    .clk_edn_i       (clk_edn),
    .rst_edn_ni      (rst_edn_n),
    .tl_i            (tl_h2d),
    .tl_o            (tl_d2h),
    .intr_classa_o   (intr_classa),
    .intr_classb_o   (intr_classb),
    .intr_classc_o   (intr_classc),
    .intr_classd_o   (intr_classd),
    .lpg_cg_en_i     (lpg_cg_en),
    .lpg_rst_en_i    (lpg_rst_en),
    .crashdump_o     (crashdump),
    .edn_o           (edn_req),
    .edn_i           (edn_rsp),
    .alert_tx_i      (alert_tx_i),
    .alert_rx_o      (),
    .esc_rx_i        (esc_rx_i),
    .esc_tx_o        (esc_tx_o)
  );

endmodule
