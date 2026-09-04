// PickerFuzz per-IP wrapper — ascon standalone DUT
module ascon_perip_tb (
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

  // EDN 模拟: LFSR 伪随机
  logic clk_edn, rst_edn_n;
  assign clk_edn = clk_i;
  assign rst_edn_n = rst_ni;
  logic [31:0] lfsr_q;
  always_ff @(posedge clk_edn or negedge rst_edn_n) begin
    if (!rst_edn_n) lfsr_q <= 32'hACE1ACE5;
    else lfsr_q <= {lfsr_q[30:0], lfsr_q[31]^lfsr_q[21]^lfsr_q[1]^lfsr_q[0]};
  end
  edn_pkg::edn_req_t edn_req_i;
  edn_pkg::edn_rsp_t edn_rsp;
  always_comb begin
    edn_rsp = edn_pkg::EDN_RSP_DEFAULT;
    edn_rsp.edn_ack = edn_req_i.edn_req;
    edn_rsp.edn_fips = 1'b1;
    edn_rsp.edn_bus = lfsr_q;
  end

  // keymgr key: 固定测试密钥
  keymgr_pkg::hw_key_req_t keymgr_key;
  always_comb begin
    keymgr_key = keymgr_pkg::HW_KEY_REQ_DEFAULT;
    keymgr_key.valid = 1'b1;
    keymgr_key.key[0] = 128'hDEADBEEF0123456789ABCDEF00112233;
    keymgr_key.key[1] = 128'hFEDCBA98765432100123456789ABCDEF;
  end

  // lc escalation 控制: cb 写 0x8000 地址时设置（harness 专用通道）
  lc_ctrl_pkg::lc_tx_t lc_escalate_ctrl;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) lc_escalate_ctrl <= lc_ctrl_pkg::Off;
    else if (cb_valid && cb_write && cb_addr[15]) lc_escalate_ctrl <= lc_ctrl_pkg::On;
  end
  logic rst_shadowed_n;
  assign rst_shadowed_n = rst_ni;
  prim_mubi_pkg::mubi4_t idle;
  logic [ascon_reg_pkg::NumAlerts-1:0] alert_tx, alert_rx_int;
  prim_alert_pkg::alert_rx_t [ascon_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  ascon u_dut (
    .clk_i, .rst_ni,
    .rst_shadowed_ni (rst_shadowed_n),
    .idle_o          (idle),
    .lc_escalate_en_i (lc_escalate_ctrl),
    .clk_edn_i  (clk_edn),
    .rst_edn_ni (rst_edn_n),
    .edn_o      (edn_req_i),
    .edn_i      (edn_rsp),
    .keymgr_key_i (keymgr_key),
    .tl_i       (tl_h2d),
    .tl_o       (tl_d2h),
    .alert_rx_i (alert_rx),
    .alert_tx_o (alert_tx)
  );

endmodule
