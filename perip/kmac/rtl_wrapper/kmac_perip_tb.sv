// PickerFuzz per-IP wrapper — KMAC standalone DUT (M5)
module kmac_perip_tb (
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
      req_addr_q <= 0; req_write_q <= 0; req_wdata_q <= 0; req_wmask_q <= 0;
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

  // DUT: kmac
  logic intr_done, intr_fifo_empty, intr_err;
  prim_mubi_pkg::mubi4_t idle;
  logic en_masking;
  prim_alert_pkg::alert_tx_t [kmac_reg_pkg::NumAlerts-1:0] alert_tx;
  prim_alert_pkg::alert_rx_t [kmac_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  keymgr_pkg::hw_key_req_t keymgr_key;
  assign keymgr_key.valid = 1'b0;
  assign keymgr_key.key   = 0;

  // app 接口 tie-off
  kmac_pkg::app_req_t [3:0] app_i;  // NumAppIntf=4 (kmac.sv 默认参数)
  kmac_pkg::app_rsp_t [3:0] app_o;
  assign app_i = 0;

  // edn tie-off
  edn_pkg::edn_req_t edn_o;
  edn_pkg::edn_rsp_t edn_i;
  assign edn_i = 0;

  lc_ctrl_pkg::lc_tx_t lc_escalate_en;
  assign lc_escalate_en = lc_ctrl_pkg::Off;

  kmac u_dut (
    .clk_i,
    .rst_ni,
    .rst_shadowed_ni(rst_ni),
    .clk_edn_i      (clk_i),
    .rst_edn_ni     (rst_ni),
    .tl_i           (tl_h2d),
    .tl_o           (tl_d2h),
    .alert_rx_i     (alert_rx),
    .alert_tx_o     (alert_tx),
    .keymgr_key_i   (keymgr_key),
    .app_i          (app_i),
    .app_o          (app_o),
    .entropy_o      (edn_o),
    .entropy_i      (edn_i),
    .lc_escalate_en_i(lc_escalate_en),
    .intr_kmac_done_o  (intr_done),
    .intr_fifo_empty_o (intr_fifo_empty),
    .intr_kmac_err_o   (intr_err),
    .en_masking_o      (en_masking),
    .idle_o            (idle)
  );
endmodule
