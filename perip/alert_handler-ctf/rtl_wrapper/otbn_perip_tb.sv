// PickerFuzz per-IP wrapper — otbn standalone DUT
module otbn_perip_tb (
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
  import otbn_pkg::*;
  import prim_mubi_pkg::*;
  import prim_alert_pkg::*;
  import edn_pkg::*;
  import lc_ctrl_pkg::*;
  import otp_ctrl_pkg::*;
  import keymgr_pkg::*;
  import prim_ram_1p_pkg::*;

  // EDN 时钟 1/2 分频
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

  // EDN 模拟（RND/URND 两个通道）
  logic [31:0] lfsr_rnd_q, lfsr_urnd_q;
  always_ff @(posedge clk_edn or negedge rst_edn_n) begin
    if (!rst_edn_n) begin
      lfsr_rnd_q <= 32'h12345678;
      lfsr_urnd_q <= 32'h9abcdef0;
    end else begin
      lfsr_rnd_q <= {lfsr_rnd_q[30:0], lfsr_rnd_q[31] ^ lfsr_rnd_q[21] ^ lfsr_rnd_q[1] ^ lfsr_rnd_q[0]};
      lfsr_urnd_q <= {lfsr_urnd_q[30:0], lfsr_urnd_q[31] ^ lfsr_urnd_q[15] ^ lfsr_urnd_q[3] ^ lfsr_urnd_q[2]};
    end
  end
  edn_req_t edn_rnd_o, edn_urnd_o;
  edn_rsp_t edn_rnd_i, edn_urnd_i;
  assign edn_rnd_i.edn_ack  = edn_rnd_o.edn_req;
  assign edn_rnd_i.edn_fips = 1'b1;
  assign edn_rnd_i.edn_bus  = lfsr_rnd_q;
  assign edn_urnd_i.edn_ack  = edn_urnd_o.edn_req;
  assign edn_urnd_i.edn_fips = 1'b1;
  assign edn_urnd_i.edn_bus  = lfsr_urnd_q;

  // lc tie-off
  lc_tx_t lc_escalate_en, lc_rma_req, lc_rma_ack;
  assign lc_escalate_en = Off;
  assign lc_rma_req = Off;

  // RAM cfg tie-off
  ram_1p_cfg_t ram_cfg_imem, ram_cfg_dmem;
  ram_1p_cfg_rsp_t ram_cfg_rsp_imem, ram_cfg_rsp_dmem;
  assign ram_cfg_imem = RAM_1P_CFG_DEFAULT;
  assign ram_cfg_dmem = RAM_1P_CFG_DEFAULT;

  // OTP key 响应模拟
  otbn_otp_key_req_t otbn_otp_key_o;
  otbn_otp_key_rsp_t otbn_otp_key_i;
  logic otp_ack_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) otp_ack_q <= 1'b0;
    else otp_ack_q <= otbn_otp_key_o.req;
  end
  assign otbn_otp_key_i.ack = otp_ack_q;
  assign otbn_otp_key_i.key = 128'h0f1571c9b98f203e8fe9a3cb32c4ab07;
  assign otbn_otp_key_i.seed_valid = 1'b1;

  // keymgr key tie-off
  otbn_key_req_t keymgr_key_i;
  assign keymgr_key_i.valid = 1'b1;
  assign keymgr_key_i.key = '0;

  prim_alert_pkg::alert_rx_t [otbn_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  mubi4_t idle;
  logic intr_done;

  otbn u_dut (
    .clk_i,
    .rst_ni,
    .tl_i            (tl_h2d),
    .tl_o            (tl_d2h),
    .idle_o          (idle),
    .intr_done_o     (intr_done),
    .alert_rx_i      (alert_rx),
    .alert_tx_o      (),
    .lc_escalate_en_i (lc_escalate_en),
    .lc_rma_req_i    (lc_rma_req),
    .lc_rma_ack_o    (lc_rma_ack),
    .ram_cfg_imem_i  (ram_cfg_imem),
    .ram_cfg_dmem_i  (ram_cfg_dmem),
    .ram_cfg_rsp_imem_o (ram_cfg_rsp_imem),
    .ram_cfg_rsp_dmem_o (ram_cfg_rsp_dmem),
    .edn_rnd_o       (edn_rnd_o),
    .edn_rnd_i       (edn_rnd_i),
    .edn_urnd_o      (edn_urnd_o),
    .edn_urnd_i      (edn_urnd_i),
    .otbn_otp_key_o  (otbn_otp_key_o),
    .otbn_otp_key_i  (otbn_otp_key_i),
    .keymgr_key_i    (keymgr_key_i)
  );

endmodule
