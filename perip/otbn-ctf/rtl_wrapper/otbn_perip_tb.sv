// HTFuzz per-IP wrapper — OTBN standalone DUT
// cb_* TL → 寄存器口（含 IMEM/DMEM 窗口）; edn×2 自应答; OTP key 自应答; lc tie-off
module otbn_perip_tb (
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
  import otbn_pkg::*;
  import otbn_reg_pkg::*;
  import prim_mubi_pkg::*;
  import lc_ctrl_pkg::*;
  import edn_pkg::*;
  import otp_ctrl_pkg::*;
  import keymgr_pkg::*;
  import prim_ram_1p_pkg::*;

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
  // EDN 自应答 ×2（rnd/urnd）: ack=req, 32bit 图案数据
  // ---------------------------------------------------------------------------
  edn_req_t rnd_req, urnd_req;
  edn_rsp_t rnd_rsp, urnd_rsp;
  logic fips_q;
  initial fips_q = 1'b0;
  always_ff @(posedge clk_i) fips_q <= ~fips_q;
  assign rnd_rsp.edn_ack  = rnd_req.edn_req;
  assign rnd_rsp.edn_fips = fips_q;
  assign rnd_rsp.edn_bus  = {fips_q, ~fips_q, 30'h5EED_0001};
  assign urnd_rsp.edn_ack  = urnd_req.edn_req;
  assign urnd_rsp.edn_fips = ~fips_q;
  assign urnd_rsp.edn_bus  = {~fips_q, fips_q, 30'h5EED_0002};

  // OTP scrambling key 自应答: ack=req, 固定 key 图案
  otbn_otp_key_req_t otp_key_req;
  otbn_otp_key_rsp_t otp_key_rsp;
  logic otp_ack_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) otp_ack_q <= 1'b0;
    else         otp_ack_q <= otp_key_req.req;
  end
  assign otp_key_rsp.ack        = otp_ack_q;
  assign otp_key_rsp.seed_valid = 1'b1;
  assign otp_key_rsp.key        = 128'h0F1E_2D3C_4B5A_6978_8796_A5B4_C3D2_E1F0;
  assign otp_key_rsp.nonce      = 256'hFE_DC_BA98_7654_3210_0F1E_2D3C_4B5A_6978_8796_A5B4_C3D2_E1F0_0123_4567;

  // ---------------------------------------------------------------------------
  // DUT: otbn
  // ---------------------------------------------------------------------------
  prim_mubi_pkg::mubi4_t idle;
  logic intr_done;
  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;
  lc_tx_t lc_rma_ack;
  ram_1p_cfg_rsp_t ram_cfg_rsp_imem, ram_cfg_rsp_dmem;
  logic unused_ram_cfg;

  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end

  otbn #(
    .RegFile (RegFileFF)
  ) u_dut (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),
    .tl_i   (tl_h2d),
    .tl_o   (tl_d2h),
    .idle_o (idle),
    .intr_done_o (intr_done),
    .alert_rx_i (alert_rx),
    .alert_tx_o (alert_tx),
    .lc_escalate_en_i (Off),
    .lc_rma_req_i (Off),
    .lc_rma_ack_o (lc_rma_ack),
    .ram_cfg_imem_i (RAM_1P_CFG_DEFAULT),
    .ram_cfg_dmem_i (RAM_1P_CFG_DEFAULT),
    .ram_cfg_rsp_imem_o (ram_cfg_rsp_imem),
    .ram_cfg_rsp_dmem_o (ram_cfg_rsp_dmem),
    .clk_edn_i  (clk_i),
    .rst_edn_ni (rst_ni),
    .edn_rnd_o  (rnd_req),
    .edn_rnd_i  (rnd_rsp),
    .edn_urnd_o (urnd_req),
    .edn_urnd_i (urnd_rsp),
    .clk_otp_i  (clk_i),
    .rst_otp_ni (rst_ni),
    .otbn_otp_key_o (otp_key_req),
    .otbn_otp_key_i (otp_key_rsp),
    .keymgr_key_i ('{valid: 1'b1, key: '{128'h1111_2222_3333_4444_5555_6666_7777_8888,
                                            128'h9999_AAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0000}})
  );

  // 防剪除
  assign unused_ram_cfg = ^{idle, intr_done, lc_rma_ack,
                            ram_cfg_rsp_imem.done, ram_cfg_rsp_dmem.done};
  logic unused_otbn;
  assign unused_otbn = ^{alert_tx};

endmodule
