// PickerFuzz per-IP wrapper — CSRNG standalone DUT
// ============================================================
// C++ harness 的简化请求经 cb_* 翻译成 TL-UL 完整握手（真实 intg ECC）。
// 时钟由 harness 驱动（无 #delay）；旧的 SV task 激励/$finish 已移除。
// ============================================================

module csrng_perip_tb (
  input  logic        clk_i,
  input  logic        rst_ni,
  // 简化主机接口（C++ harness 驱动）
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
  import csrng_pkg::*;
  import csrng_reg_pkg::*;
  import entropy_src_pkg::*;
  import prim_mubi_pkg::*;

  // -------------------------------------------------------------------------
  // TL-UL 驱动 FSM（同 hmac wrapper 模式）
  // -------------------------------------------------------------------------
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;

  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;

  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      drv_q <= DRV_IDLE;
    end else begin
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
      req_addr_q  <= '0;
      req_write_q <= 1'b0;
      req_wdata_q <= '0;
      req_wmask_q <= '0;
    end else if (cb_valid && drv_q == DRV_IDLE) begin
      req_addr_q  <= cb_addr;
      req_write_q <= cb_write;
      req_wdata_q <= cb_wdata;
      req_wmask_q <= cb_wmask;
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

  // -------------------------------------------------------------------------
  // DUT: 完整 csrng IP（tie-off 与原 wrapper 一致）
  // -------------------------------------------------------------------------
  localparam int NHwApps = 2;
  localparam int NumAlerts = 2;

  prim_mubi_pkg::mubi8_t otp_en_csrng_sw_app_read;
  lc_ctrl_pkg::lc_tx_t lc_hw_debug_en;

  entropy_src_hw_if_req_t entropy_src_hw_if;
  entropy_src_hw_if_rsp_t entropy_src_hw_if_i;
  logic [63:0] esrng_lfsr_q;
  // LFSR 不随 DUT reset 重置（模拟真实 entropy_src 连续运行）
  initial esrng_lfsr_q = 64'hDEADBEEFCAFEBABE;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) esrng_lfsr_q <= 64'hDEADBEEFCAFEBABE;
    else esrng_lfsr_q <= {esrng_lfsr_q[62:0],
                          esrng_lfsr_q[63]^esrng_lfsr_q[61]^esrng_lfsr_q[40]^esrng_lfsr_q[0]};
  end
  assign entropy_src_hw_if_i = '{es_ack: 1'b1, es_bits: esrng_lfsr_q, es_fips: 4'hF};

  cs_aes_halt_req_t cs_aes_halt_i;
  cs_aes_halt_rsp_t cs_aes_halt_o;
  assign cs_aes_halt_i.cs_aes_halt_req = 1'b0;

  csrng_req_t [NHwApps-1:0] csrng_cmd_i;
  csrng_rsp_t [NHwApps-1:0] csrng_cmd_o;

  logic [NumAlerts-1:0] alert_rx_int;
  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;

  logic intr_cs_cmd_req_done, intr_cs_entropy_req, intr_cs_hw_inst_exc, intr_cs_fatal_err;

  csrng u_dut (
    .clk_i(clk_i), .rst_ni(rst_ni),
    .tl_i(tl_h2d), .tl_o(tl_d2h),
    .otp_en_csrng_sw_app_read_i(otp_en_csrng_sw_app_read),
    .lc_hw_debug_en_i(lc_hw_debug_en),
    .entropy_src_hw_if_o(entropy_src_hw_if),
    .entropy_src_hw_if_i(entropy_src_hw_if_i),
    .cs_aes_halt_i(cs_aes_halt_i),
    .cs_aes_halt_o(cs_aes_halt_o),
    .csrng_cmd_i(csrng_cmd_i),
    .csrng_cmd_o(csrng_cmd_o),
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .intr_cs_cmd_req_done_o(intr_cs_cmd_req_done),
    .intr_cs_entropy_req_o(intr_cs_entropy_req),
    .intr_cs_hw_inst_exc_o(intr_cs_hw_inst_exc),
    .intr_cs_fatal_err_o(intr_cs_fatal_err)
  );

  initial begin
    otp_en_csrng_sw_app_read = prim_mubi_pkg::MuBi8True;
    lc_hw_debug_en = lc_ctrl_pkg::Off;
    csrng_cmd_i = '{default: '{csrng_req_valid: 1'b0, csrng_req_bus: '0, genbits_ready: 1'b0}};
    alert_rx_int = '0;
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end

endmodule
