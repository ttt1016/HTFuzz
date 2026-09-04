// HTFuzz per-IP wrapper — entropy_src standalone DUT（fresh 版接口）
// fresh entropy_src: RNG 拍平（enable/valid/bits）、xht 改 meta req/rsp、无 cs_aes_halt
module entropy_src_perip_tb (
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
  import entropy_src_pkg::*;
  import entropy_src_reg_pkg::*;  // NumAlerts
  import prim_mubi_pkg::*;
  localparam int RngBusWidth = 4;  // entropy_src_core 同参

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
  // DUT: entropy_src（fresh 接口: RNG 拍平, xht meta, 无 cs_aes_halt）
  // ---------------------------------------------------------------------------
  logic intr_es_entropy_valid, intr_es_health_test_failed, intr_es_observe_fifo_ready, intr_es_fatal_err;
  entropy_src_pkg::entropy_src_hw_if_req_t es_hw_if_req;
  entropy_src_pkg::entropy_src_hw_if_rsp_t es_hw_if_rsp;
  logic entropy_src_rng_enable;
  logic entropy_src_rng_valid;
  logic [3:0] entropy_src_rng_bits;
  entropy_src_pkg::entropy_src_xht_meta_req_t xht_meta_req;
  entropy_src_pkg::entropy_src_xht_meta_rsp_t xht_meta_rsp;
  logic rng_fips;

  // LFSR 供数（RNG 常供）
  logic [31:0] lfsr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) lfsr_q <= 32'hACE1_0001;
    else         lfsr_q <= {lfsr_q[30:0], lfsr_q[31] ^ lfsr_q[21] ^ lfsr_q[1] ^ lfsr_q[0]};
  end
  assign entropy_src_rng_valid = 1'b1;
  assign entropy_src_rng_bits  = lfsr_q[3:0];

  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;
  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end

  entropy_src u_dut (
    .clk_i        (clk_i),
    .rst_ni       (rst_ni),
    .tl_i         (tl_h2d),
    .tl_o         (tl_d2h),
    .otp_en_entropy_src_fw_read_i  (prim_mubi_pkg::MuBi8True),
    .otp_en_entropy_src_fw_over_i  (prim_mubi_pkg::MuBi8True),
    .rng_fips_o   (rng_fips),
    .entropy_src_hw_if_i (es_hw_if_req),
    .entropy_src_hw_if_o (es_hw_if_rsp),
    .entropy_src_rng_enable_o (entropy_src_rng_enable),
    .entropy_src_rng_valid_i  (entropy_src_rng_valid),
    .entropy_src_rng_bits_i   (entropy_src_rng_bits),
    .entropy_src_xht_valid_o  (),
    .entropy_src_xht_bits_o   (),
    .entropy_src_xht_bit_sel_o(),
    .entropy_src_xht_health_test_window_o (),
    .entropy_src_xht_meta_o   (xht_meta_req),
    .entropy_src_xht_meta_i   (xht_meta_rsp),
    .alert_rx_i  (alert_rx),
    .alert_tx_o  (alert_tx),
    .intr_es_entropy_valid_o        (intr_es_entropy_valid),
    .intr_es_health_test_failed_o   (intr_es_health_test_failed),
    .intr_es_observe_fifo_ready_o   (intr_es_observe_fifo_ready),
    .intr_es_fatal_err_o            (intr_es_fatal_err)
  );

  // es_hw_if_req 未接 CSRNG → tie-off（本 DUT 只测 FW_OV 路径和健康检查）
  assign es_hw_if_req = '0;
  assign xht_meta_rsp = ENTROPY_SRC_XHT_META_RSP_DEFAULT;

  // 防剪除
  logic unused_es;
  assign unused_es = ^{es_hw_if_rsp, xht_meta_req, entropy_src_rng_enable, rng_fips,
                       intr_es_entropy_valid, intr_es_health_test_failed,
                       intr_es_observe_fifo_ready, intr_es_fatal_err};

endmodule
