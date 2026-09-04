// HTFuzz per-IP wrapper — MBX standalone DUT
// cb_* TL → core 侧寄存器; soc 侧 tie-off; 私有 SRAM 主机口用最小 TL responder 喂
// （响应经 tlul_rsp_intg_gen 补完整性，避免 host 侧 intg 检查卡死）
module mbx_perip_tb (
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
  import mbx_reg_pkg::*;
  import top_racl_pkg::*;
  import prim_mubi_pkg::*;

  // TL 驱动 FSM（core 侧）
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
  // 私有 SRAM TL responder（mbx 的 sram host 口 → 1 拍读响应图案数据）
  // ---------------------------------------------------------------------------
  tlul_pkg::tl_h2d_t sram_h2d;
  tlul_pkg::tl_d2h_t sram_d2h_raw, sram_d2h;
  logic sram_a_valid_q;

  assign sram_d2h_raw.a_ready = 1'b1;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sram_d2h_raw.d_valid  <= 1'b0;
      sram_d2h_raw.d_data   <= '0;
      sram_d2h_raw.d_error  <= 1'b0;
      sram_d2h_raw.d_opcode <= tlul_pkg::AccessAckData;
      sram_d2h_raw.d_size   <= 2'b10;
      sram_d2h_raw.d_source <= '0;
      sram_d2h_raw.d_sink   <= '0;
      sram_d2h_raw.d_user   <= '0;
    end else begin
      sram_d2h_raw.d_valid <= 1'b0;
      if (sram_h2d.a_valid && sram_d2h_raw.a_ready) begin
        if (sram_h2d.a_opcode == tlul_pkg::Get) begin
          sram_d2h_raw.d_valid  <= 1'b1;
          sram_d2h_raw.d_opcode <= tlul_pkg::AccessAckData;
          sram_d2h_raw.d_data   <= {16'b0, sram_h2d.a_address[15:0]} ^ 32'hC0DE_0D00;
        end else begin
          sram_d2h_raw.d_valid  <= 1'b1;
          sram_d2h_raw.d_opcode <= tlul_pkg::AccessAck;
        end
        sram_d2h_raw.d_source <= sram_h2d.a_source;
        sram_d2h_raw.d_size   <= sram_h2d.a_size;
      end
    end
  end

  tlul_rsp_intg_gen #(
    .EnableRspIntgGen (1'b1),
    .EnableDataIntgGen(1'b1)
  ) u_sram_rsp_intg (
    .tl_i (sram_d2h_raw),
    .tl_o (sram_d2h)
  );

  // ---------------------------------------------------------------------------
  // DUT: mbx
  // ---------------------------------------------------------------------------
  logic intr_ready, intr_abort, intr_error;
  logic doe_intr_support, doe_intr_en, doe_intr, doe_async_msg_support;
  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;
  racl_policy_vec_t racl_policies;
  racl_error_log_t  racl_error;
  tlul_pkg::tl_h2d_t soc_h2d;
  tlul_pkg::tl_d2h_t soc_d2h;

  initial begin
    alert_rx     = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
    racl_policies = '0;
    soc_h2d       = tlul_pkg::TL_H2D_DEFAULT;
  end

  mbx #(
    .EnableRacl      (1'b0),
    .RaclErrorRsp    (1'b0)
  ) u_dut (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),
    .intr_mbx_ready_o (intr_ready),
    .intr_mbx_abort_o (intr_abort),
    .intr_mbx_error_o (intr_error),
    .doe_intr_support_o     (doe_intr_support),
    .doe_intr_en_o          (doe_intr_en),
    .doe_intr_o             (doe_intr),
    .doe_async_msg_support_o(doe_async_msg_support),
    .alert_rx_i (alert_rx),
    .alert_tx_o (alert_tx),
    .racl_policies_i (racl_policies),
    .racl_error_o    (racl_error),
    .core_tl_d_i (tl_h2d),
    .core_tl_d_o (tl_d2h),
    .soc_tl_d_i  (soc_h2d),
    .soc_tl_d_o  (soc_d2h),
    .sram_tl_h_i (sram_d2h),
    .sram_tl_h_o (sram_h2d)
  );

  // 防剪除
  logic unused_mbx;
  assign unused_mbx = ^{intr_ready, intr_abort, intr_error,
                        doe_intr_support, doe_intr_en, doe_intr,
                        doe_async_msg_support, racl_error, soc_d2h};

endmodule
