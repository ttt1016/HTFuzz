// PickerFuzz per-IP wrapper — HMAC standalone DUT (M5)
// ============================================================
// 把 C++ harness 的简化请求翻译成 TL-UL 完整握手，实例化完整 hmac IP。
// 其余输入 tie-off（alert_rx / keymgr sideload）。
// ============================================================

module hmac_perip_tb (
  input  logic clk_i,
  input  logic rst_ni,

  // 简化主机接口（C++ harness 驱动）
  input  logic        cb_valid,     // 请求有效
  input  logic [31:0] cb_addr,      // 字节地址
  input  logic        cb_write,     // 1=write 0=read
  input  logic [31:0] cb_wdata,
  input  logic [3:0]  cb_wmask,
  output logic        cb_done,      // 事务完成（d_valid）
  output logic [31:0] cb_rdata,     // 读数据
  output logic        cb_error      // D 通道错误
);

  import tlul_pkg::*;

  // -------------------------------------------------------------------------
  // TL-UL 通道
  // ---------------------------------------------------------------------------
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;

  // 请求锁存
  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;

  // FSM: IDLE → REQ(等 a_ready) → RESP(等 d_valid)
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

  // A 通道驱动（cmd_intg/data_intg 用 tlul_pkg 的真实 ECC 计算函数，
  // 与 OpenTitan DV agent 行为一致——全 1 默认值会触发 intg 校验错误）
  tlul_pkg::tl_h2d_t tl_a;
  always_comb begin
    tl_a                   = tlul_pkg::TL_H2D_DEFAULT;
    tl_a.a_valid           = (drv_q == DRV_REQ);
    tl_a.a_opcode          = req_write_q ? (req_wmask_q == 4'hF ? tlul_pkg::PutFullData : tlul_pkg::PutPartialData) : tlul_pkg::Get;
    tl_a.a_param           = '0;
    tl_a.a_size            = 2'b10;  // 4 bytes
    tl_a.a_mask            = req_write_q ? req_wmask_q : 4'hF;
    tl_a.a_source          = '0;
    tl_a.a_address         = req_addr_q;
    tl_a.a_data            = req_wdata_q;
    tl_a.a_user.instr_type = prim_mubi_pkg::MuBi4False;
    tl_a.a_user.cmd_intg   = tlul_pkg::get_cmd_intg(tl_a);
    tl_a.a_user.data_intg  = tlul_pkg::get_data_intg(req_wdata_q);
  end

  assign tl_h2d = tl_a;

  // D 通道接收
  assign cb_done  = (drv_q == DRV_RESP) && tl_d2h.d_valid;
  assign cb_rdata = tl_d2h.d_data;
  assign cb_error = tl_d2h.d_error;

  // -------------------------------------------------------------------------
  // DUT: 完整 hmac IP
  // ---------------------------------------------------------------------------
  logic intr_done, intr_fifo_empty, intr_err;
  prim_mubi_pkg::mubi4_t idle;
  prim_alert_pkg::alert_tx_t [hmac_reg_pkg::NumAlerts-1:0] alert_tx;
  prim_alert_pkg::alert_rx_t [hmac_reg_pkg::NumAlerts-1:0] alert_rx;

  assign alert_rx = '0;

  hmac u_dut (
    .clk_i,
    .rst_ni,
    .tl_i        (tl_h2d),
    .tl_o        (tl_d2h),
    .alert_rx_i  (alert_rx),
    .alert_tx_o  (alert_tx),
    .intr_hmac_done_o  (intr_done),
    .intr_fifo_empty_o (intr_fifo_empty),
    .intr_hmac_err_o   (intr_err),
    .idle_o            (idle)
  );

endmodule
