// PickerFuzz per-IP wrapper — ADC_CTRL standalone DUT
// 双时钟: clk_i（harness 主时钟）+ clk_aon_i（同源分频由 harness 驱动）
module adc_ctrl_perip_tb (
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
  import adc_ctrl_reg_pkg::*;
  import prim_mubi_pkg::*;

  // TL 驱动 FSM
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
      req_addr_q <= '0; req_write_q <= 1'b0; req_wdata_q <= '0; req_wmask_q <= '0;
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

  // AON 时钟: 主时钟 4 分频
  logic clk_aon_i;
  logic [1:0] aon_div = 2'b0;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) aon_div <= 2'b0;
    else aon_div <= aon_div + 1'b1;
  end
  assign clk_aon_i = aon_div[1];
  logic rst_aon_ni;
  assign rst_aon_ni = rst_ni;

  // AST ADC 接口 stub: 周期性提供转换数据
  ast_pkg::adc_ast_req_t adc_req;
  ast_pkg::adc_ast_rsp_t adc_rsp;
  logic [9:0] ast_data = 10'h1A5;
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      adc_rsp.data_valid <= 1'b0;
      adc_rsp.data       <= '0;
    end else begin
      adc_rsp.data       <= ast_data + ast_data[5:0];
      adc_rsp.data_valid <= adc_req.channel_sel != 2'b0;
    end
  end

  logic intr_match, wkup_req;
  prim_alert_pkg::alert_rx_t [adc_ctrl_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [adc_ctrl_reg_pkg::NumAlerts-1:0] alert_tx;

  adc_ctrl u_dut (
    .clk_i(clk_i), .clk_aon_i(clk_aon),
    .rst_ni(rst_ni), .rst_aon_ni(rst_aon_n),
    .tl_i(tl_h2d), .tl_o(tl_d2h),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .adc_o(adc_req), .adc_i(adc_rsp),
    .intr_match_pending_o(intr_match),
    .wkup_req_o(wkup_req)
  );

  // 防剪除
  logic [1:0] dbg_state;
  always_ff @(posedge clk_i) begin
    dbg_state <= {adc_req.channel_sel, wkup_req};
  end

  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end
endmodule
