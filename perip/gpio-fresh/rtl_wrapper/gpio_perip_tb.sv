// PickerFuzz per-IP wrapper — GPIO standalone DUT
// cb_* TL 接口（同 hmac/uart 模式），gpio 原始 IO 由 harness 驱动
module gpio_perip_tb (
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
  import gpio_pkg::*;
  import gpio_reg_pkg::*;
  import top_racl_pkg::*;
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

  // DUT
  localparam int NumIOs = gpio_reg_pkg::NumIOs;
  logic strap_en = 1'b0;
  gpio_pkg::gpio_straps_t sampled_straps;
  logic [NumIOs-1:0] cio_gpio_in = '0;
  logic [NumIOs-1:0] cio_gpio_out, cio_gpio_en;
  logic [NumIOs-1:0] intr_gpio;
  prim_alert_pkg::alert_rx_t [gpio_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [gpio_reg_pkg::NumAlerts-1:0] alert_tx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;

  gpio u_dut (
    .clk_i(clk_i), .rst_ni(rst_ni),
    .strap_en_i(strap_en),
    .sampled_straps_o(sampled_straps),
    .tl_i(tl_h2d), .tl_o(tl_d2h),
    .intr_gpio_o(intr_gpio),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .racl_policies_i(racl_policies), .racl_error_o(racl_error),
    .cio_gpio_i(cio_gpio_in),
    .cio_gpio_o(cio_gpio_out),
    .cio_gpio_en_o(cio_gpio_en)
  );
  logic [NumIOs-1:0] cio_gpio_out_d, cio_gpio_en_d;
  always_ff @(posedge clk_i) begin
    cio_gpio_out_d <= cio_gpio_out;
    cio_gpio_en_d  <= cio_gpio_en;
  end

  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
    racl_policies = '0;
  end
endmodule
