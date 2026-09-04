// PickerFuzz per-IP wrapper — rom_ctrl standalone DUT（rom 口驱动，regs 口 tie-off）
module rom_ctrl_perip_tb (
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

  // ROM 口驱动 FSM
  tlul_pkg::tl_h2d_t rom_tl_h2d;
  tlul_pkg::tl_d2h_t rom_tl_d2h;
  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;
  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) drv_q <= DRV_IDLE;
    else unique case (drv_q)
      DRV_IDLE: if (cb_valid)          drv_q <= DRV_REQ;
      DRV_REQ:  if (rom_tl_d2h.a_ready) drv_q <= DRV_RESP;
      DRV_RESP: if (rom_tl_d2h.d_valid) drv_q <= DRV_IDLE;
      default:                          drv_q <= DRV_IDLE;
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
  assign rom_tl_h2d = tl_a;
  assign cb_done  = (drv_q == DRV_RESP) && rom_tl_d2h.d_valid;
  assign cb_rdata = rom_tl_d2h.d_data;
  assign cb_error = rom_tl_d2h.d_error;

  // regs 口 tie-off（不活动）
  tlul_pkg::tl_h2d_t regs_tl_h2d;
  tlul_pkg::tl_d2h_t regs_tl_d2h;
  assign regs_tl_h2d = tlul_pkg::TL_H2D_DEFAULT;

  // kmac tie-off
  kmac_pkg::app_req_t kmac_data_o;
  kmac_pkg::app_rsp_t kmac_data_i;
  assign kmac_data_i = 0;

  import prim_rom_pkg::rom_cfg_req_t;
  import prim_rom_pkg::rom_cfg_rsp_t;
  // fresh prim_rom_pkg 的 req/rsp 双向 cfg 接口
  rom_cfg_req_t rom_cfg_req;
  rom_cfg_rsp_t rom_cfg_rsp;
  assign rom_cfg_req = prim_rom_pkg::ROM_CFG_REQ_DEFAULT;

  logic [rom_ctrl_reg_pkg::NumAlerts-1:0] alert_tx, alert_rx_int;
  prim_alert_pkg::alert_rx_t [rom_ctrl_reg_pkg::NumAlerts-1:0] alert_rx;
  assign alert_rx = 0;

  rom_ctrl_pkg::pwrmgr_data_t pwrmgr_data;
  rom_ctrl_pkg::keymgr_data_t keymgr_data;

  rom_ctrl #(
    .SecDisableScrambling(1'b1),  // 简化: 关闭扰码
    .BootRomInitFile("/workspace/pickerfuzz/perip/rom_ctrl-ctf/obj_so/rom.mem")
  ) u_dut (
    .clk_i, .rst_ni,
    .rom_cfg_i     (rom_cfg_req),
    .rom_cfg_o     (rom_cfg_rsp),
    .rom_tl_i      (rom_tl_h2d),
    .rom_tl_o      (rom_tl_d2h),
    .regs_tl_i     (regs_tl_h2d),
    .regs_tl_o     (regs_tl_d2h),
    .alert_rx_i    (alert_rx),
    .alert_tx_o    (alert_tx),
    .pwrmgr_data_o (pwrmgr_data),
    .keymgr_data_o (keymgr_data),
    .kmac_data_i   (kmac_data_i),
    .kmac_data_o   (kmac_data_o)
  );

endmodule
