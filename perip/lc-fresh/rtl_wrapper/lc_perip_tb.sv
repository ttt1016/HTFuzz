// HTFuzz per-IP wrapper — LC_CTRL standalone DUT
// UseDmiInterface=1 绕开 dmi_jtag/dm 包; kmac/otp_prog 自应答防挂死
module lc_perip_tb (
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
  import prim_mubi_pkg::*;
  import lc_ctrl_pkg::*;
  import lc_ctrl_state_pkg::*;
  import lc_ctrl_reg_pkg::*;
  import otp_ctrl_pkg::*;
  import kmac_pkg::*;
  import otp_macro_pkg::*;
  import prim_esc_pkg::*;
  import jtag_pkg::*;

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
  // DUT: lc_ctrl（tie-off: dmi/jtag/esc/pwr/otp/kmac 接口）
  // ---------------------------------------------------------------------------
  // KMAC 同步时钟
  logic clk_kmac, rst_kmac_n;
  assign clk_kmac   = clk_i;
  assign rst_kmac_n = rst_ni;

  // pwrmgr 接口: 持续 lc_init 请求（FSM 内部握手）
  pwr_lc_req_t pwr_lc_in;
  pwr_lc_rsp_t pwr_lc_out;
  assign pwr_lc_in.lc_init = 1'b1;

  // alert 通道: idle（p/n 反相）
  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;
  initial begin
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end

  // escalation: idle 差分
  esc_rx_t esc_rx0, esc_rx1;
  esc_tx_t esc_tx0, esc_tx1;
  assign esc_rx0 = ESC_RX_DEFAULT;
  assign esc_rx1 = ESC_RX_DEFAULT;

  // OTP life-cycle 广播: 显式合法值（Dev 状态, 计数 15）
  otp_lc_data_t otp_lc_data;
  assign otp_lc_data = '{
    valid: 1'b1,
    error: 1'b0,
    state: lc_state_t'(LcStDev),
    count: lc_cnt_t'(LcCnt15),
    secrets_valid: Off,
    test_tokens_valid: Off,
    test_unlock_token: '0,
    test_exit_token: '0,
    rma_token_valid: Off,
    rma_token: '0
  };

  // OTP program 接口: 自应答（ack 跟随 req, 防转移流程挂死）
  lc_otp_program_req_t lc_prog_out;
  lc_otp_program_rsp_t lc_prog_in;
  assign lc_prog_in.err = 1'b0;
  assign lc_prog_in.ack = lc_prog_out.req;

  // KMAC token hash 接口: 即时应答（done 跟随 valid, 摘要为固定图案）
  app_req_t kmac_req;
  app_rsp_t kmac_rsp;
  assign kmac_rsp.ready = 1'b1;
  assign kmac_rsp.done  = kmac_req.valid;
  assign kmac_rsp.error = 1'b0;
  assign kmac_rsp.digest_share0 = 384'h01234567_89ABCDEF_0F1E2D3C_4B5A6978_87766554_43322110;
  assign kmac_rsp.digest_share1 = 384'hFEDCBA98_76543210_C3D4E5F6_0718293A_5B6C7D8E_9FA0B1C2;

  // OTP vendor test / device id tie-off
  otp_test_rsp_t vendor_test_out;
  otp_device_id_t device_id;
  otp_device_id_t manuf_state;
  assign device_id    = {8{32'hA5A5_0001}};
  assign manuf_state  = {8{32'h5A5A_00FF}};

  // JTAG / DMI / scan tie-off（UseDmiInterface=1 时 jtag 在内部被 tie）
  jtag_req_t jtag_req_in;
  jtag_rsp_t jtag_rsp_out;
  assign jtag_req_in = JTAG_REQ_DEFAULT;
  tlul_pkg::tl_h2d_t dmi_tl_in;
  tlul_pkg::tl_d2h_t dmi_tl_out;
  assign dmi_tl_in = tlul_pkg::TL_H2D_DEFAULT;

  // 输出保持线（防剪除）
  lc_tx_t lc_dft_en, lc_raw_test_rma, lc_nvm_debug_en, lc_hw_debug_en, lc_cpu_en;
  lc_tx_t lc_creator_seed_sw_rw_en, lc_owner_seed_sw_rw_en, lc_iso_part_sw_rd_en;
  lc_tx_t lc_iso_part_sw_wr_en, lc_seed_hw_rd_en, lc_keymgr_en, lc_escalate_en;
  lc_tx_t lc_check_byp_en, lc_clk_byp_req, lc_flash_rma_req;
  logic   strap_en_override;
  lc_flash_rma_seed_t rma_seed;
  lc_keymgr_div_t     keymgr_div;
  lc_hw_rev_t         hw_rev;

  lc_ctrl #(
    .UseDmiInterface(1'b1)
  ) u_dut (
    .clk_i(clk_i), .rst_ni(rst_ni),
    .clk_kmac_i(clk_kmac), .rst_kmac_ni(rst_kmac_n),
    .regs_tl_i(tl_h2d), .regs_tl_o(tl_d2h),
    .dmi_tl_i(dmi_tl_in), .dmi_tl_o(dmi_tl_out),
    .jtag_i(jtag_req_in), .jtag_o(jtag_rsp_out),
    .scan_rst_ni(1'b1), .scanmode_i(MuBi4False),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .esc_scrap_state0_tx_i(esc_rx0), .esc_scrap_state0_rx_o(esc_tx0),
    .esc_scrap_state1_tx_i(esc_rx1), .esc_scrap_state1_rx_o(esc_tx1),
    .pwr_lc_i(pwr_lc_in), .pwr_lc_o(pwr_lc_out),
    .strap_en_override_o(strap_en_override),
    .lc_otp_vendor_test_o(vendor_test_out),
    .lc_otp_vendor_test_i('{status: '0}),
    .lc_otp_program_o(lc_prog_out), .lc_otp_program_i(lc_prog_in),
    .kmac_data_i(kmac_rsp), .kmac_data_o(kmac_req),
    .otp_lc_data_i(otp_lc_data),
    .lc_dft_en_o(lc_dft_en),
    .lc_raw_test_rma_o(lc_raw_test_rma),
    .lc_nvm_debug_en_o(lc_nvm_debug_en),
    .lc_hw_debug_en_o(lc_hw_debug_en),
    .lc_cpu_en_o(lc_cpu_en),
    .lc_creator_seed_sw_rw_en_o(lc_creator_seed_sw_rw_en),
    .lc_owner_seed_sw_rw_en_o(lc_owner_seed_sw_rw_en),
    .lc_iso_part_sw_rd_en_o(lc_iso_part_sw_rd_en),
    .lc_iso_part_sw_wr_en_o(lc_iso_part_sw_wr_en),
    .lc_seed_hw_rd_en_o(lc_seed_hw_rd_en),
    .lc_keymgr_en_o(lc_keymgr_en),
    .lc_escalate_en_o(lc_escalate_en),
    .lc_check_byp_en_o(lc_check_byp_en),
    .lc_clk_byp_req_o(lc_clk_byp_req),
    .lc_clk_byp_ack_i(Off),
    .lc_flash_rma_seed_o(rma_seed),
    .lc_flash_rma_req_o(lc_flash_rma_req),
    .lc_flash_rma_ack_i('{default: Off}),
    .lc_keymgr_div_o(keymgr_div),
    .otp_device_id_i(device_id),
    .otp_manuf_state_i(manuf_state),
    .hw_rev_o(hw_rev)
  );

  // 防剪除
  logic unused_lc;
  assign unused_lc = ^{lc_dft_en, lc_raw_test_rma, lc_nvm_debug_en, lc_hw_debug_en,
                       lc_cpu_en, lc_creator_seed_sw_rw_en, lc_owner_seed_sw_rw_en,
                       lc_iso_part_sw_rd_en, lc_iso_part_sw_wr_en, lc_seed_hw_rd_en,
                       lc_keymgr_en, lc_escalate_en, lc_check_byp_en, lc_clk_byp_req,
                       lc_flash_rma_req, strap_en_override, rma_seed, keymgr_div,
                       hw_rev, jtag_rsp_out, dmi_tl_out, esc_tx0, esc_tx1,
                       pwr_lc_out, vendor_test_out};
endmodule
