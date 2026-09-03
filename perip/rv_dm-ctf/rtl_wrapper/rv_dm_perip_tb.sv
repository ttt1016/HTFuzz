// PickerFuzz rv_dm per-IP testbench (JTAG DMI 安全边界检测)
// 时钟/复位/JTAG pad 全部由 harness（C++）直接驱动，无 #delay
// tms/td/trst/test_rst 声明为端口：避免 Verilator 常量折叠剪掉 harness 驱动点
module rv_dm_perip_tb (
  input  logic tms_i,
  input  logic td_i,
  input  logic trst_ni,
  input  logic test_rst_ni,
  input  logic clk_i,
  input  logic rst_ni,
  input  logic testmode_i,
  output logic td_o,
  output logic tdo_oe_o
);
  import dm::*;

  // ---- harness 驱动信号 ----
  logic tck_i     = 0;   // JTAG test clock（TAP 域，harness 经 rootp 翻转）

  // ---- DMI（jtag <-> dm_top）----
  logic          dmi_rst_no;
  dmi_req_t      dmi_req;
  logic          dmi_req_valid, dmi_req_ready;
  dmi_resp_t     dmi_resp;
  logic          dmi_resp_valid, dmi_resp_ready;

  // ---- dm_top 其余接口 tie-off ----
  logic          ndmreset_o, dmactive_o;
  logic          ndmreset_ack_i = 1'b0;
  logic [0:0]    debug_req_o;
  logic [0:0]    unavailable_i = 1'b0;
  dm::hartinfo_t [0:0] hartinfo_i = '0;
  logic [31:0]   next_dm_addr_i = 32'h0;

  // slave（TL-UL 到 DM 的系统侧入口）tie-off
  logic          slave_req_i = 1'b0;
  logic          slave_we_i = 1'b0;
  logic [31:0]   slave_addr_i = 32'h0;
  logic [3:0]    slave_be_i = 4'h0;
  logic [31:0]   slave_wdata_i = 32'h0;
  logic [31:0]   slave_rdata_o;
  logic          slave_err_o;

  // master（系统总线访问）tie-off
  logic          master_req_o;
  logic [31:0]   master_add_o;
  logic          master_we_o;
  logic [31:0]   master_wdata_o;
  logic [3:0]    master_be_o;
  logic          master_gnt_i = 1'b1;
  logic          master_r_valid_i = 1'b0;
  logic          master_r_err_i = 1'b0;
  logic          master_r_other_err_i = 1'b0;
  logic [31:0]   master_r_rdata_i = 32'h0;

  // ---- DUT ----
  dmi_jtag #(
    .IdcodeValue     (32'h04F54847),  // OpenTitan rv_dm IDCODE
    .NumDmiWordAbits (7)
  ) u_jtag (
    .clk_i        (clk_i),
    .rst_ni       (rst_ni),
    .testmode_i   (testmode_i),
    .test_rst_ni  (test_rst_ni),
    .dmi_rst_no   (dmi_rst_no),
    .dmi_req_o    (dmi_req),
    .dmi_req_valid_o (dmi_req_valid),
    .dmi_req_ready_i (dmi_req_ready),
    .dmi_resp_i   (dmi_resp),
    .dmi_resp_ready_o (dmi_resp_ready),
    .dmi_resp_valid_i (dmi_resp_valid),
    .tck_i        (tck_i),
    .tms_i        (tms_i),
    .trst_ni      (trst_ni),
    .td_i         (td_i),
    .td_o         (td_o),
    .tdo_oe_o     (tdo_oe_o)
  );

  dm_top #(
    .NrHarts      (1),
    .BusWidth     (32),
    .DmBaseAddress('h1000)
  ) u_dm (
    .clk_i          (clk_i),
    .rst_ni         (rst_ni),
    .next_dm_addr_i (next_dm_addr_i),
    .testmode_i     (testmode_i),
    .ndmreset_o     (ndmreset_o),
    .ndmreset_ack_i (ndmreset_ack_i),
    .dmactive_o     (dmactive_o),
    .debug_req_o    (debug_req_o),
    .unavailable_i  (unavailable_i),
    .hartinfo_i     (hartinfo_i),
    .slave_req_i    (slave_req_i),
    .slave_we_i     (slave_we_i),
    .slave_addr_i   (slave_addr_i),
    .slave_be_i     (slave_be_i),
    .slave_wdata_i  (slave_wdata_i),
    .slave_rdata_o  (slave_rdata_o),
    .slave_err_o    (slave_err_o),
    .master_req_o   (master_req_o),
    .master_add_o   (master_add_o),
    .master_we_o    (master_we_o),
    .master_wdata_o (master_wdata_o),
    .master_be_o    (master_be_o),
    .master_gnt_i   (master_gnt_i),
    .master_r_valid_i (master_r_valid_i),
    .master_r_err_i   (master_r_err_i),
    .master_r_other_err_i (master_r_other_err_i),
    .master_r_rdata_i (master_r_rdata_i),
    .dmi_rst_ni     (dmi_rst_no),
    .dmi_req_valid_i (dmi_req_valid),
    .dmi_req_ready_o (dmi_req_ready),
    .dmi_req_i      (dmi_req),
    .dmi_resp_valid_o (dmi_resp_valid),
    .dmi_resp_ready_i (dmi_resp_ready),
    .dmi_resp_o     (dmi_resp)
  );

endmodule
