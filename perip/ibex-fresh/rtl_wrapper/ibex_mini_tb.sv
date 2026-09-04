// PickerFuzz mini-CPU TB — ibex_core 裸核（指令存储器 + 数据存储器）
// 目标: 跑固定程序，白盒观察 PC/寄存器堆/FSM（O-D FSM 卡死检测）
module ibex_mini_tb (
  input  logic clk_i,
  input  logic rst_ni,
  input  logic        cb_valid,     // 简化接口: 只用于外部观察（CPU 自主运行）
  input  logic [31:0] cb_addr,
  input  logic        cb_write,
  input  logic [31:0] cb_wdata,
  input  logic [3:0]  cb_wmask,
  output logic        cb_done,
  output logic [31:0] cb_rdata,
  output logic        cb_error
);
  import ibex_pkg::*;

  localparam int unsigned IMemWords = 1024;  // 4KB 指令存储
  localparam int unsigned DMemWords = 1024;  // 4KB 数据存储

  // 存储器
  logic [31:0] imem [IMemWords];
  logic [31:0] dmem [DMemWords];

  // CPU 接口
  logic        instr_req, instr_gnt, instr_rvalid, instr_err;
  logic [31:0] instr_addr, instr_rdata;
  logic        data_req, data_gnt, data_rvalid, data_we, data_err;
  logic [31:0] data_addr, data_wdata, data_rdata;
  logic [3:0]  data_be;
  logic        dummy_instr_id, dummy_instr_wb;
  logic [4:0]  rf_raddr_a, rf_raddr_b, rf_waddr_wb;
  logic        rf_we_wb;
  logic [31:0] rf_wdata_wb_ecc, rf_rdata_a_ecc, rf_rdata_b_ecc;
  logic        ic_tag_req;
  logic        ic_data_req;
  logic        irq_pending;
  logic        core_sleep;
  ibex_pkg::ibex_mubi_t fetch_enable;
  ibex_pkg::ibex_mubi_t core_busy;
  logic alert_minor, alert_major_internal, alert_major_bus;

  // 指令取: 2 拍延迟响应
  logic [31:0] imem_addr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      instr_gnt <= 1'b0; instr_rvalid <= 1'b0; imem_addr_q <= 32'b0;
    end else begin
      instr_gnt    <= instr_req;
      instr_rvalid <= instr_gnt;  // gnt 后一拍 rvalid
      if (instr_req) imem_addr_q <= instr_addr;
    end
  end
  // rdata 组合输出（rvalid 拍有效）
  always_comb begin
    instr_rdata = imem[(imem_addr_q[31:2]) % IMemWords];
  end
  assign instr_err = 1'b0;

  // 数据访问: 2 拍延迟
  logic [31:0] dmem_addr_q;
  logic        dmem_we_q;
  logic [31:0] dmem_wdata_q;
  logic [3:0]  dmem_be_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      data_gnt <= 1'b0; data_rvalid <= 1'b0; data_rdata <= 32'b0;
      dmem_addr_q <= 32'b0; dmem_we_q <= 1'b0; dmem_wdata_q <= 32'b0; dmem_be_q <= 4'b0;
    end else begin
      data_gnt    <= data_req;
      data_rvalid <= data_gnt;
      if (data_req && !data_gnt) begin
        dmem_addr_q <= data_addr; dmem_we_q <= data_we;
        dmem_wdata_q <= data_wdata; dmem_be_q <= data_be;
      end
      if (data_gnt) begin
        // gnt 拍 req/we/addr/wdata 仍保持（ibex 协议），直接用当拍信号
        if (data_we) begin
          dmem[(data_addr[31:2]) % DMemWords] <= data_wdata;
          data_rdata <= 32'b0;
        end else begin
          data_rdata <= dmem[(data_addr[31:2]) % DMemWords];
        end
      end
    end
  end
  assign data_err = 1'b0;

  // 中断/调试 tie-off
  assign fetch_enable = ibex_pkg::IbexMuBiOn;

  localparam int unsigned TAG_ECC_W = ibex_pkg::IC_TAG_SIZE;
  localparam int unsigned LINE_ECC_W = ibex_pkg::IC_LINE_SIZE;
  logic [TAG_ECC_W-1:0] ic_tag_rdata [ibex_pkg::IC_NUM_WAYS];
  logic [LINE_ECC_W-1:0] ic_data_rdata [ibex_pkg::IC_NUM_WAYS];

  // CPU 实例（匹配 ibex_core 真实端口）
  ibex_core #(
    .RV32M (ibex_pkg::RV32MFast),
    .RV32B (ibex_pkg::RV32BNone),
    .BranchTargetALU (1'b1),
    .WritebackStage  (1'b0)
  ) u_dut (
    .clk_i, .rst_ni,
    .hart_id_i     (32'b0),
    .boot_addr_i   (32'h0000_0000),
    .instr_req_o   (instr_req),
    .instr_gnt_i   (instr_gnt),
    .instr_rvalid_i(instr_rvalid),
    .instr_addr_o  (instr_addr),
    .instr_rdata_i (instr_rdata),
    .instr_err_i   (instr_err),
    .data_req_o    (data_req),
    .data_gnt_i    (data_gnt),
    .data_rvalid_i (data_rvalid),
    .data_we_o     (data_we),
    .data_be_o     (data_be),
    .data_addr_o   (data_addr),
    .data_wdata_o  (data_wdata),
    .data_rdata_i  (data_rdata),
    .data_err_i    (data_err),
    .dummy_instr_id_o  (dummy_instr_id),
    .dummy_instr_wb_o  (dummy_instr_wb),
    .rf_raddr_a_o      (rf_raddr_a),
    .rf_raddr_b_o      (rf_raddr_b),
    .rf_waddr_wb_o     (rf_waddr_wb),
    .rf_we_wb_o        (rf_we_wb),
    .rf_wdata_wb_ecc_o (rf_wdata_wb_ecc),
    .rf_rdata_a_ecc_i  (rf_rdata_a_ecc),
    .rf_rdata_b_ecc_i  (rf_rdata_b_ecc),
    .ic_tag_req_o      (),
    .ic_tag_write_o    (),
    .ic_tag_addr_o     (),
    .ic_tag_wdata_o    (),
    .ic_tag_rdata_i    (ic_tag_rdata),
    .ic_data_req_o     (),
    .ic_data_write_o   (),
    .ic_data_addr_o    (),
    .ic_data_wdata_o   (),
    .ic_data_rdata_i   (ic_data_rdata),
    .ic_scr_key_valid_i (1'b0),
    .ic_scr_key_req_o   (),
    .irq_software_i (1'b0),
    .irq_timer_i    (1'b0),
    .irq_external_i (1'b0),
    .irq_fast_i     (15'b0),
    .irq_nm_i       (1'b0),
    .irq_pending_o  (irq_pending),
    .debug_req_i    (1'b0),
    .crash_dump_o   (),
    .double_fault_seen_o (),
    .fetch_enable_i (fetch_enable),
    .alert_minor_o  (alert_minor),
    .alert_major_internal_o (alert_major_internal),
    .alert_major_bus_o (alert_major_bus),
    .core_busy_o    (core_busy)
  );

  // 简化接口: cb_* 用于外部读存储器（观察用）
  assign cb_done = cb_valid;
  assign cb_error = 1'b0;
  always_comb begin
    cb_rdata = 32'b0;
    if (cb_valid) begin
      if (cb_addr[12]) cb_rdata = dmem[(cb_addr[31:2]) % DMemWords];
      else             cb_rdata = imem[(cb_addr[31:2]) % IMemWords];
    end
  end

  // 程序加载: initial 块从 prog.hex 加载（hex 每行一个 32bit 字）
  initial begin
    for (int i = 0; i < IMemWords; i++) imem[i] = 32'h00000013;  // nop (addi x0,x0,0)
    for (int i = 0; i < DMemWords; i++) dmem[i] = 32'b0;
    if (1) begin // 无条件加载（PMP 测试）
      // ibex 复位向量 = boot_addr + 0x80 → 程序加载到 0x80 (word 32)
      $readmemh("prog_pmp.hex", imem, 32);
    end
  end

endmodule
