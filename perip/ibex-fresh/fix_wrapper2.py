#!/usr/bin/env python3
"""重写 ibex wrapper 的 CPU 实例化（匹配真实端口）"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/rtl_wrapper/ibex_mini_tb.sv"
s = open(p).read()

# 替换信号声明 + 实例化
old_start = s.index("  // CPU 接口")
old_end = s.index("  // 简化接口: cb_* 用于外部读存储器（观察用）")
new_block = """  // CPU 接口
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
      instr_gnt <= 1'b0; instr_rvalid <= 1'b0; instr_rdata <= 32'b0; imem_addr_q <= 32'b0;
    end else begin
      instr_gnt    <= instr_req;
      instr_rvalid <= instr_gnt;  // gnt 后一拍 rvalid
      if (instr_req && !instr_gnt) imem_addr_q <= instr_addr;
      if (instr_gnt) instr_rdata <= imem[(imem_addr_q[31:2]) % IMemWords];
    end
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
        if (dmem_we_q) begin
          if (dmem_be_q[0]) dmem[(dmem_addr_q[31:2]) % DMemWords][7:0]   <= dmem_wdata_q[7:0];
          if (dmem_be_q[1]) dmem[(dmem_addr_q[31:2]) % DMemWords][15:8]  <= dmem_wdata_q[15:8];
          if (dmem_be_q[2]) dmem[(dmem_addr_q[31:2]) % DMemWords][23:16] <= dmem_wdata_q[23:16];
          if (dmem_be_q[3]) dmem[(dmem_addr_q[31:2]) % DMemWords][31:24] <= dmem_wdata_q[31:24];
          data_rdata <= 32'b0;
        end else begin
          data_rdata <= dmem[(dmem_addr_q[31:2]) % DMemWords];
        end
      end
    end
  end
  assign data_err = 1'b0;

  // 中断/调试 tie-off
  assign fetch_enable = ibex_pkg::IbexMuBiOn;

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
    .ic_tag_rdata_i    ('0),
    .ic_data_req_o     (),
    .ic_data_write_o   (),
    .ic_data_addr_o    (),
    .ic_data_wdata_o   (),
    .ic_data_rdata_i   ('0),
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
    .rvfi_valid     (),
    .rvfi_order     (),
    .rvfi_insn      (),
    .rvfi_trap      (),
    .rvfi_halt      (),
    .rvfi_intr      (),
    .rvfi_mode      (),
    .rvfi_ixl       (),
    .rvfi_rs1_addr  (),
    .rvfi_rs2_addr  (),
    .rvfi_rs3_addr  (),
    .rvfi_rs1_rdata (),
    .rvfi_rs2_rdata (),
    .rvfi_rs3_rdata (),
    .rvfi_rd_addr   (),
    .rvfi_rd_wdata  (),
    .rvfi_pc_rdata  (),
    .rvfi_pc_wdata  (),
    .rvfi_mem_addr  (),
    .rvfi_mem_rmask (),
    .rvfi_mem_wmask (),
    .rvfi_mem_rdata (),
    .rvfi_mem_wdata (),
    .rvfi_ext_pre_mip     (),
    .rvfi_ext_post_mip    (),
    .rvfi_ext_nmi         (),
    .rvfi_ext_nmi_int     (),
    .rvfi_ext_debug_req   (),
    .rvfi_ext_debug_mode  (),
    .rvfi_ext_rf_wr_suppress (),
    .rvfi_ext_mcycle      (),
    .rvfi_ext_mhpmcounters (),
    .rvfi_ext_mhpmcountersh (),
    .rvfi_ext_ic_scr_key_valid (),
    .rvfi_ext_irq_valid   (),
    .fetch_enable_i (fetch_enable),
    .alert_minor_o  (alert_minor),
    .alert_major_internal_o (alert_major_internal),
    .alert_major_bus_o (alert_major_bus),
    .core_busy_o    (core_busy)
  );

"""
s = s[:old_start] + new_block + s[old_end:]
open(p, "w").write(s)
print("wrapper 实例化已重写")
