// HTFuzz per-IP wrapper — SPI_TPM standalone DUT
// cb_* TL → sys_* 寄存器桥 + 内置 TPM 主机模型（TPM_XFER 写触发 SPI 事务）
// 引擎写 CSR 即可驱动完整 TPM 读/写事务（return-by-HW / cmdaddr upload 可观测）
module spi_tpm_perip_tb (
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

  import spi_device_pkg::*;
  import spi_device_reg_pkg::*;
  import prim_mubi_pkg::*;

  // ===========================================================================
  // 声明区（先声明后使用）
  // ===========================================================================
  // TL 驱动 FSM
  tlul_pkg::tl_h2d_t tl_h2d, tl_a;
  tlul_pkg::tl_d2h_t tl_d2h;
  logic        req_write_q;
  logic [31:0] req_addr_q, req_wdata_q;
  logic [3:0]  req_wmask_q;
  typedef enum logic [1:0] { DRV_IDLE, DRV_REQ, DRV_RESP } drv_state_e;
  drv_state_e drv_q;

  // 寄存器块
  logic [31:0] cfg_q, access_lo_q, access_hi_q, int_en_q, int_vec_q;
  logic [31:0] int_sts_q, intf_cap_q, sts_q, did_vid_q, rid_q;
  logic [31:0] tx_q, wdata_q;
  logic        d_valid_q, d_error_q, req_req_q, req_we_q;
  logic [31:0] d_rdata_q, req_addr_q2, req_wdata_q2;
  logic [3:0]  req_wmask_q2;

  // TPM 主机模型 ↔ 寄存器块握手
  logic h_start_ev;      // 寄存器块写（单驱动: 寄存器块）
  logic h_consume_q;     // 主机模型已消费（单驱动: 主机模型）

  // TPM 主机模型
  typedef enum logic [2:0] { H_IDLE, H_RST, H_HEADER, H_TURN, H_DATA, H_END } h_state_e;
  h_state_e h_q;
  logic        h_active_q, h_csb_q, h_is_rd_q, sys_tpm_rst_n_q;
  logic [5:0]  h_bitcnt_q;   // 0..47: header 32 + data 32（需容纳 32 拍数据相）
  logic [71:0] h_shift_q;   // {cmd8, addr24, start8, data32} MSB first
  logic [7:0]  h_size_q;
  logic [31:0] h_rx_q;
  logic [39:0] h_rx_raw;
  logic        miso_sample;

  // cmdaddr 上传捕获
  logic        h_cmdaddr_rvalid;
  logic [31:0] h_cmdaddr_rdata;
  logic [31:0] upcmd_q;
  logic [7:0]  upcount_q;

  // DUT 接口线
  logic miso, miso_en, csb, mosi;
  logic st_cmdaddr_notempty, st_wrfifo_pending, st_rdfifo_aborted;
  sram_l2m_t sck_sram_l2m;
  sram_m2l_t sck_sram_m2l;
  sram_l2m_t sys_sram_l2m;
  sram_m2l_t sys_sram_m2l;

  // ===========================================================================
  // TL 驱动 FSM
  // ===========================================================================
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

  // ===========================================================================
  // 最小寄存器块（TL device: a_ready 恒 1, 1 拍 d_valid, >0x3C → d_error）
  //   0x00 TPM_CFG       {inv_loc[4], reg_chk_dis[3], hw_reg_dis[2], mode[1], en[0]}
  //   0x04 TPM_ACCESS_LO localities 0..3
  //   0x08 TPM_ACCESS_HI locality 4 (byte0)
  //   0x0C INT_ENABLE  0x10 INT_VECTOR  0x14 INT_STS  0x18 INTF_CAP
  //   0x1C TPM_STS     0x20 DID_VID     0x24 RID
  //   0x28 TPM_TX      {rw[31], size[29:24], addr[23:0]}
  //   0x2C TPM_XFER    写触发事务
  //   0x30 TPM_WDATA   0x34 TPM_RX(RO)  0x38 TPM_UPCMD(RO)  0x3C TPM_STATUS(RO)
  // ===========================================================================
  localparam logic [31:0] REG_TOP = 32'h3C;

  function automatic logic [31:0] reg_rdata(input logic [31:0] a);
    unique case (a)
      32'h00: reg_rdata = cfg_q;
      32'h04: reg_rdata = access_lo_q;
      32'h08: reg_rdata = access_hi_q;
      32'h0C: reg_rdata = int_en_q;
      32'h10: reg_rdata = int_vec_q;
      32'h14: reg_rdata = int_sts_q;
      32'h18: reg_rdata = intf_cap_q;
      32'h1C: reg_rdata = sts_q;
      32'h20: reg_rdata = did_vid_q;
      32'h24: reg_rdata = rid_q;
      32'h28: reg_rdata = tx_q;
      32'h30: reg_rdata = wdata_q;
      32'h34: reg_rdata = h_rx_q;
      32'h38: reg_rdata = upcmd_q;
      32'h3C: reg_rdata = {22'b0, st_rdfifo_aborted, st_wrfifo_pending,
                           st_cmdaddr_notempty, h_active_q, h_q};
      default: reg_rdata = 32'h0;
    endcase
  endfunction

  assign tl_d2h.a_ready = 1'b1;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      d_valid_q <= 1'b0; d_error_q <= 1'b0; d_rdata_q <= '0;
      req_req_q <= 1'b0; req_we_q <= 1'b0; req_addr_q2 <= '0;
      req_wdata_q2 <= '0; req_wmask_q2 <= '0;
    end else begin
      d_valid_q <= 1'b0;
      if (h_consume_q) h_start_ev <= 1'b0;   // 主机模型已消费 → 撤销触发
      if (tl_h2d.a_valid && (drv_q == DRV_REQ)) begin
        req_req_q    <= 1'b1;
        req_we_q     <= (tl_h2d.a_opcode == tlul_pkg::PutFullData) ||
                        (tl_h2d.a_opcode == tlul_pkg::PutPartialData);
        req_addr_q2  <= tl_h2d.a_address;
        req_wdata_q2 <= tl_h2d.a_data;
        req_wmask_q2 <= tl_h2d.a_mask;
      end else if (req_req_q) begin
        req_req_q <= 1'b0;
        if (!req_we_q) begin
          d_valid_q <= 1'b1;
          d_error_q <= (req_addr_q2 > REG_TOP);
          d_rdata_q <= reg_rdata(req_addr_q2);
        end else if (req_addr_q2 <= REG_TOP) begin
          for (int b = 0; b < 4; b++) begin
            if (req_wmask_q2[b]) begin
              unique case (req_addr_q2)
                32'h00: cfg_q[b*8 +: 8]       <= req_wdata_q2[b*8 +: 8];
                32'h04: access_lo_q[b*8 +: 8] <= req_wdata_q2[b*8 +: 8];
                32'h08: access_hi_q[b*8 +: 8] <= req_wdata_q2[b*8 +: 8];
                32'h0C: int_en_q[b*8 +: 8]    <= req_wdata_q2[b*8 +: 8];
                32'h10: int_vec_q[b*8 +: 8]   <= req_wdata_q2[b*8 +: 8];
                32'h14: int_sts_q[b*8 +: 8]   <= req_wdata_q2[b*8 +: 8];
                32'h18: intf_cap_q[b*8 +: 8]  <= req_wdata_q2[b*8 +: 8];
                32'h1C: sts_q[b*8 +: 8]       <= req_wdata_q2[b*8 +: 8];
                32'h20: did_vid_q[b*8 +: 8]   <= req_wdata_q2[b*8 +: 8];
                32'h24: rid_q[b*8 +: 8]       <= req_wdata_q2[b*8 +: 8];
                32'h28: tx_q[b*8 +: 8]        <= req_wdata_q2[b*8 +: 8];
                32'h30: wdata_q[b*8 +: 8]     <= req_wdata_q2[b*8 +: 8];
                default: ;
              endcase
            end
          end
          if (req_addr_q2 == 32'h2C) h_start_ev <= 1'b1;  // 触发事务
          d_valid_q <= 1'b1;                              // 写 ACK
        end else begin
          d_valid_q <= 1'b1;              // 写响应（越界也回 ACK+error）
          d_error_q <= (req_addr_q2 > REG_TOP);
        end
      end
    end
  end

  assign tl_d2h.d_valid  = d_valid_q;
  assign tl_d2h.d_data   = d_rdata_q;
  assign tl_d2h.d_error  = d_error_q;
  assign tl_d2h.d_opcode = req_we_q ? tlul_pkg::AccessAck : tlul_pkg::AccessAckData;
  assign tl_d2h.d_size   = 2'b10;
  assign tl_d2h.d_source = '0;
  assign tl_d2h.d_sink   = '0;
  assign tl_d2h.d_user   = '0;
  assign cb_done  = (drv_q == DRV_RESP) && tl_d2h.d_valid;
  assign cb_rdata = tl_d2h.d_data;
  assign cb_error = tl_d2h.d_error;

  // ===========================================================================
  // TPM 主机模型（negedge 驱动 → 每个 clk_in posedge 采样前半拍数据已稳定）
  // clk_in/clk_out 由 csb 门控（spi_tpm FSM 在 StIdle 无条件移位，必须靠时钟门控停止）
  // ===========================================================================
  logic clk_in, clk_out;
  assign clk_in  = h_csb_q ? 1'b0 : clk_i;
  assign clk_out = h_csb_q ? 1'b0 : ~clk_i;

  always_ff @(negedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      h_q <= H_IDLE; h_active_q <= 1'b0; h_csb_q <= 1'b1; h_is_rd_q <= 1'b0;
      h_bitcnt_q <= '0; h_shift_q <= '0; h_size_q <= '0; h_rx_q <= '0; h_rx_raw <= '0;
      sys_tpm_rst_n_q <= 1'b1; h_consume_q <= 1'b0;
    end else begin
      unique case (h_q)
        H_IDLE: begin
          h_csb_q <= 1'b1; h_active_q <= 1'b0;
          if (h_start_ev) begin
            h_consume_q    <= 1'b1;
            h_q            <= H_RST;
            sys_tpm_rst_n_q <= 1'b0;  // 脉冲: DUT 在 sys 域重新锁存 cfg/reg
          end
        end
        H_RST: begin
          sys_tpm_rst_n_q <= 1'b1;
          h_consume_q <= 1'b0;
          h_is_rd_q   <= tx_q[31];
          h_size_q    <= (tx_q[29:24] > 6'd4) ? 8'd4 : {2'b00, tx_q[29:24]};
          h_shift_q   <= {(tx_q[31] ? 8'h80 : 8'h00) | {1'b0, tx_q[29:24]},
                          tx_q[23:0], 8'h00, wdata_q};
          h_bitcnt_q  <= '0;
          h_active_q  <= 1'b1;
          h_csb_q     <= 1'b0;
          h_q         <= H_HEADER;
        end
        // cmd8 + addr24 连续 32 拍（无相位间隙）
        H_HEADER: begin
          if (h_bitcnt_q == 5'd31) begin
            h_bitcnt_q <= '0; h_q <= h_is_rd_q ? H_TURN : H_DATA;
            if (!h_is_rd_q) begin
              // 首个数据位由组合逻辑在 H_DATA bitcnt=0 时给出
            end
          end else begin
            h_bitcnt_q <= h_bitcnt_q + 5'd1;
          end
        end
        H_TURN: begin
          // 读 turnaround: 等 DUT p2s 流水线 1 拍（miso 首位在下一 negedge 稳定）
          h_q <= H_DATA;
        end
        H_DATA: begin
          // 写: 切换拍已发 start[7]，此处 39 拍发完余下位; 读: 40 拍捕获 start+data
          if (h_bitcnt_q == 6'd40) begin
            h_bitcnt_q <= '0;
            h_rx_q     <= h_is_rd_q ? h_rx_raw[31:0] : h_rx_q;  // 丢弃 start 字节
            h_q        <= H_END;
          end else begin
            if (h_is_rd_q) begin
              h_rx_raw <= {h_rx_raw[39:0], miso_sample};
            end
            h_bitcnt_q <= h_bitcnt_q + 5'd1;
          end
        end
        H_END: begin
          // csb 保持低 8 拍: 让 DUT 完成 StEnd/CDC 推送，再释放
          if (h_bitcnt_q == 5'd7) begin
            h_bitcnt_q <= '0;
            h_csb_q    <= 1'b1;
            h_active_q <= 1'b0;
            h_q        <= H_IDLE;
          end else h_bitcnt_q <= h_bitcnt_q + 5'd1;
        end
        default: h_q <= H_IDLE;
      endcase
    end
  end

  always_ff @(posedge clk_i) miso_sample <= miso;

  // mosi 组合驱动: 位索引 H_RST=0 / H_HEADER=1+bc / H_DATA=32+bc（72 位流）
  //   [71:64]=cmd [63:40]=addr [39:32]=start(哑字节) [31:0]=wdata
  logic mosi_c;
  always_comb begin
    if (h_q == H_RST)                     mosi_c = h_shift_q[71];
    else if (h_q == H_HEADER && h_bitcnt_q <= 5'd31) mosi_c = h_shift_q[71 - h_bitcnt_q];
    else if (h_q == H_DATA && !h_is_rd_q && h_bitcnt_q <= 5'd39)
                                          mosi_c = h_shift_q[39 - h_bitcnt_q[5:0]];
    else                                  mosi_c = 1'b0;
  end
  assign mosi = mosi_c;

  // cmdaddr 上传捕获（rready 恒 1）
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      upcmd_q <= '0; upcount_q <= '0;
    end else if (h_cmdaddr_rvalid) begin
      upcmd_q   <= h_cmdaddr_rdata;
      upcount_q <= upcount_q + 8'd1;
    end
  end

  // ===========================================================================
  // SRAM stub（1 拍读响应图案数据, 写立即完成）
  // ===========================================================================
  always_ff @(posedge clk_in or negedge rst_ni) begin
    if (!rst_ni) begin
      sck_sram_m2l.rvalid <= 1'b0; sck_sram_m2l.rdata <= '0; sck_sram_m2l.rerror <= '0;
      sys_sram_m2l.rvalid <= 1'b0; sys_sram_m2l.rdata <= '0; sys_sram_m2l.rerror <= '0;
    end else begin
      sck_sram_m2l.rvalid <= sck_sram_l2m.req & ~sck_sram_l2m.we;
      sck_sram_m2l.rdata  <= {28'b0, sck_sram_l2m.addr} ^ 32'hC0DE_C0DE;
      sck_sram_m2l.rerror <= '0;
      sys_sram_m2l.rvalid <= sys_sram_l2m.req & ~sys_sram_l2m.we;
      sys_sram_m2l.rdata  <= {28'b0, sys_sram_l2m.addr} ^ 32'hF00D_F00D;
      sys_sram_m2l.rerror <= '0;
    end
  end

  // ===========================================================================
  // DUT: spi_tpm
  // ===========================================================================
  assign csb = h_csb_q;

  // sck 域复位方案（同 spi_device.sv）: csb 高 → tpm_rst_in_n=0 → FSM/上传 FIFO 全复位
  logic csb_d, tpm_rst_in_n, tpm_rst_out_n;
  always_ff @(posedge clk_in or negedge rst_ni) csb_d <= csb;
  assign tpm_rst_in_n  = rst_ni & ~csb;
  assign tpm_rst_out_n = rst_ni & ~csb_d;

  spi_tpm u_dut (
    .clk_in_i  (clk_in),
    .clk_out_i (clk_out),
    .rst_ni    (tpm_rst_in_n),
    .rst_out_ni(tpm_rst_out_n),
    .sys_clk_i (clk_i),
    .sys_rst_ni(rst_ni),
    .sys_tpm_rst_ni(sys_tpm_rst_n_q),
    .csb_i      (csb),
    .mosi_i     (mosi),
    .miso_o     (miso),
    .miso_en_o  (miso_en),
    .tpm_cap_o  (),
    .cfg_tpm_en_i               (cfg_q[0]),
    .cfg_tpm_mode_i             (cfg_q[1]),
    .cfg_tpm_hw_reg_dis_i       (cfg_q[2]),
    .cfg_tpm_reg_chk_dis_i      (cfg_q[3]),
    .cfg_tpm_invalid_locality_i (cfg_q[4]),
    .sys_access_reg_i           ({access_hi_q[7:0], access_lo_q}),
    .sys_int_enable_reg_i       (int_en_q),
    .sys_int_vector_reg_i       (int_vec_q[7:0]),
    .sys_int_status_reg_i       (int_sts_q),
    .sys_intf_capability_reg_i  (intf_cap_q),
    .sys_status_reg_i           (sts_q),
    .sys_id_reg_i               (did_vid_q),
    .sys_rid_reg_i              (rid_q[7:0]),
    .sck_sram_o (sck_sram_l2m),
    .sck_sram_i (sck_sram_m2l),
    .sys_sram_o (sys_sram_l2m),
    .sys_sram_i (sys_sram_m2l),
    .sys_sram_gnt_i (1'b1),
    .sys_cmdaddr_rvalid_o (h_cmdaddr_rvalid),
    .sys_cmdaddr_rdata_o  (h_cmdaddr_rdata),
    .sys_cmdaddr_rready_i (1'b1),
    .sys_rdfifo_wvalid_i  (1'b0),
    .sys_rdfifo_wdata_i   ('0),
    .sys_rdfifo_wready_o  (),
    .sys_rdfifo_cmd_end_o (),
    .sys_tpm_rdfifo_drop_o(),
    .sys_wrfifo_release_i (1'b0),
    .sys_cmdaddr_notempty_o (st_cmdaddr_notempty),
    .sys_wrfifo_pending_o   (st_wrfifo_pending),
    .sys_rdfifo_aborted_o   (st_rdfifo_aborted)
  );

  // 防剪除
  logic unused_tpm;
  assign unused_tpm = ^{miso, miso_en, miso_sample};

endmodule
