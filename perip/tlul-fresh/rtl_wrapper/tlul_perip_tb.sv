// PickerFuzz per-IP wrapper — TLUL adapter standalone DUT
// 检测目标: tlul_adapter_reg 地址截断/错误响应（P1 #34 类）+ 总线完整性
module tlul_perip_tb (
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

  // ---- TL 主机（激励源）----
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2hbra;
  // DUT 的 tl_o 接到主机的 tl_i
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
        DRV_REQ:  if (tl_d2hbra.a_ready) drv_q <= DRV_RESP;
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

  // -------------------------------------------------------------------------
  // DUT: tlul_adapter_reg + 最小寄存器块（2 个可读寄存器 @0x0/0x4）
  // -------------------------------------------------------------------------
  logic        req_valid;
  logic        req_write;
  logic [31:0] req_addr;
  logic [31:0] req_wdata;
  logic [3:0]  req_wmask;
  logic        rsp_valid;
  logic [31:0] rsp_rdata;
  logic        rsp_error;

  tlul_adapter_reg #(
    .AccessLatency(0)
  ) u_adapter (
    .clk_i(clk_i), .rst_ni(rst_ni),
    .tl_i(tl_h2d), .tl_o(tl_d2hbra),
    .en_ifetch_i(prim_mubi_pkg::MuBi4False),
    .intg_error_o(),
    .re_o(req_valid),
    .addr_o(req_addr), .we_o(req_write),
    .wdata_o(req_wdata), .be_o(req_wmask),
    .busy_i(1'b0),
    .rdata_i(rsp_rdata),
    .error_i(rsp_error)
  );

  // 最小寄存器块（含越界判定）
  logic [31:0] mem [2];
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      mem[0] <= 32'hA5A5A5A5;
      mem[1] <= 32'h5A5A5A5A;
      rsp_valid <= 1'b0; rsp_rdata <= '0; rsp_error <= 1'b0;
    end else begin
      rsp_valid <= 1'b0; rsp_error <= 1'b0;
      if (req_valid) begin
        if (req_addr < 32'h8) begin
          if (req_write) mem[req_addr[2]] <= req_wdata;
          rsp_rdata <= mem[req_addr[2]];
        end else begin
          rsp_rdata <= 32'h0;
          rsp_error <= 1'b1;  // 越界访问必须报错（P1 #34: adapter 截断地址则不会报）
        end
        rsp_valid <= 1'b1;
      end
    end
  end
endmodule
