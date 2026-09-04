// primgen 生成件的手写 shim: prim_ram_1p → prim_generic_ram_1p（standalone verilator 用）
module prim_ram_1p #(
  parameter  int Width           = 32,
  parameter  int Depth           = 128,
  parameter  int DataBitsPerMask = 1,
  parameter      MemInitFile     = "",

  localparam int Aw = $clog2(Depth)
) (
  input  logic             clk_i,
  input  logic             rst_ni,
  input  logic             req_i,
  input  logic             write_i,
  input  logic [Aw-1:0]    addr_i,
  input  logic [Width-1:0] wdata_i,
  input  logic [Width-1:0] wmask_i,
  output logic [Width-1:0] rdata_o,
  input  prim_ram_1p_pkg::ram_1p_cfg_t      cfg_i,
  output prim_ram_1p_pkg::ram_1p_cfg_rsp_t  cfg_rsp_o
);

  prim_generic_ram_1p #(
    .Width           (Width),
    .Depth           (Depth),
    .DataBitsPerMask (DataBitsPerMask),
    .MemInitFile     (MemInitFile)
  ) u_impl_generic (
    .clk_i,
    .rst_ni,
    .req_i,
    .write_i,
    .addr_i,
    .wdata_i,
    .wmask_i,
    .rdata_o,
    .cfg_i,
    .cfg_rsp_o
  );

endmodule
