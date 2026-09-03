// Primgen abstraction wrapper (verilator build without fusesoc)
module prim_flop_2sync #(
  parameter int Width = 16,
  parameter bit ResetValue = 0
) (
  input                    clk_i,
  input                    rst_ni,
  input        [Width-1:0] d_i,
  output logic [Width-1:0] q_o
);
  prim_generic_flop_2sync #(
    .Width(Width),
    .ResetValue(ResetValue)
  ) u_impl_generic (
    .clk_i,
    .rst_ni,
    .d_i,
    .q_o
  );
endmodule
