module prim_flop #(parameter int Width = 1, parameter logic [Width-1:0] ResetValue = 0) (
  input clk_i, input rst_ni,
  input [Width-1:0] d_i, output logic [Width-1:0] q_o
);
  logic [Width-1:0] q_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) q_q <= ResetValue;
    else q_q <= d_i;
  end
  assign q_o = q_q;
endmodule
