// O-I 特权级语义 oracle 验证 top：U-mode 执行 MRET → 应 illegal
module priv_test_top (
  input  logic clk_i,
  input  logic rst_ni,
  output logic illegal_expected,
  output logic illegal_fork,
  output logic violation
);
  // 场景：U-mode 执行 MRET（TW=0）
  logic priv_umode  = 1'b1;
  logic insn_mret   = 1'b1;
  logic insn_wfi    = 1'b0;
  logic mstatus_tw  = 1'b0;

  priv_oracle_tb u_oracle (
    .clk_i, .rst_ni,
    .cb_priv_umode(priv_umode), .cb_insn_mret(insn_mret),
    .cb_insn_wfi(insn_wfi), .cb_mstatus_tw(mstatus_tw),
    .illegal_expected(illegal_expected), .illegal_fork(illegal_fork),
    .violation(violation)
  );
endmodule
