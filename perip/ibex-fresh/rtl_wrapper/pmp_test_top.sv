// O-H 独立验证 top：配置 deny region + 访问命中 → 期望 err=1（clean）/ err=0（fork 注入）
module pmp_test_top (
  input  logic clk_i,
  input  logic rst_ni,
  output logic pmp_err_out,
  output logic pmp_violation,
  output logic perm_mismatch
);
  // region0 = NAPOT base 0x0 size 64B, R=W=X=0（全 deny）
  logic [1:0]  we       = 2'b01;
  logic [1:0]  idx      = 2'b00;
  logic [7:0]  cfg      = 8'h18;  // A=NAPOT, R=W=X=0
  logic [31:0] addr     = 32'h00000001;  // NAPOT: 8B region @ 0x0
  logic [31:0] acc_addr = 32'h00000004;  // region 内地址（NAPOT 0 = 8B @0）
  logic [1:0]  acc_type = 2'b00;  // read

  pmp_oracle_tb u_oracle (
    .clk_i, .rst_ni,
    .cb_pmp_we(we), .cb_pmp_idx(idx), .cb_pmp_cfg(cfg), .cb_pmp_addr(addr),
    .cb_pmp_acc_addr(acc_addr), .cb_pmp_acc_type(acc_type),
    .pmp_err_out(pmp_err_out), .pmp_violation(pmp_violation), .perm_mismatch(perm_mismatch)
  );
endmodule
