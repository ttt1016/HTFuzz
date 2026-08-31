// O-I 扩展验证 top：U-mode 写 mstatus（0x300，addr[9:8]=3>0）→ 应拒绝
module csr_priv_test_top (
  input  logic clk_i,
  input  logic rst_ni,
  output logic we_expected,
  output logic we_fork,
  output logic violation
);
  // 场景：U-mode 写 mstatus (0x300)
  logic        priv_umode = 1'b1;
  logic        csr_wr     = 1'b1;
  logic [11:0] csr_addr   = 12'h300;

  csr_priv_oracle_tb u_oracle (
    .clk_i, .rst_ni,
    .cb_priv_umode(priv_umode), .cb_csr_wr(csr_wr), .cb_csr_addr(csr_addr),
    .we_expected(we_expected), .we_fork(we_fork), .violation(violation)
  );
endmodule
