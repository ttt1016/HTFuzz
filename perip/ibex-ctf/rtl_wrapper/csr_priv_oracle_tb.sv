// O-I 扩展：CSR 特权级写保护语义检查（Bug#13）
// fork 注入：privilege_level_violation 恒 1 → illegal_csr_insn_o 恒 0 →
//           csr_we_int = csr_wr & csr_op_en（任意特权级可写任意 CSR）
// clean:    illegal_csr_insn_o = access & (illegal | write_prot | priv_viol | dbg)
//           U-mode 写高位 CSR（addr[9:8] > 0）→ illegal → 写被拒
module csr_priv_oracle_tb (
  input  logic clk_i,
  input  logic rst_ni,
  // cb 口输入
  input  logic        cb_priv_umode,   // 1 = U-mode
  input  logic        cb_csr_wr,       // CSR 写操作
  input  logic [11:0] cb_csr_addr,     // CSR 地址
  output logic        we_expected,     // 标准语义：写应被允许
  output logic        we_fork,         // fork 实现
  output logic        violation        // 1 = 应拒绝但 fork 放行（注入特征）
);
  // fork 实现（ibex_cs_registers.sv:340/880）：
  // illegal_csr_insn_o = access & combined & ~priv_violation，priv_violation 恒 1
  // → illegal_csr_insn_o = 0 → we = csr_wr & csr_op_en
  assign we_fork = cb_csr_wr;  // op_en 假定为 1

  // 标准语义（clean）：U-mode 写 addr[9:8]>0 的 CSR → illegal → 拒绝
  logic priv_violation_clean;
  assign priv_violation_clean = (cb_csr_addr[9:8] > (cb_priv_umode ? 2'b00 : 2'b11));
  logic illegal_clean;
  assign illegal_clean = cb_priv_umode & priv_violation_clean;
  assign we_expected = cb_csr_wr & ~illegal_clean;

  // 注入特征：标准语义拒绝但 fork 放行
  assign violation = ~we_expected & we_fork;

endmodule
