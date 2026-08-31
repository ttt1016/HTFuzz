// O-H PMP 违例检查器：直接例化 ibex_pmp，喂配置+访问，对比 err 输出
// 注入特征：配置了 deny region 且访问命中 → pmp_req_err_o 应为 1；
// fork 注入使 err 恒 0 → pmp_violation=1 检出
module pmp_oracle_tb (
  input  logic clk_i,
  input  logic rst_ni,
  // cb 口直写 PMP 配置
  input  logic [1:0]     cb_pmp_we,     // 01=写cfg 10=写addr
  input  logic [1:0]     cb_pmp_idx,    // region 索引
  input  logic [7:0]     cb_pmp_cfg,    // cfg 字节
  input  logic [31:0]    cb_pmp_addr,   // addr 值
  // 被检查的访问
  input  logic [31:0]    cb_pmp_acc_addr,
  input  logic [1:0]     cb_pmp_acc_type, // 0=R 1=W 2=X
  output logic           pmp_err_out,     // DUT 实际 err 输出
  output logic           pmp_violation,   // 1 = 应违例但 err=0（注入特征）
  output logic           perm_mismatch    // 1 = perm 极性反转（Bug#27 注入特征）
);
  import ibex_pkg::*;

  localparam int unsigned PMPR = 4;

  // PMP 配置寄存器堆
  pmp_cfg_t  pmp_cfg_q [PMPR];
  logic [33:0] pmp_addr_q [PMPR];

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (int i = 0; i < PMPR; i++) begin
        pmp_cfg_q[i]  <= '0;
        pmp_addr_q[i] <= '0;
      end
    end else begin
      if (cb_pmp_we == 2'b01) pmp_cfg_q[cb_pmp_idx]  <= cb_pmp_cfg;
      if (cb_pmp_we == 2'b10) pmp_addr_q[cb_pmp_idx] <= {2'b00, cb_pmp_addr};
    end
  end

  // 访问类型
  pmp_req_e req_type;
  assign req_type = (cb_pmp_acc_type == 2'b00) ? PMP_ACC_READ :
                    (cb_pmp_acc_type == 2'b01) ? PMP_ACC_WRITE : PMP_ACC_EXEC;

  // 直接例化 ibex_pmp（与 cs_registers 内部相同参数）
  logic [0:0] pmp_err;
  logic [33:0] pmp_req_addr;
  assign pmp_req_addr = {2'b00, cb_pmp_acc_addr[31:2], 2'b00};
  ibex_pmp #(
    .PMPGranularity(0),
    .PMPNumRegions(PMPR),
    .PMPNumChan(1)
  ) u_pmp_checker (
    .csr_pmp_cfg_i     (pmp_cfg_q),
    .csr_pmp_addr_i    (pmp_addr_q),
    .csr_pmp_mseccfg_i (pmp_mseccfg_t'(0)),
    .pmp_req_type_i    ({req_type}),
    .pmp_req_addr_i    ({pmp_req_addr}),
    .pmp_req_err_o     ({pmp_err}),
    .priv_mode_i       ({PRIV_LVL_M}),
    .debug_mode_i      (1'b0)
  );

  assign pmp_err_out = pmp_err;
  // 违例判定：region0 配了非 OFF 模式且无权限 → 应该 err=1
  logic cfg_active;
  logic [PMPR-1:0] perm_vec;
  assign cfg_active = (pmp_cfg_q[0].mode != PMP_MODE_OFF);
  assign pmp_violation = cfg_active & ~pmp_err_out;
  // Bug#27 注入特征：L=0 无权限 region 在 M-mode 下应允许（perm=1）
  // fork 极性反转 → perm=0
  logic perm_expected;
  assign perm_expected = ~pmp_cfg_q[0].lock | (pmp_cfg_q[0].read | pmp_cfg_q[0].write | pmp_cfg_q[0].exec);
  assign perm_mismatch = cfg_active & (region_perm_check_obs[0] != perm_expected);
  // 需要 region_perm_check 观测——从 u_pmp_checker 内部引出（verilator public 或层次引用）
  wire [PMPR-1:0] region_perm_check_obs = u_pmp_checker.region_perm_check[0];

endmodule
