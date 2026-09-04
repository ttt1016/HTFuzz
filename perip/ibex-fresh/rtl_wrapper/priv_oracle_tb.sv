// O-I 特权级语义 oracle：检测 illegal_umode_insn 恒 0 注入（Bug#5）
// 判据：U-mode 下执行 MRET/WFI 应触发 illegal insn；
// fork 把 illegal_umode_insn 硬编码 1'b0 → U-mode mret/wfi 被放行
module priv_oracle_tb (
  input  logic clk_i,
  input  logic rst_ni,
  // cb 口输入
  input  logic        cb_priv_umode,   // 1 = U-mode, 0 = M-mode
  input  logic        cb_insn_mret,    // 指令是 MRET
  input  logic        cb_insn_wfi,     // 指令是 WFI
  input  logic        cb_mstatus_tw,   // mstatus.TW 位
  output logic        illegal_expected,// RISC-V 标准语义：应触发 illegal
  output logic        illegal_fork,    // fork 实现（恒 0）
  output logic        violation        // 1 = 应 illegal 但 fork 放行（注入特征）
);
  import ibex_pkg::*;

  // fork 的实现（ibex_id_stage.sv:537）
  assign illegal_fork = 1'b0;

  // RISC-V 标准语义（clean ibex_id_stage.sv:606）
  assign illegal_expected = (cb_priv_umode ? PRIV_LVL_U : PRIV_LVL_M) != PRIV_LVL_M &
                            (cb_insn_mret | (cb_mstatus_tw & cb_insn_wfi));

  // 注入特征：标准语义判 illegal 但 fork 放行
  assign violation = illegal_expected & ~illegal_fork;

endmodule
