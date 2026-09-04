// O-I 特权级语义 oracle 验证 main
#include <verilated.h>
#include "Vpriv_test_top.h"
#include <cstdio>

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* dut = new Vpriv_test_top;
    dut->clk_i = 0;
    dut->rst_ni = 0;
    for (int i = 0; i < 3; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }
    dut->rst_ni = 1;
    for (int i = 0; i < 3; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }

    printf("=== O-I 特权级语义 oracle 验证 ===\n");
    printf("场景: U-mode 执行 MRET (TW=0)\n");
    printf("RISC-V 标准: MRET 必须 M-mode → 应触发 illegal insn\n\n");
    printf("illegal_expected (标准语义) = %d\n", dut->illegal_expected);
    printf("illegal_fork    (fork 实现) = %d\n", dut->illegal_fork);
    printf("violation       (注入特征)  = %d\n", dut->violation);
    if (dut->violation == 1) {
        printf("=> O-I 检出: U-mode 特权指令放行注入（Bug#5 类）!\n");
    } else {
        printf("=> 特权检查正常（clean 行为）\n");
    }
    delete dut;
    return 0;
}
