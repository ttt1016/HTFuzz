// O-I 扩展（CSR 特权写保护）验证 main
#include <verilated.h>
#include "Vcsr_priv_test_top.h"
#include <cstdio>

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* dut = new Vcsr_priv_test_top;
    dut->clk_i = 0;
    dut->rst_ni = 0;
    for (int i = 0; i < 3; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }
    dut->rst_ni = 1;
    for (int i = 0; i < 3; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }

    printf("=== O-I 扩展: CSR 特权级写保护检查 ===\n");
    printf("场景: U-mode 写 mstatus (0x300, addr[9:8]=3)\n");
    printf("RISC-V 标准: U-mode 写 M-mode CSR → 应拒绝\n\n");
    printf("we_expected (标准语义) = %d\n", dut->we_expected);
    printf("we_fork     (fork 实现) = %d\n", dut->we_fork);
    printf("violation   (注入特征)  = %d\n", dut->violation);
    if (dut->violation == 1) {
        printf("=> O-I 检出: CSR 特权级写保护失效注入（Bug#13 类）!\n");
    } else {
        printf("=> CSR 写保护正常（clean 行为）\n");
    }
    delete dut;
    return 0;
}
