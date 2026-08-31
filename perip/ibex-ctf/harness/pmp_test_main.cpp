// O-H PMP oracle 独立验证 main
#include <verilated.h>
#include "Vpmp_test_top.h"
#include "Vpmp_test_top___024root.h"
#include <cstdio>

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* dut = new Vpmp_test_top;
    dut->clk_i = 0;
    dut->rst_ni = 0;
    for (int i = 0; i < 5; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }
    dut->rst_ni = 1;
    for (int i = 0; i < 5; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }

    printf("=== O-H PMP oracle 验证 ===\n");
    printf("配置: region0 = NAPOT base 0x0 size 64B, R=W=X=0 (全 deny)\n");
    printf("访问: READ @ 0x10 (region 内), M-mode, 非调试\n\n");
    printf("pmp_err_out  (DUT 实际输出) = %d\n", dut->pmp_err_out);
    printf("pmp_violation(应违例但 err=0) = %d\n", dut->pmp_violation);
    printf("perm_mismatch(perm 极性反转)  = %d\n", dut->perm_mismatch);
    printf("\n判定: clean 版应 err=1/violation=0; fork 注入应 err=0/violation=1\n");
    if (dut->perm_mismatch == 1) {
        printf("=> O-H 检出: PMP perm 极性反转注入（Bug#27 类）!\n");
    } else {
        printf("=> PMP perm 检查正常（clean 行为）\n");
    }
    delete dut;
    return 0;
}
