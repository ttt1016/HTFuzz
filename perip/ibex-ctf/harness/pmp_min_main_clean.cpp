// 最小 PMP 验证 main
#include <verilated.h>
#include "Vpmp_min_top_clean.h"
#include <cstdio>
int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* dut = new Vpmp_min_top_clean;
    dut->clk_i = 0; dut->rst_ni = 0;
    for (int i = 0; i < 3; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }
    dut->rst_ni = 1;
    for (int i = 0; i < 3; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); }
    printf("cfg=0x18(NAPOT deny) addr=0x1(8B@0) acc=0x4 READ M-mode\n");
    printf("pmp_err = %d\n", dut->pmp_err);
    delete dut;
    return 0;
}
