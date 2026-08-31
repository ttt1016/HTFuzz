// PickerFuzz 吞吐基准 — per-IP HMAC DUT (M5-5)
// 验收标准: ≥ 100 op/s（计划书 M5）
#include <verilated.h>
#include "Vhmac_perip_tb.h"
#include <cstdio>
#include <ctime>
#include <cstdint>

static void ec(Vhmac_perip_tb* d) { d->clk_i = 0; d->eval(); d->clk_i = 1; d->eval(); }

static uint32_t rd(Vhmac_perip_tb* d, uint32_t a) {
    d->cb_valid = 1; d->cb_addr = a; d->cb_write = 0; d->cb_wdata = 0; d->cb_wmask = 0xF;
    for (int i = 0; i < 1000; i++) { ec(d); if (d->cb_done) break; }
    uint32_t v = d->cb_rdata; d->cb_valid = 0; ec(d); return v;
}

static void wr(Vhmac_perip_tb* d, uint32_t a, uint32_t v) {
    d->cb_valid = 1; d->cb_addr = a; d->cb_write = 1; d->cb_wdata = v; d->cb_wmask = 0xF;
    for (int i = 0; i < 1000; i++) { ec(d); if (d->cb_done) break; }
    d->cb_valid = 0; ec(d);
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* d = new Vhmac_perip_tb;
    d->clk_i = 0; d->rst_ni = 0;
    d->cb_valid = 0; d->cb_addr = 0; d->cb_write = 0; d->cb_wdata = 0; d->cb_wmask = 0xF;
    for (int i = 0; i < 10; i++) { d->clk_i = 0; d->eval(); d->clk_i = 1; d->eval(); }
    d->rst_ni = 1; d->eval(); ec(d);

    const int N = 1000;
    // 基准 1: 纯读
    clock_t t0 = clock();
    for (int i = 0; i < N; i++) rd(d, 0x18);
    clock_t t1 = clock();
    double secs = double(t1 - t0) / CLOCKS_PER_SEC;
    printf("[bench] %d reads in %.3fs => %.0f ops/s\n", N, secs, N / secs);

    // 基准 2: 写+读对
    t0 = clock();
    for (int i = 0; i < N; i++) { wr(d, 0x10, 0x422); rd(d, 0x10); }
    t1 = clock();
    secs = double(t1 - t0) / CLOCKS_PER_SEC;
    printf("[bench] %d write+read pairs in %.3fs => %.0f ops/s\n", N, secs, 2.0 * N / secs);

    // 基准 3: 完整 SHA256 序列（约 15 op）
    t0 = clock();
    const int M = 100;
    for (int r = 0; r < M; r++) {
        wr(d, 0x10, 0x422);
        wr(d, 0x14, 0x1);
        for (int w = 0; w < 8; w++) wr(d, 0x1000, 0x61616161u);
        wr(d, 0xE4, 256);
        wr(d, 0x14, 0x2);
        // 等 done
        for (int i = 0; i < 100000; i++) { ec(d); if ((rd(d, 0x0) & 1) == 1) break; }
        wr(d, 0x0, 0x1);
        uint32_t d0 = rd(d, 0xA4);
        if (d0 != 0x3ba3f5f4u) { printf("[bench] SHA256 MISMATCH at iter %d: 0x%08x\n", r, d0); return 1; }
    }
    t1 = clock();
    secs = double(t1 - t0) / CLOCKS_PER_SEC;
    printf("[bench] %d full SHA256 runs in %.3fs => %.1f hashes/s (%.0f ops/s)\n",
           M, secs, M / secs, 15.0 * M / secs);

    delete d;
    printf("[bench] ALL PASS\n");
    return 0;
}
