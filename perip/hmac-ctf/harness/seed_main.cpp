// 双种子一致性测试 (O3-①): 同一序列在 seed=0 和 seed=2 下跑，比对全部可观测输出
#include <verilated.h>
#include "Vhmac_perip_tb.h"
#include "Vhmac_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

static Vhmac_perip_tb* dut = nullptr;
static Vhmac_perip_tb___024root* rootp = nullptr;

static void ec() { dut->clk_i=0; dut->eval(); dut->clk_i=1; dut->eval(); }
static void wr(uint32_t a, uint32_t v) {
    dut->cb_valid=1; dut->cb_addr=a; dut->cb_write=1; dut->cb_wdata=v; dut->cb_wmask=0xF;
    for (int i=0;i<10000;i++){ ec(); if (dut->cb_done) break; }
    dut->cb_valid=0; ec();
}
static uint32_t rd(uint32_t a) {
    dut->cb_valid=1; dut->cb_addr=a; dut->cb_write=0; dut->cb_wdata=0; dut->cb_wmask=0xF;
    for (int i=0;i<10000;i++){ ec(); if (dut->cb_done) break; }
    uint32_t v=dut->cb_rdata; dut->cb_valid=0; ec(); return v;
}

// 跑标准 SHA256 序列，返回 {DIGEST[0..7], STATUS 轨迹}
static std::vector<uint32_t> run_seq(unsigned seed) {
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vhmac_perip_tb;
    rootp = dut->rootp;
    dut->clk_i=0; dut->rst_ni=0; dut->cb_valid=0; dut->cb_addr=0; dut->cb_write=0; dut->cb_wdata=0; dut->cb_wmask=0xF;
    for (int i=0;i<10;i++){ dut->clk_i=0; dut->eval(); dut->clk_i=1; dut->eval(); }
    dut->rst_ni=1; dut->eval(); ec();

    std::vector<uint32_t> obs;
    wr(0x10, 0x422);
    obs.push_back(rd(0x10));
    wr(0x14, 0x1);
    for (int w=0; w<8; w++) wr(0x1000, 0x61616161u);
    wr(0xE4, 256);
    wr(0x14, 0x2);
    // 等 done
    for (int i=0;i<100000;i++){ ec(); if ((rd(0x0)&1)==1) break; }
    wr(0x0, 0x1);
    for (int w=0; w<8; w++) obs.push_back(rd(0xA4 + 4*w));
    // 内部状态: secret_key + sha2 hash_q（白盒）
    for (int w=0; w<32; w++) obs.push_back(((uint32_t*)(&rootp->hmac_perip_tb__DOT__u_dut__DOT__secret_key))[w]);
    for (int w=0; w<16; w++) obs.push_back(((uint32_t*)(&rootp->hmac_perip_tb__DOT__u_dut__DOT__u_prim_sha2_512__DOT__gen_multimode_logic__DOT__u_prim_sha2_multimode__DOT__gen_multimode__DOT__hash_q))[w]);
    dut->final(); delete dut; dut=nullptr;
    return obs;
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto a = run_seq(0);   // 全零初值
    auto b = run_seq(2);   // 随机初值
    printf("[seed-test] obs words: seed0=%zu seed2=%zu\n", a.size(), b.size());
    int diff = 0;
    for (size_t i=0; i<a.size() && i<b.size(); i++) {
        if (a[i] != b[i]) { diff++; if (diff <= 5) printf("  diff@%zu: 0x%08x vs 0x%08x\n", i, a[i], b[i]); }
    }
    printf("[seed-test] O3-1 DUAL-SEED: %s (%d diff words)\n", diff==0 ? "CONSISTENT" : "DIVERGED", diff);
    return diff == 0 ? 0 : 1;
}
