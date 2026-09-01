// PickerFuzz per-IP C++ harness — KMAC (kmac-ctf, Bug#26 静态掩码检测)
// ====================================================================
// 检测思路: EnMasking=1 时 msg_data_masked 应为 msg_data ^ 动态随机掩码。
// Bug#26 注入后掩码是静态全 1（cfg_msg_mask 恒定时）:
//   - 同一消息两次 hash（不同 PRNG 状态）应产生不同中间掩码值
//   - 静态掩码下 msg_data_masked 与 msg_data 的关系恒定（XOR 全 1 或 0）
// 白盒观测: msg_data / msg_data_masked / mux2fifo_mask
#include <verilated.h>
#include "Vkmac_perip_tb.h"
#include "Vkmac_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vkmac_perip_tb* dut = nullptr;
static Vkmac_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };
#define SIGD(n) rootp->kmac_perip_tb__DOT__u_dut__DOT__##n

static SigEntry g_sigs[] = {
    {"u_dut.msg_data",         nullptr, 2, true},   // 64bit MsgWidth
    {"u_dut.msg_data_masked",  nullptr, 4, true},   // [Share][MsgWidth]
    {"u_dut.mux2fifo_mask",    nullptr, 2, true},
};
static const int g_nsig = sizeof(g_sigs)/sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        if (strcmp(n, "u_dut.msg_data") == 0) g_sigs[i].ptr = &SIGD(msg_data);
        else if (strcmp(n, "u_dut.msg_data_masked") == 0) g_sigs[i].ptr = &SIGD(msg_data_masked);
        else if (strcmp(n, "u_dut.mux2fifo_mask") == 0) g_sigs[i].ptr = &SIGD(mux2fifo_mask);
    }
}

static void ec() { dut->clk_i=0; dut->eval(); dut->clk_i=1; dut->eval(); main_time+=10; }

extern "C" {
int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vkmac_perip_tb;
    rootp = dut->rootp;
    bind_signals();
    dut->clk_i=0; dut->rst_ni=0; dut->cb_valid=0; dut->cb_addr=0; dut->cb_write=0; dut->cb_wdata=0; dut->cb_wmask=0xF;
    for (int i=0;i<10;i++){ dut->clk_i=0; dut->eval(); dut->clk_i=1; dut->eval(); main_time+=2; }
    dut->rst_ni=1; dut->eval(); ec();
    return 0;
}
int pf_write(uint32_t addr, uint32_t data, uint32_t mask) {
    dut->cb_valid=1; dut->cb_addr=addr; dut->cb_write=1; dut->cb_wdata=data;
    dut->cb_wmask = mask ? (mask & 0xF) : 0xF;
    for (int i=0;i<100000;i++){ ec(); if (dut->cb_done) break; }
    int err = dut->cb_error;
    dut->cb_valid=0; ec();
    return err ? -1 : 0;
}
uint32_t pf_read(uint32_t addr) {
    dut->cb_valid=1; dut->cb_addr=addr; dut->cb_write=0; dut->cb_wdata=0; dut->cb_wmask=0xF;
    for (int i=0;i<100000;i++){ ec(); if (dut->cb_done) break; }
    uint32_t v=dut->cb_rdata; dut->cb_valid=0; ec(); return v;
}
void pf_step(int n) { for (int i=0;i<n;i++) ec(); }
int pf_poll(uint32_t addr, uint32_t mask, uint32_t expect, int max_cycles) {
    for (int i=0;i<max_cycles;i++){ ec(); if ((pf_read(addr)&mask)==expect) return i; }
    return -1;
}
int pf_sig_count(void) { return g_nsig; }
const char* pf_sig_name(int i) { return g_sigs[i].name; }
int pf_sig_words(int i) { return g_sigs[i].words; }
uint32_t pf_sig_value(int i, int w) {
    if (!g_sigs[i].ptr || w >= g_sigs[i].words) return 0;
    return reinterpret_cast<uint32_t*>(g_sigs[i].ptr)[w];
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i = 0; i < g_nsig; i++)
        if (strcmp(g_sigs[i].name, name) == 0) {
            if (!g_sigs[i].ptr || w >= g_sigs[i].words) return 0;
            return reinterpret_cast<uint32_t*>(g_sigs[i].ptr)[w];
        }
    return 0;
}
void pf_reset(void) {
    dut->rst_ni = 0;
    for (int i = 0; i < 5; i++) ec();
    dut->rst_ni = 1;
    ec();
}
uint64_t pf_get_cycle(void) { return main_time/2; }
void pf_final(void) { if (dut){dut->final(); delete dut; dut=nullptr; rootp=nullptr;} }
} // extern "C"

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    pf_init(0);
    printf("[kmac-harness] init OK\n");
    uint32_t st = pf_read(0x1c);
    printf("[kmac-harness] STATUS(reset) = 0x%08x\n", st);
    pf_final();
    return 0;
}
