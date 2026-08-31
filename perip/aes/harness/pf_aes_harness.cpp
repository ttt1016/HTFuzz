// PickerFuzz per-IP C++ harness — AES (aes-ctf)
#include <verilated.h>
#include "Vaes_perip_tb.h"
#include "Vaes_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

static Vaes_perip_tb* dut = nullptr;
static Vaes_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };
#define SIGD(n) rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__##n
#define SIGC(n) rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_cipher_core__DOT__##n

static SigEntry g_sigs[] = {
    {"u_dut.data_in_prev_q", nullptr, 4, true},
    {"u_dut.key_init", nullptr, 16, true},
    {"u_dut.data_out_q", nullptr, 4, true},
    {"u_dut.key_full_q", nullptr, 8, true},
    {"u_dut.key_dec_q", nullptr, 8, true},
};
static const int g_nsig = sizeof(g_sigs)/sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        if (strcmp(n, "u_dut.data_in_prev_q") == 0) g_sigs[i].ptr = &SIGD(data_in_prev_q);
        else if (strcmp(n, "u_dut.key_init") == 0) g_sigs[i].ptr = &SIGD(key_init);
        else if (strcmp(n, "u_dut.data_out_q") == 0) g_sigs[i].ptr = &SIGD(data_out_q);
        else if (strcmp(n, "u_dut.key_full_q") == 0) g_sigs[i].ptr = &SIGC(key_full_q);
        else if (strcmp(n, "u_dut.key_dec_q") == 0) g_sigs[i].ptr = &SIGC(key_dec_q);
    }
}

static void ec() { dut->clk_i=0; dut->eval(); dut->clk_i=1; dut->eval(); main_time+=10; }

extern "C" {
int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vaes_perip_tb;
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
void pf_reset(void) { dut->rst_ni=0; for(int i=0;i<5;i++) ec(); dut->rst_ni=1; ec(); }
int pf_sig_count(void) { return g_nsig; }
const char* pf_sig_name(int i) { return g_sigs[i].name; }
int pf_sig_words(int i) { return g_sigs[i].words; }
uint32_t pf_sig_value(int i, int w) {
    if (!g_sigs[i].ptr || w >= g_sigs[i].words) return 0;
    return reinterpret_cast<uint32_t*>(g_sigs[i].ptr)[w];
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i=0;i<g_nsig;i++) if (strcmp(g_sigs[i].name,name)==0) return pf_sig_value(i,w);
    return 0;
}
uint64_t pf_get_cycle(void) { return main_time/2; }
void pf_final(void) { if (dut){dut->final(); delete dut; dut=nullptr; rootp=nullptr;} }
} // extern "C"

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    pf_init(0);
    printf("[aes-harness] init OK\n");
    // 自检: 读 STATUS 复位值（idle=1）
    uint32_t st = pf_read(0x84);
    printf("[aes-harness] STATUS(reset) = 0x%08x (expect 0x1: idle)\n", st);
    bool ok = (st == 0x1u);
    printf("[aes-harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
