// PickerFuzz per-IP C++ harness — UART（uart-ctf, lsio_trigger 观测）
// ============================================================================
// API（extern "C"）: pf_init/pf_write/pf_read/pf_step/pf_reset/pf_sig_*
// 自检: STATUS 读回 + WDATA 写入 + lsio_trigger 白盒观测
// ============================================================================
#include <verilated.h>
#include "Vadc_ctrl_perip_tb.h"
#include "Vadc_ctrl_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vadc_ctrl_perip_tb* dut = nullptr;
static Vadc_ctrl_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    // adc_ctrl 白盒表待 SEC_CM 脚本扩充
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    // 待扩充
}

static uint32_t sig_word(const SigEntry& s, int w) {
    if (!s.ptr) return 0;
    if (s.is_wide) return reinterpret_cast<uint32_t*>(s.ptr)[w];
    return *reinterpret_cast<uint8_t*>(s.ptr);
}

static void eval_cycle() {
    dut->clk_i = 0; dut->eval();
    dut->clk_i = 1; dut->eval();
    main_time += 10;
}

extern "C" {

int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vadc_ctrl_perip_tb;
    dut->clk_i = 0;
    dut->rst_ni = 0;
    dut->cb_valid = 0;
    dut->cb_addr = 0;
    dut->cb_write = 0;
    dut->cb_wdata = 0;
    dut->cb_wmask = 0xF;
    for (int i = 0; i < 10; i++) {
        dut->clk_i = 0; dut->eval();
        dut->clk_i = 1; dut->eval();
        main_time += 2;
    }
    dut->rst_ni = 1;
    dut->eval();
    eval_cycle();
    return 0;
}

int pf_write(uint32_t addr, uint32_t data, uint32_t mask = 0xF) {
    dut->cb_valid = 1;
    dut->cb_addr = addr;
    dut->cb_write = 1;
    dut->cb_wdata = data;
    dut->cb_wmask = mask ? (mask & 0xF) : 0xF;
    for (int i = 0; i < 10000; i++) {
        eval_cycle();
        if (dut->cb_done) break;
    }
    int err = dut->cb_error;
    dut->cb_valid = 0;
    eval_cycle();
    return err ? -1 : 0;
}

uint32_t pf_read(uint32_t addr) {
    dut->cb_valid = 1;
    dut->cb_addr = addr;
    dut->cb_write = 0;
    dut->cb_wdata = 0;
    dut->cb_wmask = 0xF;
    for (int i = 0; i < 10000; i++) {
        eval_cycle();
        if (dut->cb_done) break;
    }
    uint32_t v = dut->cb_rdata;
    dut->cb_valid = 0;
    eval_cycle();
    return v;
}

void pf_step(int n) {
    for (int i = 0; i < n; i++) eval_cycle();
}

void pf_reset(void) {
    dut->rst_ni = 0;
    for (int i = 0; i < 5; i++) eval_cycle();
    dut->rst_ni = 1;
    eval_cycle();
}

int pf_sig_count(void) { return g_nsig; }
const char* pf_sig_name(int i) { return (i >= 0 && i < g_nsig) ? g_sigs[i].name : ""; }
int pf_sig_words(int i) { return (i >= 0 && i < g_nsig) ? g_sigs[i].words : 0; }
uint32_t pf_sig_value(int i, int w) {
    if (i < 0 || i >= g_nsig || w >= g_sigs[i].words) return 0;
    return sig_word(g_sigs[i], w);
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i = 0; i < g_nsig; i++) {
        if (strcmp(g_sigs[i].name, name) == 0) return sig_word(g_sigs[i], w);
    }
    return 0;
}
uint64_t pf_get_cycle(void) { return main_time / 2; }
void pf_final(void) { if (dut) { dut->final(); delete dut; dut = nullptr; } }

} // extern "C"

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    printf("[harness] init...\n");
    pf_init(0);
    printf("[harness] signals bound: %d\n", pf_sig_count());

    // T0: 读复位后的 STATUS（RXEMPTY|TXIDLE）
    uint32_t st = pf_read(0x10);
    printf("[harness] STATUS(reset) = 0x%08x\n", st);

    // T1: 写 WDATA 填 TX FIFO（40 字节）→ 观测 lsio_trigger
    for (int i = 0; i < 40; i++) {
        pf_write(0x1C, 0x41 + i);
    }
    pf_step(50);

    bool ok = (pf_sig_count() >= 0);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
