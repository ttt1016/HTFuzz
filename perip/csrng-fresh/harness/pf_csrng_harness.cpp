// PickerFuzz per-IP C++ harness — CSRNG（M5 模式，cb_* 接口）
// ============================================================================
// API（extern "C"，供 Python ctypes 调用）: 同 hmac harness
// 自检 main: 复位读回 + CTRL shadow 写 + INS/GEN 命令流
// ============================================================================
#include <verilated.h>
#include "Vcsrng_perip_tb.h"
#include "Vcsrng_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

static Vcsrng_perip_tb* dut = nullptr;
static Vcsrng_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    // v1: 首版占位，编译后从 root 头扩充
    {"u_dut.u_csrng_core.u_csrng_main_sm.u_state_regs.state_raw", nullptr, 1, false},
    {"u_dut.u_csrng_core.u_csrng_ctr_drbg_gen.u_state_regs.state_raw", nullptr, 1, false},
    {"u_dut.u_csrng_core.acmd_q", nullptr, 1, false},
    {"u_dut.u_csrng_core.cs_bus_cmp_alert", nullptr, 1, false},
    {"u_dut.u_csrng_core.fatal_loc_events", nullptr, 1, false},
    {"u_dut.u_csrng_core.cmd_stage_sm_err_sum", nullptr, 1, false},
    {"u_dut.u_csrng_core.aes_cipher_sm_err_sum", nullptr, 1, false},
    {"u_dut.u_csrng_core.block_encrypt_sfifo_blkenc_err_sum", nullptr, 1, false},
    {"u_dut.u_csrng_core.u_csrng_block_encrypt.u_aes_cipher_core.add_rk_sel_raw", nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        else if (strcmp(n, "u_dut.u_csrng_core.u_csrng_main_sm.u_state_regs.state_raw") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__u_csrng_main_sm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.u_csrng_core.u_csrng_ctr_drbg_gen.u_state_regs.state_raw") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__u_csrng_ctr_drbg_gen__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.u_csrng_core.acmd_q") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__acmd_q;
        else if (strcmp(n, "u_dut.u_csrng_core.cs_bus_cmp_alert") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__cs_bus_cmp_alert;
        else if (strcmp(n, "u_dut.u_csrng_core.fatal_loc_events") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__fatal_loc_events;
        else if (strcmp(n, "u_dut.u_csrng_core.cmd_stage_sm_err_sum") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__cmd_stage_sm_err_sum;
        else if (strcmp(n, "u_dut.u_csrng_core.aes_cipher_sm_err_sum") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__aes_cipher_sm_err_sum;
        else if (strcmp(n, "u_dut.u_csrng_core.block_encrypt_sfifo_blkenc_err_sum") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__block_encrypt_sfifo_blkenc_err_sum;
        else if (strcmp(n, "u_dut.u_csrng_core.u_csrng_block_encrypt.u_aes_cipher_core.add_rk_sel_raw") == 0) p = &rootp->csrng_perip_tb__DOT__u_dut__DOT__u_csrng_core__DOT__u_csrng_block_encrypt__DOT__u_aes_cipher_core__DOT__add_rk_sel_raw;
        g_sigs[i].ptr = p;
    }
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
    dut = new Vcsrng_perip_tb;
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
    printf("[harness] init(seed=0)...\n");
    pf_init(0);
    printf("[harness] signals bound: %d\n", pf_sig_count());

    // T0: CTRL shadow 两阶段写读回（0x14, mubi4×4 全 True=0x6666）
    pf_write(0x14, 0x6666); pf_write(0x14, 0x6666);
    uint32_t ctrl = pf_read(0x14);
    printf("[harness] CTRL readback = 0x%08x (expect 0x6666)\n", ctrl);

    // T1: instantiate (INS=1) → 等 cmd_req_done
    pf_write(0x18, 0x00000001);  // CMD_REQ
    int done = -1;
    for (int i = 0; i < 200; i++) {
        pf_step(20);
        if (pf_read(0x0) & 0x1) { done = i; break; }  // INTR_STATE.cmd_req_done
    }
    pf_write(0x0, 0x1);  // rw1c 清中断
    printf("[harness] INS done after %d polls\n", done);

    // T2: generate (GEN=3) → GENBITS_VLD → GENBITS ×4
    pf_write(0x18, 0x00000003);
    uint32_t g[4] = {0, 0, 0, 0};
    int got = 0;
    for (int i = 0; i < 400 && got < 4; i++) {
        pf_step(20);
        uint32_t vld = pf_read(0x30);
        if (vld & 0x1) {
            g[got++] = pf_read(0x34);
        }
    }
    printf("[harness] GEN output: %08x %08x %08x %08x (got %d/4)\n",
           g[0], g[1], g[2], g[3], got);

    bool ok = (ctrl == 0x6666u) && (done >= 0) && (got == 4);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
