// PickerFuzz per-IP C++ harness — alert_handler
#include <verilated.h>
#include "Valert_handler_perip_tb.h"
#include "Valert_handler_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Valert_handler_perip_tb* dut = nullptr;
static Valert_handler_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

// Whitebox signals: class0-3 累加计数器 + esc_timer FSM 状态 + crashdump
static SigEntry g_sigs[] = {
    {"class0.accu_cnt", nullptr, 1, false},
    {"class1.accu_cnt", nullptr, 1, false},
    {"class2.accu_cnt", nullptr, 1, false},
    {"class3.accu_cnt", nullptr, 1, false},
    {"class0.esc_state", nullptr, 1, false},
    {"class1.esc_state", nullptr, 1, false},
    {"class2.esc_state", nullptr, 1, false},
    {"class3.esc_state", nullptr, 1, false},
    {"u_dut.esc_sig_req0", nullptr, 1, false},
    {"u_dut.esc_sig_req1", nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        else if (strcmp(n, "class0.accu_cnt") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__0__KET____DOT__u_accu__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "class1.accu_cnt") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__1__KET____DOT__u_accu__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "class2.accu_cnt") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__2__KET____DOT__u_accu__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "class3.accu_cnt") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__3__KET____DOT__u_accu__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "class0.esc_state") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__0__KET____DOT__u_esc_timer__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "class1.esc_state") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__1__KET____DOT__u_esc_timer__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "class2.esc_state") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__2__KET____DOT__u_esc_timer__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "class3.esc_state") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__gen_classes__BRA__3__KET____DOT__u_esc_timer__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.esc_sig_req0") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__esc_sig_req__BRA__0__KET__;
        else if (strcmp(n, "u_dut.esc_sig_req1") == 0) p = &rootp->alert_handler_perip_tb__DOT__u_dut__DOT__esc_sig_req__BRA__1__KET__;
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

struct Snapshot { std::vector<uint32_t> data; };
static std::vector<Snapshot> g_snaps;

static void take_snapshot() {
    Snapshot s;
    for (int i = 0; i < g_nsig; i++)
        for (int w = 0; w < g_sigs[i].words; w++)
            s.data.push_back(sig_word(g_sigs[i], w));
    g_snaps.push_back(std::move(s));
}

extern "C" {

int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    g_snaps.clear();
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Valert_handler_perip_tb;
    rootp = dut->rootp;
    bind_signals();
    dut->clk_i = 0;
    dut->rst_ni = 0;
    dut->cb_valid = 0;
    dut->cb_addr = 0;
    dut->cb_write = 0;
    dut->cb_wdata = 0;
    dut->cb_wmask = 0xF;
    for (int i = 0; i < 10; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); main_time += 2; }
    dut->rst_ni = 1;
    dut->eval();
    eval_cycle();
    take_snapshot();
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
    take_snapshot();
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

int pf_poll(uint32_t addr, uint32_t mask, uint32_t expect, int max_cycles) {
    for (int i = 0; i < max_cycles; i++) {
        eval_cycle();
        if ((pf_read(addr) & mask) == expect) return i;
    }
    return -1;
}

void pf_reset(void) {
    dut->rst_ni = 0;
    for (int i = 0; i < 5; i++) eval_cycle();
    dut->rst_ni = 1;
    eval_cycle();
    take_snapshot();
}

int pf_snapshot(void) { take_snapshot(); return (int)g_snaps.size() - 1; }
int pf_snap_count(void) { return (int)g_snaps.size(); }
int pf_sig_count(void) { return g_nsig; }
const char* pf_sig_name(int i) { return (i >= 0 && i < g_nsig) ? g_sigs[i].name : ""; }
int pf_sig_words(int i) { return (i >= 0 && i < g_nsig) ? g_sigs[i].words : 0; }
uint32_t pf_sig_value(int i, int w) {
    if (i < 0 || i >= g_nsig || w >= g_sigs[i].words) return 0;
    return sig_word(g_sigs[i], w);
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i = 0; i < g_nsig; i++)
        if (strcmp(g_sigs[i].name, name) == 0) return sig_word(g_sigs[i], w);
    return 0;
}
uint32_t pf_snap_value(int s, int i, int w) {
    if (s < 0 || s >= (int)g_snaps.size() || i < 0 || i >= g_nsig) return 0;
    int off = 0;
    for (int k = 0; k < i; k++) off += g_sigs[k].words;
    if (w >= g_sigs[i].words) return 0;
    return g_snaps[s].data[off + w];
}

} // extern "C"
