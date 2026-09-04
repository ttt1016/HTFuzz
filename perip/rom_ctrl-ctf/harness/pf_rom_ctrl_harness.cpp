// PickerFuzz per-IP C++ harness — rom_ctrl（Bug#2: bus_rom_rvalid 时序）
#include <verilated.h>
#include "Vrom_ctrl_perip_tb.h"
#include "Vrom_ctrl_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vrom_ctrl_perip_tb* dut = nullptr;
static Vrom_ctrl_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

// Whitebox signals: bus response timing (Bug#2 target) + FSM
static SigEntry g_sigs[] = {
    {"u_dut.rom_rvalid", nullptr, 1, false},

    {"u_dut.rom_req", nullptr, 1, false},
{"gen_rom_scramble_disabled.u_rom.u_prim_rom.mem", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "gen_rom_scramble_disabled.u_rom.u_prim_rom.mem") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__gen_rom_scramble_disabled__DOT__u_rom__DOT__u_prim_rom__DOT__mem;
        else if (strcmp(n, "u_dut.rom_req") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__rom_req;
        else if (strcmp(n, "u_dut.rom_rvalid") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__rom_rvalid;
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
    static bool args_set = false;
    if (!args_set) {
        const char* argv[] = {"pf_rom_ctrl", "+meminit"};
        Verilated::commandArgs(2, (char**)argv);
        args_set = true;
    }
    if (dut) { dut->final(); delete dut; }
    g_snaps.clear();
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vrom_ctrl_perip_tb;
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

// O-G 脉冲宽度采样: rvalid 拍数 + done 后残留拍数
static int g_rvalid_cycles = 0;
static int g_done_residual = 0;  // cb_done 后 rvalid 仍高的拍数（电平化特征）
uint32_t pf_read(uint32_t addr) {
    dut->cb_valid = 1;
    dut->cb_addr = addr;
    dut->cb_write = 0;
    dut->cb_wdata = 0;
    dut->cb_wmask = 0xF;
    g_rvalid_cycles = 0;
    g_done_residual = 0;
    bool done_seen = false;
    int rvalid_before_done = 0, rvalid_after_done = 0;
    for (int i = 0; i < 10000; i++) {
        eval_cycle();
        bool rv = sig_word(g_sigs[0], 0);
        if (rv) g_rvalid_cycles++;
        if (dut->cb_done) done_seen = true;
        if (rv && !done_seen) rvalid_before_done++;
        if (rv && done_seen) rvalid_after_done++;
        if (done_seen && rv) g_done_residual++;
        if (dut->cb_done) break;
    }
    // 相位差: rvalid 高电平出现在 done 之后的次数（正常应为 0——rvalid 先于/等于 done）
    if (rvalid_after_done > 0 && rvalid_before_done == 0) {
        // rvalid 只在 done 后出现 = 响应与数据错位
        g_done_residual = rvalid_after_done * 10;  // 放大标记相位错位
    }
    uint32_t v = dut->cb_rdata;
    dut->cb_valid = 0;
    // 事务完成后继续采样 8 拍: rvalid 残留 = 电平化 bug 特征
    for (int i = 0; i < 8; i++) {
        eval_cycle();
        if (sig_word(g_sigs[0], 0)) g_done_residual++;
    }
    return v;
}
int pf_rvalid_cycles(void) { return g_rvalid_cycles; }
int pf_done_residual(void) { return g_done_residual; }

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
int pf_sig_bound(int i) { return (i >= 0 && i < g_nsig && g_sigs[i].ptr != nullptr) ? 1 : 0; }
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
int pf_snap_diff(int a, int b) {
    if (a < 0 || b < 0 || a >= (int)g_snaps.size() || b >= (int)g_snaps.size()) return -1;
    int diff = 0;
    int off = 0;
    for (int i = 0; i < g_nsig; i++) {
        for (int w = 0; w < g_sigs[i].words; w++)
            if (g_snaps[a].data[off + w] != g_snaps[b].data[off + w]) diff++;
        off += g_sigs[i].words;
    }
    return diff;
}
uint64_t pf_get_cycle(void) { return main_time / 2; }
void pf_final(void) {
    if (dut) { dut->final(); delete dut; dut = nullptr; rootp = nullptr; }
}

} // extern "C"
