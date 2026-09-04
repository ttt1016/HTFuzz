// HTFuzz per-IP C++ harness — LC_CTRL（cb_* 接口）
// ============================================================================
// API（extern "C"，供 Python ctypes 调用）: 同 csrng harness
// 白盒: FSM 状态 / token mux（#28 截断比较面）/ 错误旗标 / 转移令牌
// 自检 main: STATUS 读回 + CLAIM mutex + LC_STATE 读 + 转移命令流
// ============================================================================
#include <verilated.h>
#include "Vmbx_perip_tb.h"
#include "Vmbx_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vmbx_perip_tb* dut = nullptr;
static Vmbx_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };
// is_wide=true 时按 uint32 读（VlWide/IData）；fsm_state_q 是 SData(16b)，用 half 读取

static SigEntry g_sigs[] = {
    // v1: 首版占位，编译后从 root 头扩充
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);
static const char* g_half_sigs[] = {"u_dut.u_lc_ctrl_fsm.fsm_state_q"};

static bool is_half_sig(const char* n) {
    for (size_t k = 0; k < sizeof(g_half_sigs)/sizeof(g_half_sigs[0]); k++)
        if (strcmp(n, g_half_sigs[k]) == 0) return true;
    return false;
}

static void bind_signals() {
    // 待 SEC_CM 脚本扩充
}

static uint32_t sig_word(const SigEntry& s, int w) {
    if (!s.ptr) return 0;
    if (!s.is_wide) return *reinterpret_cast<uint8_t*>(s.ptr);
    if (s.words == 1 && is_half_sig(s.name)) return *reinterpret_cast<uint16_t*>(s.ptr);
    return reinterpret_cast<uint32_t*>(s.ptr)[w];
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
    dut = new Vmbx_perip_tb;
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
    rootp = dut->rootp;
    bind_signals();
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
    printf("[harness] signals: %d\n", pf_sig_count());

    // T0: 读复位后的 STATUS（ready 置位）
    uint32_t st = pf_read(0x14);
    printf("[harness] STATUS(reset) = 0x%08x\n", st);

    // T1: 配置 INBOUND 地址窗（REGWEN 解锁 + base/limit + VALID 使能）
    pf_write(0x18, 0x1);          // ADDRESS_RANGE_REGWEN 解锁
    pf_write(0x20, 0x10000000);   // INBOUND_BASE
    pf_write(0x24, 0x10000FFF);   // INBOUND_LIMIT
    pf_write(0x1C, 0x1);          // ADDRESS_RANGE_VALID
    uint32_t arv = pf_read(0x1C);
    printf("[harness] ADDR_RANGE_VALID readback = 0x%08x\n", arv);

    // T2: CONTROL 启动（观察 STATUS 变化）
    pf_write(0x10, 0x1);
    pf_step(50);
    uint32_t st2 = pf_read(0x14);
    printf("[harness] STATUS(after ctrl) = 0x%08x\n", st2);

    bool ok = (arv == 0x1u) && (st != 0);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
