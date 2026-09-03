// HTFuzz per-IP C++ harness — LC_CTRL（cb_* 接口）
// ============================================================================
// API（extern "C"，供 Python ctypes 调用）: 同 csrng harness
// 白盒: FSM 状态 / token mux（#28 截断比较面）/ 错误旗标 / 转移令牌
// 自检 main: STATUS 读回 + CLAIM mutex + LC_STATE 读 + 转移命令流
// ============================================================================
#include <verilated.h>
#include "Vlc_perip_tb.h"
#include "Vlc_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vlc_perip_tb* dut = nullptr;
static Vlc_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };
// is_wide=true 时按 uint32 读（VlWide/IData）；fsm_state_q 是 SData(16b)，用 half 读取

static SigEntry g_sigs[] = {
    {"u_dut.u_lc_ctrl_fsm.fsm_state_q",                     nullptr, 1, true },  // SData: half 读
    {"u_dut.u_lc_ctrl_fsm.hashed_token_mux",                nullptr, 4, true },
    {"u_dut.transition_token_q",                            nullptr, 4, true },
    {"u_dut.transition_target_q",                           nullptr, 1, true },
    {"u_dut.u_lc_ctrl_fsm.state_invalid_error",             nullptr, 1, false},
    {"u_dut.trans_success_q",                               nullptr, 1, false},
    {"u_dut.token_invalid_error_q",                         nullptr, 1, false},
    {"u_dut.fatal_state_error_q",                           nullptr, 1, false},
    {"u_dut.fatal_prog_error_q",                            nullptr, 1, false},
    {"u_dut.fatal_bus_integ_error_q",                       nullptr, 1, false},
    {"u_dut.otp_part_error_q",                              nullptr, 1, false},
    {"u_dut.use_ext_clock_q",                               nullptr, 1, false},
    {"u_dut.u_lc_ctrl_kmac_if.kmac_fsm_err_q",              nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);
static const char* g_half_sigs[] = {"u_dut.u_lc_ctrl_fsm.fsm_state_q"};

static bool is_half_sig(const char* n) {
    for (size_t k = 0; k < sizeof(g_half_sigs)/sizeof(g_half_sigs[0]); k++)
        if (strcmp(n, g_half_sigs[k]) == 0) return true;
    return false;
}

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        else if (strcmp(n, "u_dut.u_lc_ctrl_fsm.fsm_state_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__u_lc_ctrl_fsm__DOT__u_fsm_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "u_dut.u_lc_ctrl_fsm.hashed_token_mux") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__u_lc_ctrl_fsm__DOT__hashed_token_mux;
        else if (strcmp(n, "u_dut.transition_token_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__transition_token_q;
        else if (strcmp(n, "u_dut.transition_target_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__transition_target_q;
        else if (strcmp(n, "u_dut.u_lc_ctrl_fsm.state_invalid_error") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__u_lc_ctrl_fsm__DOT__state_invalid_error;
        else if (strcmp(n, "u_dut.trans_success_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__trans_success_q;
        else if (strcmp(n, "u_dut.token_invalid_error_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__token_invalid_error_q;
        else if (strcmp(n, "u_dut.fatal_state_error_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__fatal_state_error_q;
        else if (strcmp(n, "u_dut.fatal_prog_error_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__fatal_prog_error_q;
        else if (strcmp(n, "u_dut.fatal_bus_integ_error_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__fatal_bus_integ_error_q;
        else if (strcmp(n, "u_dut.otp_part_error_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__otp_part_error_q;
        else if (strcmp(n, "u_dut.use_ext_clock_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__use_ext_clock_q;
        else if (strcmp(n, "u_dut.u_lc_ctrl_kmac_if.kmac_fsm_err_q") == 0)
            p = &rootp->lc_perip_tb__DOT__u_dut__DOT__u_lc_ctrl_kmac_if__DOT__kmac_fsm_err_q;
        g_sigs[i].ptr = p;
    }
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
    dut = new Vlc_perip_tb;
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
    int bound = 0;
    for (int i = 0; i < pf_sig_count(); i++) if (pf_sig_value(i, 0) != 0 || pf_sig_name(i)[0]) bound++;
    printf("[harness] signals: %d\n", pf_sig_count());

    // T0: 等 init 握手完成后读 STATUS（initialized/ready 置位）
    pf_step(30);
    uint32_t st = pf_read(0x04);
    printf("[harness] STATUS(post-init) = 0x%08x\n", st);

    // T1: LC_STATE RO 读回（应反映 otp_lc_data 驱动的 Dev 状态）
    uint32_t lcs = pf_read(0x38);
    printf("[harness] LC_STATE = 0x%08x\n", lcs);

    // T2: CLAIM_TRANSITION_IF mutex（MuBi8True=0x96）→ 读回
    pf_write(0x0C, 0x00000096);
    uint32_t claim = pf_read(0x0C);
    printf("[harness] CLAIM readback = 0x%08x\n", claim);

    // T3: 转移流: TOKEN=全 A5 → TARGET=RMA → CMD=1 → 观察 FSM/token 错误
    pf_write(0x1C, 0xA5A5A5A5); pf_write(0x20, 0xA5A5A5A5);
    pf_write(0x24, 0xA5A5A5A5); pf_write(0x28, 0xA5A5A5A5);
    pf_write(0x2C, 0x1F1F1F1F);  // TRANSITION_TARGET（RMA 编码复制）
    pf_write(0x14, 0x00000001);  // TRANSITION_CMD.start
    pf_step(100);
    uint32_t fsm = pf_sig_read("u_dut.u_lc_ctrl_fsm.fsm_state_q", 0);
    uint32_t tok_err = pf_sig_read("u_dut.token_invalid_error_q", 0);
    uint32_t st_err = pf_sig_read("u_dut.fatal_state_error_q", 0);
    printf("[harness] after CMD: fsm_state=0x%04x token_err=%u state_err=%u\n",
           fsm, tok_err, st_err);

    bool ok = (st != 0) && (claim == 0x00000096u) && (fsm != 0);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
