// PickerFuzz per-IP C++ harness — pwrmgr
#include <verilated.h>
#include "Vpwrmgr_perip_tb.h"
#include "Vpwrmgr_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vpwrmgr_perip_tb* dut = nullptr;
static Vpwrmgr_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

// Whitebox signals: fast FSM state / slow FSM / power handshakes (verified in root header)
static SigEntry g_sigs[] = {
    {"u_fsm.state_raw", nullptr, 1, false},
    {"u_fsm.low_power_q", nullptr, 1, false},
    {"u_fsm.req_pwrdn_q", nullptr, 1, false},
    {"u_fsm.ack_pwrup_q", nullptr, 1, false},
    {"u_fsm.ip_clk_en_q", nullptr, 1, false},
    {"u_fsm.lc_done", nullptr, 1, false},
    {"u_fsm.fsm_invalid", nullptr, 1, false},
    {"u_slow_fsm.state_raw", nullptr, 1, false},
{"fsm_invalid", nullptr, 1, true },
{"u_cdc.u_int_fsm_invalid_sync.intq", nullptr, 1, true },
{"u_esc_rx.state_q", nullptr, 1, true },
{"u_esc_rx.u_prim_count.err_q", nullptr, 1, true },
{"u_esc_rx.u_prim_count.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_esc_rx.u_prim_count.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_esc_timeout.u_ref_timeout.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_esc_timeout.u_ref_timeout.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_esc_timeout.u_ref_timeout.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_fsm.__VlemCall_3__mubi4_test_true_strict", nullptr, 1, true },
{"u_fsm.__VlemCall_4__mubi4_test_true_strict", nullptr, 1, true },
{"u_fsm.__VlemCall_5__lc_tx_test_false_loose", nullptr, 1, true },
{"u_fsm.ack_pwrup_d", nullptr, 1, true },
{"u_fsm.ip_clk_en_d", nullptr, 1, true },
{"u_fsm.low_power_d", nullptr, 1, true },
{"u_fsm.req_pwrdn_d", nullptr, 1, true },
{"u_fsm.reset_cause_d", nullptr, 1, true },
{"u_fsm.reset_cause_q", nullptr, 1, true },
{"u_fsm.reset_ongoing_d", nullptr, 1, true },
{"u_fsm.reset_ongoing_q", nullptr, 1, true },
{"u_fsm.rst_lc_req_d", nullptr, 1, true },
{"u_fsm.rst_lc_req_q", nullptr, 1, true },
{"u_fsm.rst_sys_req_d", nullptr, 1, true },
{"u_fsm.rst_sys_req_q", nullptr, 1, true },
{"u_fsm.slow_lc_done", nullptr, 1, true },
{"u_fsm.state_d", nullptr, 1, true },
{"u_fsm.u_slow_sync_lc_done.intq", nullptr, 1, true },
{"u_fsm.u_state_regs.state_raw", nullptr, 1, true },
{"u_fsm.u_sync_lc_done.intq", nullptr, 1, true },
{"u_reg.u_reg_if.rdata_q", nullptr, 1, true },
{"u_slow_fsm.ack_pwrdn_d", nullptr, 1, true },
{"u_slow_fsm.ack_pwrdn_q", nullptr, 1, true },
{"u_slow_fsm.async_main_pok_st", nullptr, 1, true },
{"u_slow_fsm.cause_d", nullptr, 1, true },
{"u_slow_fsm.cause_q", nullptr, 1, true },
{"u_slow_fsm.cause_toggle_d", nullptr, 1, true },
{"u_slow_fsm.cause_toggle_q", nullptr, 1, true },
{"u_slow_fsm.clk_active", nullptr, 1, true },
{"u_slow_fsm.fsm_invalid_d", nullptr, 1, true },
{"u_slow_fsm.fsm_invalid_q", nullptr, 1, true },
{"u_slow_fsm.main_pok_st", nullptr, 1, true },
{"u_slow_fsm.mon_main_pok", nullptr, 1, true },
{"u_slow_fsm.pd_nd", nullptr, 1, true },
{"u_slow_fsm.pd_nq", nullptr, 1, true },
{"u_slow_fsm.req_pwrup_d", nullptr, 1, true },
{"u_slow_fsm.req_pwrup_q", nullptr, 1, true },
{"u_slow_fsm.set_main_pok", nullptr, 1, true },
{"u_slow_fsm.state_d", nullptr, 1, true },
{"u_slow_fsm.u_main_pok_sync.intq", nullptr, 1, true },
{"u_slow_fsm.u_state_regs.state_raw", nullptr, 1, true },
{"u_slow_fsm.usb_clk_en_lp", nullptr, 1, true },
{"u_slow_fsm.usb_clk_en_q", nullptr, 1, true },
{"u_reg.err_q", nullptr, 1, true },
{"u_reg.intg_err", nullptr, 1, true },
{"u_reg.reg_error", nullptr, 1, true },
{"u_reg.reg_we_err", nullptr, 1, true },
{"u_reg.u_escalate_reset_status.q", nullptr, 1, true },
{"u_reg.u_reg_if.err_internal", nullptr, 1, true },
{"u_reg.u_reg_if.error_q", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "fsm_invalid") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__fsm_invalid;
        else if (strcmp(n, "u_cdc.u_int_fsm_invalid_sync.intq") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_cdc__DOT__u_int_fsm_invalid_sync__DOT__intq;
        else if (strcmp(n, "u_esc_rx.state_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_rx__DOT__state_q;
        else if (strcmp(n, "u_esc_rx.u_prim_count.err_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_rx__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "u_esc_rx.u_prim_count.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_rx__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_esc_rx.u_prim_count.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_rx__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_esc_timeout.u_ref_timeout.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_timeout__DOT__u_ref_timeout__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_esc_timeout.u_ref_timeout.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_timeout__DOT__u_ref_timeout__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_esc_timeout.u_ref_timeout.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_esc_timeout__DOT__u_ref_timeout__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_fsm.__VlemCall_3__mubi4_test_true_strict") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT____VlemCall_3__mubi4_test_true_strict;
        else if (strcmp(n, "u_fsm.__VlemCall_4__mubi4_test_true_strict") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT____VlemCall_4__mubi4_test_true_strict;
        else if (strcmp(n, "u_fsm.__VlemCall_5__lc_tx_test_false_loose") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT____VlemCall_5__lc_tx_test_false_loose;
        else if (strcmp(n, "u_fsm.ack_pwrup_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__ack_pwrup_d;
        else if (strcmp(n, "u_fsm.ack_pwrup_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__ack_pwrup_q;
        else if (strcmp(n, "u_fsm.fsm_invalid") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__fsm_invalid;
        else if (strcmp(n, "u_fsm.ip_clk_en_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__ip_clk_en_d;
        else if (strcmp(n, "u_fsm.ip_clk_en_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__ip_clk_en_q;
        else if (strcmp(n, "u_fsm.lc_done") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__lc_done;
        else if (strcmp(n, "u_fsm.low_power_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__low_power_d;
        else if (strcmp(n, "u_fsm.low_power_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__low_power_q;
        else if (strcmp(n, "u_fsm.req_pwrdn_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__req_pwrdn_d;
        else if (strcmp(n, "u_fsm.req_pwrdn_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__req_pwrdn_q;
        else if (strcmp(n, "u_fsm.reset_cause_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__reset_cause_d;
        else if (strcmp(n, "u_fsm.reset_cause_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__reset_cause_q;
        else if (strcmp(n, "u_fsm.reset_ongoing_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__reset_ongoing_d;
        else if (strcmp(n, "u_fsm.reset_ongoing_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__reset_ongoing_q;
        else if (strcmp(n, "u_fsm.rst_lc_req_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__rst_lc_req_d;
        else if (strcmp(n, "u_fsm.rst_lc_req_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__rst_lc_req_q;
        else if (strcmp(n, "u_fsm.rst_sys_req_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__rst_sys_req_d;
        else if (strcmp(n, "u_fsm.rst_sys_req_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__rst_sys_req_q;
        else if (strcmp(n, "u_fsm.slow_lc_done") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__slow_lc_done;
        else if (strcmp(n, "u_fsm.state_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__state_d;
        else if (strcmp(n, "u_fsm.state_raw") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_fsm.u_slow_sync_lc_done.intq") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__u_slow_sync_lc_done__DOT__intq;
        else if (strcmp(n, "u_fsm.u_state_regs.state_raw") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_fsm.u_sync_lc_done.intq") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__u_sync_lc_done__DOT__intq;
        else if (strcmp(n, "u_reg.err_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__err_q;
        else if (strcmp(n, "u_reg.intg_err") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__intg_err;
        else if (strcmp(n, "u_reg.reg_error") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_error;
        else if (strcmp(n, "u_reg.reg_we_err") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_we_err;
        else if (strcmp(n, "u_reg.u_escalate_reset_status.q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_escalate_reset_status__DOT__q;
        else if (strcmp(n, "u_reg.u_reg_if.err_internal") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__err_internal;
        else if (strcmp(n, "u_reg.u_reg_if.error_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__error_q;
        else if (strcmp(n, "u_reg.u_reg_if.rdata_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__rdata_q;
        else if (strcmp(n, "u_slow_fsm.ack_pwrdn_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__ack_pwrdn_d;
        else if (strcmp(n, "u_slow_fsm.ack_pwrdn_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__ack_pwrdn_q;
        else if (strcmp(n, "u_slow_fsm.async_main_pok_st") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__async_main_pok_st;
        else if (strcmp(n, "u_slow_fsm.cause_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__cause_d;
        else if (strcmp(n, "u_slow_fsm.cause_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__cause_q;
        else if (strcmp(n, "u_slow_fsm.cause_toggle_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__cause_toggle_d;
        else if (strcmp(n, "u_slow_fsm.cause_toggle_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__cause_toggle_q;
        else if (strcmp(n, "u_slow_fsm.clk_active") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__clk_active;
        else if (strcmp(n, "u_slow_fsm.fsm_invalid_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__fsm_invalid_d;
        else if (strcmp(n, "u_slow_fsm.fsm_invalid_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__fsm_invalid_q;
        else if (strcmp(n, "u_slow_fsm.main_pok_st") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__main_pok_st;
        else if (strcmp(n, "u_slow_fsm.mon_main_pok") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__mon_main_pok;
        else if (strcmp(n, "u_slow_fsm.pd_nd") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__pd_nd;
        else if (strcmp(n, "u_slow_fsm.pd_nq") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__pd_nq;
        else if (strcmp(n, "u_slow_fsm.req_pwrup_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__req_pwrup_d;
        else if (strcmp(n, "u_slow_fsm.req_pwrup_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__req_pwrup_q;
        else if (strcmp(n, "u_slow_fsm.set_main_pok") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__set_main_pok;
        else if (strcmp(n, "u_slow_fsm.state_d") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__state_d;
        else if (strcmp(n, "u_slow_fsm.state_raw") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_slow_fsm.u_main_pok_sync.intq") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__u_main_pok_sync__DOT__intq;
        else if (strcmp(n, "u_slow_fsm.u_state_regs.state_raw") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_slow_fsm.usb_clk_en_lp") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__usb_clk_en_lp;
        else if (strcmp(n, "u_slow_fsm.usb_clk_en_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__usb_clk_en_q;
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
    dut = new Vpwrmgr_perip_tb;
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
