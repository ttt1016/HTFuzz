// PickerFuzz per-IP C++ harness — entropy_src
// API 与 hmac harness 完全一致（pf_init/write/read/step/poll/reset/sig_*)
#include <verilated.h>
#include "Ventropy_src_perip_tb.h"
#include "Ventropy_src_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

static Ventropy_src_perip_tb* dut = nullptr;
static Ventropy_src_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry {
    const char* name;
    void* ptr;
    int words;
    bool is_wide;
};

// 白盒信号表: entropy_src 安全关键信号（熵数据/健康检查/FSM/FIFO）
static SigEntry g_sigs[] = {
    // 熵数据通路（O-A 残留 / O-B 确定性目标）
    {"u_core.es_rdata_capt_q", nullptr, 1, false},
    {"u_core.msg_data", nullptr, 1, false},
    {"u_sha3.keccak_data", nullptr, 2, true},
    // 健康检查事件计数（O-B 目标: 计数应随熵流变化）
    {"u_core.repcnt_event_cnt", nullptr, 1, false},
    {"u_core.adaptp_hi_event_cnt", nullptr, 1, false},
    {"u_core.adaptp_lo_event_cnt", nullptr, 1, false},
    {"u_core.markov_hi_event_cnt", nullptr, 1, false},
    {"u_core.markov_lo_event_cnt", nullptr, 1, false},
    {"u_core.any_fail_pulse", nullptr, 1, false},
    {"u_core.ht_failed_q", nullptr, 1, false},
    // FSM（O-D 目标）
    {"u_core.main_sm_state_raw", nullptr, 1, false},
    {"u_core.ack_sm_state_raw", nullptr, 1, false},
    {"u_core.es_main_sm_idle", nullptr, 1, false},
    {"u_core.main_sm_done_pulse", nullptr, 1, false},
    // FIFO 状态（O-E 目标）
    {"u_core.sfifo_esrng_full", nullptr, 1, false},
    {"u_core.sfifo_esrng_rdata", nullptr, 1, false},
    {"u_core.sfifo_observe_full", nullptr, 1, false},
    {"u_core.sfifo_observe_depth", nullptr, 1, false},
    {"u_core.sfifo_esfinal_full", nullptr, 1, false},
    {"u_core.sfifo_esfinal_rdata", nullptr, 1, false},
    {"u_core.sfifo_distr_full", nullptr, 1, false},
    {"u_core.fw_ov_wr_fifo_full", nullptr, 1, false},
    // 使能/配置
    {"u_core.fw_ov_mode", nullptr, 1, false},
    {"u_core.fw_ov_mode_entropy_insert", nullptr, 1, false},
    {"u_core.rng_enable_q", nullptr, 1, false},
    {"u_core.rng_bit_sel", nullptr, 1, false},
    {"u_core.es_data_reg_rd_en", nullptr, 1, false},
    {"u_core.es_bypass_mode", nullptr, 1, false},
    // 告警/错误
    {"u_core.es_main_sm_alert", nullptr, 1, false},
    {"u_core.es_ack_sm_err", nullptr, 1, false},
    {"u_core.es_cntr_err", nullptr, 1, false},
    {"u_core.es_bus_cmp_alert", nullptr, 1, false},
    // sha3 子块
    {"u_sha3.st_d", nullptr, 1, false},
    {"u_sha3.absorbed", nullptr, 1, false},
    {"u_sha3.squeezing", nullptr, 1, false},
    {"u_sha3.state_valid", nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        // 前缀: rootp->entropy_src_perip_tb__DOT__u_dut__DOT__
        #define CORE(name) rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__##name
        if (0) {}
        else if (strcmp(n, "u_core.es_rdata_capt_q") == 0) p = &CORE(es_rdata_capt_q);
        else if (strcmp(n, "u_core.msg_data") == 0) p = &CORE(msg_data);
        else if (strcmp(n, "u_sha3.keccak_data") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_sha3__DOT__keccak_data;
        else if (strcmp(n, "u_core.repcnt_event_cnt") == 0) p = &CORE(repcnt_event_cnt);
        else if (strcmp(n, "u_core.adaptp_hi_event_cnt") == 0) p = &CORE(adaptp_hi_event_cnt);
        else if (strcmp(n, "u_core.adaptp_lo_event_cnt") == 0) p = &CORE(adaptp_lo_event_cnt);
        else if (strcmp(n, "u_core.markov_hi_event_cnt") == 0) p = &CORE(markov_hi_event_cnt);
        else if (strcmp(n, "u_core.markov_lo_event_cnt") == 0) p = &CORE(markov_lo_event_cnt);
        else if (strcmp(n, "u_core.any_fail_pulse") == 0) p = &CORE(any_fail_pulse);
        else if (strcmp(n, "u_core.ht_failed_q") == 0) p = &CORE(ht_failed_q);
        else if (strcmp(n, "u_core.main_sm_state_raw") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_entropy_src_main_sm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_core.ack_sm_state_raw") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_entropy_src_ack_sm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_core.es_main_sm_idle") == 0) p = &CORE(es_main_sm_idle);
        else if (strcmp(n, "u_core.main_sm_done_pulse") == 0) p = &CORE(main_sm_done_pulse);
        else if (strcmp(n, "u_core.sfifo_esrng_full") == 0) p = &CORE(sfifo_esrng_full);
        else if (strcmp(n, "u_core.sfifo_esrng_rdata") == 0) p = &CORE(sfifo_esrng_rdata);
        else if (strcmp(n, "u_core.sfifo_observe_full") == 0) p = &CORE(sfifo_observe_full);
        else if (strcmp(n, "u_core.sfifo_observe_depth") == 0) p = &CORE(sfifo_observe_depth);
        else if (strcmp(n, "u_core.sfifo_esfinal_full") == 0) p = &CORE(sfifo_esfinal_full);
        else if (strcmp(n, "u_core.sfifo_esfinal_rdata") == 0) p = &CORE(sfifo_esfinal_rdata);
        else if (strcmp(n, "u_core.sfifo_distr_full") == 0) p = &CORE(sfifo_distr_full);
        else if (strcmp(n, "u_core.fw_ov_wr_fifo_full") == 0) p = &CORE(fw_ov_wr_fifo_full);
        else if (strcmp(n, "u_core.fw_ov_mode") == 0) p = &CORE(fw_ov_mode);
        else if (strcmp(n, "u_core.fw_ov_mode_entropy_insert") == 0) p = &CORE(fw_ov_mode_entropy_insert);
        else if (strcmp(n, "u_core.rng_enable_q") == 0) p = &CORE(rng_enable_q);
        else if (strcmp(n, "u_core.rng_bit_sel") == 0) p = &CORE(rng_bit_sel);
        else if (strcmp(n, "u_core.es_data_reg_rd_en") == 0) p = &CORE(es_data_reg_rd_en);
        else if (strcmp(n, "u_core.es_bypass_mode") == 0) p = &CORE(es_bypass_mode);
        else if (strcmp(n, "u_core.es_main_sm_alert") == 0) p = &CORE(es_main_sm_alert);
        else if (strcmp(n, "u_core.es_ack_sm_err") == 0) p = &CORE(es_ack_sm_err);
        else if (strcmp(n, "u_core.es_cntr_err") == 0) p = &CORE(es_cntr_err);
        else if (strcmp(n, "u_core.es_bus_cmp_alert") == 0) p = &CORE(es_bus_cmp_alert);
        else if (strcmp(n, "u_sha3.st_d") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_sha3__DOT__st_d;
        else if (strcmp(n, "u_sha3.absorbed") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_sha3__DOT__absorbed;
        else if (strcmp(n, "u_sha3.squeezing") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_sha3__DOT__squeezing;
        else if (strcmp(n, "u_sha3.state_valid") == 0) p = &rootp->entropy_src_perip_tb__DOT__u_dut__DOT__u_entropy_src_core__DOT__u_sha3__DOT__state_valid;
        #undef CORE
        g_sigs[i].ptr = p;
    }
}

static uint32_t sig_word(const SigEntry& s, int w) {
    if (!s.ptr) return 0;
    if (s.is_wide) {
        uint32_t* words = reinterpret_cast<uint32_t*>(s.ptr);
        return words[w];
    }
    uint8_t* bytes = reinterpret_cast<uint8_t*>(s.ptr);
    return bytes[0];
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
    dut = new Ventropy_src_perip_tb;
    rootp = dut->rootp;
    bind_signals();
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

// 自检 main: FW_OV 路径供熵 → 观察健康检查计数器变化
int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    printf("[es-harness] init(seed=0)...\n");
    pf_init(0);
    printf("[es-harness] signals bound: %d\n", pf_sig_count());

    // 读复位值
    uint32_t st = pf_read(0x24);  // CONF
    printf("[es-harness] CONF(reset) = 0x%08x\n", st);

    // 使能模块 + FW_OV 模式
    pf_write(0x24, 0x66666666);   // CONF: 全部 mubi4=True
    pf_write(0x18, 0x66);         // MODULE_ENABLE = True (mubi4)
    pf_write(0xB0, 0x66);         // FW_OV_CONTROL: fw_ov_mode + insert = True
    pf_step(20);
    // FW_OV 写熵数据
    for (int i = 0; i < 16; i++) {
        pf_write(0xC4, 0xDEADBEEF ^ (i * 0x01010101));  // FW_OV_WR_DATA
        pf_step(4);
    }
    pf_step(200);
    // 观察健康检查计数器
    printf("[es-harness] window_cntr = 0x%08x\n", pf_sig_read("u_core.repcnt_event_cnt", 0));
    printf("[es-harness] main_sm_state = 0x%08x\n", pf_sig_read("u_core.main_sm_state_raw", 0));
    printf("[es-harness] SELF-TEST DONE\n");
    return 0;
}
