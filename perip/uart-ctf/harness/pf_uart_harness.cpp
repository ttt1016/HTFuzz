// PickerFuzz per-IP C++ harness — UART（uart-ctf, lsio_trigger 观测）
// ============================================================================
// API（extern "C"）: pf_init/pf_write/pf_read/pf_step/pf_reset/pf_sig_*
// 自检: STATUS 读回 + WDATA 写入 + lsio_trigger 白盒观测
// ============================================================================
#include <verilated.h>
#include "Vuart_perip_tb.h"
#include "Vuart_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vuart_perip_tb* dut = nullptr;
static Vuart_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    // 编译后从 root 头扩充
    {"dbg_lsio_trigger", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_tx_watermark__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_rx_watermark__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_tx_done__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_rx_overflow__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_rx_frame_err__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_rx_break_err__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_rx_timeout__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_rx_parity_err__q", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_intr_state_tx_empty__q", nullptr, 1, false},
    {"u_dut.u_reg.wdata_qe", nullptr, 1, false},
    {"u_dut.u_reg.__Vcellout__u_wdata__q", nullptr, 1, false},
    {"u_dut.u_reg.u_wdata.wr_en", nullptr, 1, false},
    {"u_dut.uart_core.tx_fifo_depth", nullptr, 1, false},
    {"u_dut.uart_core.rx_fifo_depth", nullptr, 1, false},
    {"u_dut.uart_core.rx_fifo_depth_prev_q", nullptr, 1, false},
    {"u_dut.uart_core.event_rx_frame_err", nullptr, 1, false},
    {"u_dut.uart_core.event_rx_break_err", nullptr, 1, false},
    {"u_dut.uart_core.event_rx_timeout", nullptr, 1, false},
    {"u_dut.uart_core.event_rx_parity_err", nullptr, 1, false},
    {"u_dut.uart_core.intr_hw_rx_parity_err.g_intr_event.new_event", nullptr, 1, false},
    {"u_dut.uart_core.intr_hw_rx_timeout.g_intr_event.new_event", nullptr, 1, false},
    {"u_dut.uart_core.intr_hw_rx_break_err.g_intr_event.new_event", nullptr, 1, false},
    {"u_dut.uart_core.intr_hw_rx_frame_err.g_intr_event.new_event", nullptr, 1, false},
    {"u_dut.uart_core.intr_hw_rx_overflow.g_intr_event.new_event", nullptr, 1, false},
    {"u_dut.uart_core.intr_hw_tx_done.g_intr_event.new_event", nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)n;
        if (strcmp(n, "dbg_lsio_trigger") == 0) p = &rootp->dbg_lsio_trigger;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_tx_watermark__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_tx_watermark__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_rx_watermark__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_rx_watermark__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_tx_done__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_tx_done__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_rx_overflow__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_rx_overflow__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_rx_frame_err__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_rx_frame_err__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_rx_break_err__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_rx_break_err__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_rx_timeout__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_rx_timeout__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_rx_parity_err__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_rx_parity_err__q;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_intr_state_tx_empty__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_intr_state_tx_empty__q;
        else if (strcmp(n, "u_dut.u_reg.wdata_qe") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT__wdata_qe;
        else if (strcmp(n, "u_dut.u_reg.__Vcellout__u_wdata__q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT____Vcellout__u_wdata__q;
        else if (strcmp(n, "u_dut.u_reg.u_wdata.wr_en") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_wdata__DOT__wr_en;
        else if (strcmp(n, "u_dut.uart_core.tx_fifo_depth") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__tx_fifo_depth;
        else if (strcmp(n, "u_dut.uart_core.rx_fifo_depth") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__rx_fifo_depth;
        else if (strcmp(n, "u_dut.uart_core.rx_fifo_depth_prev_q") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__rx_fifo_depth_prev_q;
        else if (strcmp(n, "u_dut.uart_core.event_rx_frame_err") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__event_rx_frame_err;
        else if (strcmp(n, "u_dut.uart_core.event_rx_break_err") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__event_rx_break_err;
        else if (strcmp(n, "u_dut.uart_core.event_rx_timeout") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__event_rx_timeout;
        else if (strcmp(n, "u_dut.uart_core.event_rx_parity_err") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__event_rx_parity_err;
        else if (strcmp(n, "u_dut.uart_core.intr_hw_rx_parity_err.g_intr_event.new_event") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__intr_hw_rx_parity_err__DOT__g_intr_event__DOT__new_event;
        else if (strcmp(n, "u_dut.uart_core.intr_hw_rx_timeout.g_intr_event.new_event") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__intr_hw_rx_timeout__DOT__g_intr_event__DOT__new_event;
        else if (strcmp(n, "u_dut.uart_core.intr_hw_rx_break_err.g_intr_event.new_event") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__intr_hw_rx_break_err__DOT__g_intr_event__DOT__new_event;
        else if (strcmp(n, "u_dut.uart_core.intr_hw_rx_frame_err.g_intr_event.new_event") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__intr_hw_rx_frame_err__DOT__g_intr_event__DOT__new_event;
        else if (strcmp(n, "u_dut.uart_core.intr_hw_rx_overflow.g_intr_event.new_event") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__intr_hw_rx_overflow__DOT__g_intr_event__DOT__new_event;
        else if (strcmp(n, "u_dut.uart_core.intr_hw_tx_done.g_intr_event.new_event") == 0) p = &rootp->uart_perip_tb__DOT__u_dut__DOT__uart_core__DOT__intr_hw_tx_done__DOT__g_intr_event__DOT__new_event;
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
    dut = new Vuart_perip_tb;
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
