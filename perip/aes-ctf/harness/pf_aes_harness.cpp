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
#define SIGF(n) rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_control__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_control_fsm_i__DOT__##n
#define SIGF2(n) rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_cipher_core__DOT__u_aes_cipher_control__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_cipher_control_fsm_i__DOT__##n

static SigEntry g_sigs[] = {
    {"u_dut.data_in_prev_q", nullptr, 4, true},
    {"u_dut.key_init", nullptr, 16, true},
    {"u_dut.data_out_q", nullptr, 4, true},
    {"u_dut.key_full_q", nullptr, 8, true},
    {"u_dut.key_dec_q", nullptr, 8, true},
    {"u_dut.data_out_we", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_control.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_control_fsm_i.u_aes_control_fsm.u_state_regs.state_raw", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_control.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_control_fsm_i.u_aes_control_fsm.u_state_regs.state_raw", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_control.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_control_fsm_i.u_aes_control_fsm.u_state_regs.state_raw", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.aes_ctr_ns", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.alert_counter_q", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.aes_ctr_ns", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.alert_counter_q", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.u_aes_ctr_fsm.aes_ctr_ns", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.u_aes_ctr_fsm.alert_counter_q", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.alert", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.ctr_we", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.alert", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.ctr_we", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.alert", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.ctr_we", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_ctr.ctr_i_rev", nullptr, 4, true},
    {"u_dut.u_aes_core.u_aes_ctr.ctr_o_rev", nullptr, 4, true},
    {"u_dut.u_aes_core.u_aes_cipher_core.add_rk_sel_raw", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_cipher_core.sp_enc_err_q", nullptr, 1, false},
    {"u_dut.u_aes_core.u_aes_cipher_core.gen_masks.u_aes_prng_masking.prng_key", nullptr, 5, true},
    {"u_dut.u_aes_core.u_aes_cipher_core.gen_masks.u_aes_prng_masking.u_prim_bivium.state_q", nullptr, 6, true},
    {"u_dut.u_aes_core.data_in_prev_q", nullptr, 4, true},
    {"u_dut.u_aes_core.sp_enc_err_q", nullptr, 1, false},
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
        else if (strcmp(n, "u_dut.data_out_we") == 0) g_sigs[i].ptr = &SIGD(u_aes_control__DOT__sp_data_out_we);
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_control.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_control_fsm_i.u_aes_control_fsm.u_state_regs.state_raw") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_control__DOT__gen_fsm__BRA__1__KET____DOT__gen_fsm_p__DOT__u_aes_control_fsm_i__DOT__u_aes_control_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_control.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_control_fsm_i.u_aes_control_fsm.u_state_regs.state_raw") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_control__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_control_fsm_i__DOT__u_aes_control_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_control.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_control_fsm_i.u_aes_control_fsm.u_state_regs.state_raw") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_control__DOT__gen_fsm__BRA__2__KET____DOT__gen_fsm_n__DOT__u_aes_control_fsm_i__DOT__u_aes_control_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.aes_ctr_ns") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__1__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__u_aes_ctr_fsm__DOT__aes_ctr_ns;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.alert_counter_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__1__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__u_aes_ctr_fsm__DOT__alert_counter_q;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.aes_ctr_ns") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__u_aes_ctr_fsm__DOT__aes_ctr_ns;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.u_aes_ctr_fsm.alert_counter_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__u_aes_ctr_fsm__DOT__alert_counter_q;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.u_aes_ctr_fsm.aes_ctr_ns") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__2__KET____DOT__gen_fsm_n__DOT__u_aes_ctr_fsm_i__DOT__u_aes_ctr_fsm__DOT__aes_ctr_ns;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.u_aes_ctr_fsm.alert_counter_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__2__KET____DOT__gen_fsm_n__DOT__u_aes_ctr_fsm_i__DOT__u_aes_ctr_fsm__DOT__alert_counter_q;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.alert") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__1__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__alert;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__1__KET__.gen_fsm_p.u_aes_ctr_fsm_i.ctr_we") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__1__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__ctr_we;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.alert") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__alert;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__0__KET__.gen_fsm_p.u_aes_ctr_fsm_i.ctr_we") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_ctr_fsm_i__DOT__ctr_we;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.alert") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__2__KET____DOT__gen_fsm_n__DOT__u_aes_ctr_fsm_i__DOT__alert;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.gen_fsm__BRA__2__KET__.gen_fsm_n.u_aes_ctr_fsm_i.ctr_we") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__gen_fsm__BRA__2__KET____DOT__gen_fsm_n__DOT__u_aes_ctr_fsm_i__DOT__ctr_we;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.ctr_i_rev") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__ctr_i_rev;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_ctr.ctr_o_rev") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_ctr__DOT__ctr_o_rev;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_cipher_core.add_rk_sel_raw") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_cipher_core__DOT__add_rk_sel_raw;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_cipher_core.sp_enc_err_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_cipher_core__DOT__sp_enc_err_q;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_cipher_core.gen_masks.u_aes_prng_masking.prng_key") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_cipher_core__DOT__gen_masks__DOT__u_aes_prng_masking__DOT__prng_key;
        else if (strcmp(n, "u_dut.u_aes_core.u_aes_cipher_core.gen_masks.u_aes_prng_masking.u_prim_bivium.state_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_cipher_core__DOT__gen_masks__DOT__u_aes_prng_masking__DOT__u_prim_bivium__DOT__state_q;
        else if (strcmp(n, "u_dut.u_aes_core.data_in_prev_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__data_in_prev_q;
        else if (strcmp(n, "u_dut.u_aes_core.sp_enc_err_q") == 0) g_sigs[i].ptr = &rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__sp_enc_err_q;
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
    if (!g_sigs[i].is_wide) {
        // CData（1 字节）信号: 用 uint8 读
        return reinterpret_cast<uint8_t*>(g_sigs[i].ptr)[w];
    }
    return reinterpret_cast<uint32_t*>(g_sigs[i].ptr)[w];
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i=0;i<g_nsig;i++) if (strcmp(g_sigs[i].name,name)==0) return pf_sig_value(i,w);
    return 0;
}
uint64_t pf_get_cycle(void) { return main_time/2; }
void pf_final(void) { if (dut){dut->final(); delete dut; dut=nullptr; rootp=nullptr;} }
// Bug#32 检测: 等 data_out_we 高（组合值），在下一拍复位
int pf_reset_at_we(const char* we_sig) {
    // 轮询: 每半拍检查 data_out_we，为高时立即复位
    for (int i = 0; i < 200000; i++) {
        dut->clk_i = 0; dut->eval();
        uint32_t we = pf_sig_read(we_sig, 0);
        if (we == 3) {  // SP2V_HIGH = 3'b011
            // we 高（当前组合态），拉低复位
            dut->rst_ni = 0;
            dut->clk_i = 1; dut->eval();  // 复位沿
            dut->clk_i = 0; dut->eval();
            dut->rst_ni = 1;
            for (int k = 0; k < 5; k++) ec();
            return 1;
        }
        dut->clk_i = 1; dut->eval();
        main_time += 10;
    }
    return 0;
}

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
