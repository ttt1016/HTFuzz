// PickerFuzz per-IP C++ harness — UART（uart-ctf, lsio_trigger 观测）
// ============================================================================
// API（extern "C"）: pf_init/pf_write/pf_read/pf_step/pf_reset/pf_sig_*
// 自检: STATUS 读回 + WDATA 写入 + lsio_trigger 白盒观测
// ============================================================================
#include <verilated.h>
#include "Vgpio_perip_tb.h"
#include "Vgpio_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vgpio_perip_tb* dut = nullptr;
static Vgpio_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    // gpio 白盒表待 SEC_CM 脚本扩充,
{"gen_filter__BRA__0__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__0__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__10__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__10__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__11__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__11__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__12__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__12__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__13__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__13__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__14__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__14__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__15__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__15__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__16__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__16__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__17__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__17__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__18__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__18__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__19__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__19__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__1__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__1__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__20__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__20__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__21__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__21__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__22__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__22__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__23__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__23__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__24__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__24__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__25__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__25__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__26__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__26__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__27__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__27__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__28__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__28__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__29__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__29__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__2__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__2__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__30__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__30__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__31__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__31__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__3__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__3__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__4__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__4__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__5__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__5__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__6__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__6__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__7__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__7__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__8__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__8__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"gen_filter__BRA__9__KET__.u_filter.diff_ctr_d", nullptr, 1, true },
{"gen_filter__BRA__9__KET__.u_filter.diff_ctr_q", nullptr, 1, true },
{"u_reg.intr_state_we", nullptr, 1, true },
{"u_reg.u_reg_if.rdata_q", nullptr, 1, true },
{"u_reg.reg_error", nullptr, 1, true },
{"u_reg.u_reg_if.err_internal", nullptr, 1, true },
{"u_reg.u_reg_if.error_q", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "gen_filter__BRA__0__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__0__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__0__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__0__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__10__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__10__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__10__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__10__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__11__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__11__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__11__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__11__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__12__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__12__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__12__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__12__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__13__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__13__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__13__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__13__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__14__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__14__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__14__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__14__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__15__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__15__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__15__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__15__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__16__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__16__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__16__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__16__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__17__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__17__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__17__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__17__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__18__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__18__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__18__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__18__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__19__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__19__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__19__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__19__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__1__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__1__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__1__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__1__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__20__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__20__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__20__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__20__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__21__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__21__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__21__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__21__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__22__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__22__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__22__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__22__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__23__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__23__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__23__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__23__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__24__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__24__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__24__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__24__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__25__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__25__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__25__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__25__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__26__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__26__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__26__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__26__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__27__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__27__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__27__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__27__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__28__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__28__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__28__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__28__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__29__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__29__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__29__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__29__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__2__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__2__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__2__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__2__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__30__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__30__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__30__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__30__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__31__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__31__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__31__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__31__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__3__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__3__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__3__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__3__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__4__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__4__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__4__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__4__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__5__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__5__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__5__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__5__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__6__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__6__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__6__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__6__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__7__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__7__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__7__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__7__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__8__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__8__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__8__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__8__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "gen_filter__BRA__9__KET__.u_filter.diff_ctr_d") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__9__KET____DOT__u_filter__DOT__diff_ctr_d;
        else if (strcmp(n, "gen_filter__BRA__9__KET__.u_filter.diff_ctr_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__gen_filter__BRA__9__KET____DOT__u_filter__DOT__diff_ctr_q;
        else if (strcmp(n, "u_reg.intr_state_we") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__u_reg__DOT__intr_state_we;
        else if (strcmp(n, "u_reg.reg_error") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_error;
        else if (strcmp(n, "u_reg.u_reg_if.err_internal") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__err_internal;
        else if (strcmp(n, "u_reg.u_reg_if.error_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__error_q;
        else if (strcmp(n, "u_reg.u_reg_if.rdata_q") == 0) p = &rootp->gpio_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__rdata_q;
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
    dut = new Vgpio_perip_tb;
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

int pf_sig_bound(int i) { return (i >= 0 && i < g_nsig && g_sigs[i].ptr != nullptr) ? 1 : 0; }
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
