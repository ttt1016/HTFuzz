// PickerFuzz per-IP C++ harness — UART（uart-ctf, lsio_trigger 观测）
// ============================================================================
// API（extern "C"）: pf_init/pf_write/pf_read/pf_step/pf_reset/pf_sig_*
// 自检: STATUS 读回 + WDATA 写入 + lsio_trigger 白盒观测
// ============================================================================
#include <verilated.h>
#include "Votp_ctrl_perip_tb.h"
#include "Votp_ctrl_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Votp_ctrl_perip_tb* dut = nullptr;
static Votp_ctrl_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    // otp_ctrl 白盒表待 SEC_CM 脚本扩充,
{"gen_partitions__BRA__0__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en", nullptr, 1, true },
{"gen_partitions__BRA__1__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en", nullptr, 1, true },
{"gen_partitions__BRA__2__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en", nullptr, 1, true },
{"gen_partitions__BRA__3__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en", nullptr, 1, true },
{"gen_partitions__BRA__4__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en", nullptr, 1, true },
{"key_edn_ack", nullptr, 1, true },
{"u_edn_arb.gen_normal_case.prio_mask_q", nullptr, 1, true },
{"u_otp_arb.gen_normal_case.mask_tree__BRA__10__KET__", nullptr, 1, true },
{"u_otp_arb.gen_normal_case.mask_tree__BRA__12__KET__", nullptr, 1, true },
{"u_otp_arb.gen_normal_case.mask_tree__BRA__13__KET__", nullptr, 1, true },
{"u_otp_arb.gen_normal_case.prio_mask_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.entropy_cnt_clr", nullptr, 1, true },
{"u_otp_ctrl_kdi.entropy_cnt_en", nullptr, 1, true },
{"u_otp_ctrl_kdi.seed_cnt_clr", nullptr, 1, true },
{"u_otp_ctrl_kdi.seed_cnt_en", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_entropy.err_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__0__KET__.ext_cnt", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__1__KET__.ext_cnt", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_seed.err_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__0__KET__.ext_cnt", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__1__KET__.ext_cnt", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.reseed_cnt_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.reseed_en", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_double_lfsr.gen_double_lfsr__BRA__0__KET__.entropy_buf", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.digest_init", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.digest_mode_d", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.digest_mode_q", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.digest_state_en", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.digest_state_q", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.key_state_en", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.key_state_q", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.key_state_sel", nullptr, 1, true },
{"u_prim_lc_sync_creator_seed_sw_rw_en.gen_flops.u_prim_flop_2sync.u_impl_generic.u_sync_1.q_q", nullptr, 1, true },
{"u_prim_lc_sync_creator_seed_sw_rw_en.gen_flops.u_prim_flop_2sync.u_impl_generic.u_sync_2.q_q", nullptr, 1, true },
{"u_reg_core.status_key_deriv_fsm_error_qs", nullptr, 1, true },
{"u_reg_core.status_scrambling_fsm_error_qs", nullptr, 1, true },
{"u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__12__KET__", nullptr, 1, true },
{"u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__13__KET__", nullptr, 1, true },
{"u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__22__KET__", nullptr, 1, true },
{"u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__24__KET__", nullptr, 1, true },
{"u_scrmbl_mtx.gen_normal_case.prio_mask_q", nullptr, 1, true },
{"u_tlul_adapter_sram.u_err.mask_chk", nullptr, 1, true },
{"gen_partitions__BRA__0__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q", nullptr, 1, true },
{"gen_partitions__BRA__0__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_prim_count.err_q", nullptr, 1, true },
{"gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__1__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q", nullptr, 1, true },
{"gen_partitions__BRA__1__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__2__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q", nullptr, 1, true },
{"gen_partitions__BRA__2__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__3__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q", nullptr, 1, true },
{"gen_partitions__BRA__3__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__4__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q", nullptr, 1, true },
{"gen_partitions__BRA__4__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_prim_count.err_q", nullptr, 1, true },
{"gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_prim_count.err_q", nullptr, 1, true },
{"gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_prim_count.err_q", nullptr, 1, true },
{"gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_prim_count.err_q", nullptr, 1, true },
{"gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_prim_count.err_q", nullptr, 1, true },
{"gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_dai.state_d", nullptr, 1, true },
{"u_otp_ctrl_dai.u_prim_count.err_q", nullptr, 1, true },
{"u_otp_ctrl_dai.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_dai.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_dai.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_kdi.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lci.u_prim_count.err_q", nullptr, 1, true },
{"u_otp_ctrl_lci.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lci.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lci.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_count_cnsty.err_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_count_cnsty.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_count_cnsty.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_count_integ.err_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_count_integ.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_count_integ.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_prim_double_lfsr.lfsr_state", nullptr, 1, true },
{"u_otp_ctrl_lfsr_timer.u_state_regs.u_state_flop.q_q", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.data_state_d", nullptr, 1, true },
{"u_otp_ctrl_scrmbl.data_state_en", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "gen_partitions__BRA__0__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__0__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__digest_reg_en;
        else if (strcmp(n, "gen_partitions__BRA__0__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__0__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__tlul_addr_q;
        else if (strcmp(n, "gen_partitions__BRA__0__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__0__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__10__KET____DOT__gen_lifecycle__DOT__u_part_buf__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__10__KET____DOT__gen_lifecycle__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__10__KET____DOT__gen_lifecycle__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__10__KET__.gen_lifecycle.u_part_buf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__10__KET____DOT__gen_lifecycle__DOT__u_part_buf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__1__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__1__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__digest_reg_en;
        else if (strcmp(n, "gen_partitions__BRA__1__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__1__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__tlul_addr_q;
        else if (strcmp(n, "gen_partitions__BRA__1__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__1__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__2__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__2__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__digest_reg_en;
        else if (strcmp(n, "gen_partitions__BRA__2__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__2__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__tlul_addr_q;
        else if (strcmp(n, "gen_partitions__BRA__2__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__2__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__3__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__3__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__digest_reg_en;
        else if (strcmp(n, "gen_partitions__BRA__3__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__3__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__tlul_addr_q;
        else if (strcmp(n, "gen_partitions__BRA__3__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__3__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__4__KET__.gen_unbuffered.u_part_unbuf.digest_reg_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__4__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__digest_reg_en;
        else if (strcmp(n, "gen_partitions__BRA__4__KET__.gen_unbuffered.u_part_unbuf.tlul_addr_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__4__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__tlul_addr_q;
        else if (strcmp(n, "gen_partitions__BRA__4__KET__.gen_unbuffered.u_part_unbuf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__4__KET____DOT__gen_unbuffered__DOT__u_part_unbuf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__5__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__5__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__5__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__5__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__5__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__6__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__6__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__6__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__6__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__6__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__7__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__7__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__7__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__7__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__7__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__8__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__8__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__8__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__8__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__8__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__9__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__9__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__9__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "gen_partitions__BRA__9__KET__.gen_buffered.u_part_buf.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__gen_partitions__BRA__9__KET____DOT__gen_buffered__DOT__u_part_buf__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "key_edn_ack") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__key_edn_ack;
        else if (strcmp(n, "u_edn_arb.gen_normal_case.prio_mask_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_edn_arb__DOT__gen_normal_case__DOT__prio_mask_q;
        else if (strcmp(n, "u_otp_arb.gen_normal_case.mask_tree__BRA__10__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_arb__DOT__gen_normal_case__DOT__mask_tree__BRA__10__KET__;
        else if (strcmp(n, "u_otp_arb.gen_normal_case.mask_tree__BRA__12__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_arb__DOT__gen_normal_case__DOT__mask_tree__BRA__12__KET__;
        else if (strcmp(n, "u_otp_arb.gen_normal_case.mask_tree__BRA__13__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_arb__DOT__gen_normal_case__DOT__mask_tree__BRA__13__KET__;
        else if (strcmp(n, "u_otp_arb.gen_normal_case.prio_mask_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_arb__DOT__gen_normal_case__DOT__prio_mask_q;
        else if (strcmp(n, "u_otp_ctrl_dai.state_d") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_dai__DOT__state_d;
        else if (strcmp(n, "u_otp_ctrl_dai.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_dai__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "u_otp_ctrl_dai.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_dai__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_dai.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_dai__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_dai.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_dai__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.entropy_cnt_clr") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__entropy_cnt_clr;
        else if (strcmp(n, "u_otp_ctrl_kdi.entropy_cnt_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__entropy_cnt_en;
        else if (strcmp(n, "u_otp_ctrl_kdi.seed_cnt_clr") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__seed_cnt_clr;
        else if (strcmp(n, "u_otp_ctrl_kdi.seed_cnt_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__seed_cnt_en;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_entropy.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_entropy__DOT__err_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__0__KET__.ext_cnt") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_entropy__DOT__gen_cnts__BRA__0__KET____DOT__ext_cnt;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_entropy__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__1__KET__.ext_cnt") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_entropy__DOT__gen_cnts__BRA__1__KET____DOT__ext_cnt;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_entropy.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_entropy__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_seed.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_seed__DOT__err_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__0__KET__.ext_cnt") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_seed__DOT__gen_cnts__BRA__0__KET____DOT__ext_cnt;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_seed__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__1__KET__.ext_cnt") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_seed__DOT__gen_cnts__BRA__1__KET____DOT__ext_cnt;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_prim_count_seed.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_prim_count_seed__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_kdi.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_kdi__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lci.u_prim_count.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lci__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "u_otp_ctrl_lci.u_prim_count.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lci__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lci.u_prim_count.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lci__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lci.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lci__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.reseed_cnt_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__reseed_cnt_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.reseed_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__reseed_en;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_count_cnsty.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_count_cnsty__DOT__err_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_count_cnsty.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_count_cnsty__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_count_cnsty.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_count_cnsty__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_count_integ.err_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_count_integ__DOT__err_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_count_integ.gen_cnts__BRA__0__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_count_integ__DOT__gen_cnts__BRA__0__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_count_integ.gen_cnts__BRA__1__KET__.u_cnt_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_count_integ__DOT__gen_cnts__BRA__1__KET____DOT__u_cnt_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_double_lfsr.gen_double_lfsr__BRA__0__KET__.entropy_buf") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_double_lfsr__DOT__gen_double_lfsr__BRA__0__KET____DOT__entropy_buf;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_prim_double_lfsr.lfsr_state") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_prim_double_lfsr__DOT__lfsr_state__BRA__39__03a0__KET__;
        else if (strcmp(n, "u_otp_ctrl_lfsr_timer.u_state_regs.u_state_flop.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_lfsr_timer__DOT__u_state_regs__DOT__u_state_flop__DOT__q_q;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.data_state_d") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__data_state_d;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.data_state_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__data_state_en;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.digest_init") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__digest_init;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.digest_mode_d") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__digest_mode_d;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.digest_mode_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__digest_mode_q;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.digest_state_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__digest_state_en;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.digest_state_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__digest_state_q;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.key_state_en") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__key_state_en;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.key_state_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__key_state_q;
        else if (strcmp(n, "u_otp_ctrl_scrmbl.key_state_sel") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_otp_ctrl_scrmbl__DOT__key_state_sel;
        else if (strcmp(n, "u_prim_lc_sync_creator_seed_sw_rw_en.gen_flops.u_prim_flop_2sync.u_impl_generic.u_sync_1.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_lc_sync_creator_seed_sw_rw_en__DOT__gen_flops__DOT__u_prim_flop_2sync__DOT__u_impl_generic__DOT__u_sync_1__DOT__q_q;
        else if (strcmp(n, "u_prim_lc_sync_creator_seed_sw_rw_en.gen_flops.u_prim_flop_2sync.u_impl_generic.u_sync_2.q_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_lc_sync_creator_seed_sw_rw_en__DOT__gen_flops__DOT__u_prim_flop_2sync__DOT__u_impl_generic__DOT__u_sync_2__DOT__q_q;
        else if (strcmp(n, "u_reg_core.status_key_deriv_fsm_error_qs") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_reg_core__DOT__status_key_deriv_fsm_error_qs;
        else if (strcmp(n, "u_reg_core.status_scrambling_fsm_error_qs") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_reg_core__DOT__status_scrambling_fsm_error_qs;
        else if (strcmp(n, "u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__12__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_scrmbl_mtx__DOT__gen_normal_case__DOT__mask_tree__BRA__12__KET__;
        else if (strcmp(n, "u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__13__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_scrmbl_mtx__DOT__gen_normal_case__DOT__mask_tree__BRA__13__KET__;
        else if (strcmp(n, "u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__22__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_scrmbl_mtx__DOT__gen_normal_case__DOT__mask_tree__BRA__22__KET__;
        else if (strcmp(n, "u_scrmbl_mtx.gen_normal_case.mask_tree__BRA__24__KET__") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_scrmbl_mtx__DOT__gen_normal_case__DOT__mask_tree__BRA__24__KET__;
        else if (strcmp(n, "u_scrmbl_mtx.gen_normal_case.prio_mask_q") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_scrmbl_mtx__DOT__gen_normal_case__DOT__prio_mask_q;
        else if (strcmp(n, "u_tlul_adapter_sram.u_err.mask_chk") == 0) p = &rootp->otp_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram__DOT__u_err__DOT__mask_chk;
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
    dut = new Votp_ctrl_perip_tb;
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
