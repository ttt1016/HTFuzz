// PickerFuzz per-IP C++ harness — sram_ctrl
#include <verilated.h>
#include "Vsram_ctrl_perip_tb.h"
#include "Vsram_ctrl_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vsram_ctrl_perip_tb* dut = nullptr;
static Vsram_ctrl_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    {"u_dut.u_reg.status_q", nullptr, 1, false},
    {"u_dut.init_q", nullptr, 1, false},
    {"u_dut.scr_key_valid_q", nullptr, 1, false},
{"key_ack", nullptr, 1, true },
{"key_q", nullptr, 1, true },
{"key_req", nullptr, 1, true },
{"key_req_pending_q", nullptr, 1, true },
{"key_valid", nullptr, 1, true },
{"u_prim_ram_1p_scr.keystream_repl", nullptr, 1, true },
{"u_prim_ram_1p_scr.wmask_q", nullptr, 1, true },
{"u_prim_count.err_q", nullptr, 1, true },
{"u_prim_count.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_prim_count.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_prim_ram_1p_scr.gen_par_scr__BRA__0__KET__.u_prim_prince.data_state_lo", nullptr, 1, true },
{"u_prim_ram_1p_scr.gen_par_scr__BRA__0__KET__.u_prim_prince.data_state_middle_q", nullptr, 1, true },
{"u_prim_ram_1p_scr.u_prim_ram_1p_adv.addr_q", nullptr, 1, true },
{"u_prim_ram_1p_scr.wdata_q", nullptr, 1, true },
{"u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_ns", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.state_d", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.state_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size.gen_normal_fifo.u_fifo_cnt.rptr_wrap_cnt_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size.gen_normal_fifo.u_fifo_cnt.wptr_wrap_cnt_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size_shadow.gen_normal_fifo.u_fifo_cnt.rptr_wrap_cnt_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size_shadow.gen_normal_fifo.u_fifo_cnt.wptr_wrap_cnt_q", nullptr, 1, true },
{"u_tlul_lc_gate.state_d", nullptr, 1, true },
{"u_tlul_lc_gate.u_state_regs.state_raw", nullptr, 1, true },
{"u_prim_ram_1p_scr.intg_error_buf", nullptr, 1, true },
{"u_prim_ram_1p_scr.intg_error_r_q", nullptr, 1, true },
{"u_prim_ram_1p_scr.intg_error_w_q", nullptr, 1, true },
{"u_reg_regs.err_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.error_det", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.error_internal", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.intg_error", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.intg_error_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.missed_err_gnt_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.readback_error", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.readback_error_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.reqfifo_error", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.rsp_fifo_error", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.sramreqfifo_error", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_reqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_reqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_rspfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_rspfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.enable_intg_check_cmp_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.txn_data_intg_wr", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_intg.gen_singleton_fifo.full_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_intg.gen_singleton_fifo.storage", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sramreqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q", nullptr, 1, true },
{"u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sramreqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q", nullptr, 1, true },
{"u_tlul_lc_gate.err_en", nullptr, 1, true },
{"u_tlul_lc_gate.tl_h2d_error", nullptr, 1, true },
{"u_tlul_lc_gate.u_tlul_err_resp.err_instr_type", nullptr, 1, true },
{"u_tlul_lc_gate.u_tlul_err_resp.err_opcode", nullptr, 1, true },
{"u_tlul_lc_gate.u_tlul_err_resp.err_rsp_pending", nullptr, 1, true },
{"u_tlul_lc_gate.u_tlul_err_resp.err_size", nullptr, 1, true },
{"u_tlul_lc_gate.u_tlul_err_resp.err_source", nullptr, 1, true },
{"u_tlul_lc_gate.u_tlul_err_resp.tl_h_o_int", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "key_ack") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__key_ack;
        else if (strcmp(n, "key_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__key_q;
        else if (strcmp(n, "key_req") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__key_req;
        else if (strcmp(n, "key_req_pending_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__key_req_pending_q;
        else if (strcmp(n, "key_valid") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__key_valid;
        else if (strcmp(n, "u_dut.init_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__init_q;
        else if (strcmp(n, "u_prim_count.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_count__DOT__err_q;
        else if (strcmp(n, "u_prim_count.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_prim_count.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_count__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_prim_ram_1p_scr.gen_par_scr__BRA__0__KET__.u_prim_prince.data_state_lo") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__gen_par_scr__BRA__0__KET____DOT__u_prim_prince__DOT__data_state_lo__BRA__255__03a192__KET__;
        else if (strcmp(n, "u_prim_ram_1p_scr.gen_par_scr__BRA__0__KET__.u_prim_prince.data_state_middle_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__gen_par_scr__BRA__0__KET____DOT__u_prim_prince__DOT__data_state_middle_q;
        else if (strcmp(n, "u_prim_ram_1p_scr.intg_error_buf") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__intg_error_buf;
        else if (strcmp(n, "u_prim_ram_1p_scr.intg_error_r_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__intg_error_r_q;
        else if (strcmp(n, "u_prim_ram_1p_scr.intg_error_w_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__intg_error_w_q;
        else if (strcmp(n, "u_prim_ram_1p_scr.keystream_repl") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__keystream_repl;
        else if (strcmp(n, "u_prim_ram_1p_scr.u_prim_ram_1p_adv.addr_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__u_prim_ram_1p_adv__DOT__addr_q;
        else if (strcmp(n, "u_prim_ram_1p_scr.wdata_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__wdata_q;
        else if (strcmp(n, "u_prim_ram_1p_scr.wmask_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_ram_1p_scr__DOT__wmask_q;
        else if (strcmp(n, "u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_ns") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__src_fsm_ns;
        else if (strcmp(n, "u_reg_regs.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_reg_regs__DOT__err_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.error_det") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__error_det;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.error_internal") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__error_internal;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.intg_error") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__intg_error;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.intg_error_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__intg_error_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.missed_err_gnt_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__missed_err_gnt_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.readback_error") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__readback_error;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.readback_error_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__readback_error_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.reqfifo_error") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__reqfifo_error;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.rsp_fifo_error") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__rsp_fifo_error;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.sramreqfifo_error") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__sramreqfifo_error;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_reqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_reqfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_rptr__DOT__err_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_reqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_reqfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_wptr__DOT__err_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_rspfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_rspfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_rptr__DOT__err_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_rspfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_rspfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_wptr__DOT__err_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.enable_intg_check_cmp_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__enable_intg_check_cmp_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.state_d") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__state_d;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.state_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__state_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.txn_data_intg_wr") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__txn_data_intg_wr;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size.gen_normal_fifo.u_fifo_cnt.rptr_wrap_cnt_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__u_sync_fifo_a_size__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__rptr_wrap_cnt_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size.gen_normal_fifo.u_fifo_cnt.wptr_wrap_cnt_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__u_sync_fifo_a_size__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__wptr_wrap_cnt_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size_shadow.gen_normal_fifo.u_fifo_cnt.rptr_wrap_cnt_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__u_sync_fifo_a_size_shadow__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__rptr_wrap_cnt_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_a_size_shadow.gen_normal_fifo.u_fifo_cnt.wptr_wrap_cnt_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__u_sync_fifo_a_size_shadow__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__wptr_wrap_cnt_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_intg.gen_singleton_fifo.full_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__u_sync_fifo_intg__DOT__gen_singleton_fifo__DOT__full_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sram_byte.gen_integ_handling.u_sync_fifo_intg.gen_singleton_fifo.storage") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sram_byte__DOT__gen_integ_handling__DOT__u_sync_fifo_intg__DOT__gen_singleton_fifo__DOT__storage;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sramreqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sramreqfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_rptr__DOT__err_q;
        else if (strcmp(n, "u_tlul_adapter_sram_racl.tlul_adapter_sram.u_sramreqfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_sram_racl__DOT__tlul_adapter_sram__DOT__u_sramreqfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_wptr__DOT__err_q;
        else if (strcmp(n, "u_tlul_lc_gate.err_en") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__err_en;
        else if (strcmp(n, "u_tlul_lc_gate.state_d") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__state_d;
        else if (strcmp(n, "u_tlul_lc_gate.tl_h2d_error") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__tl_h2d_error;
        else if (strcmp(n, "u_tlul_lc_gate.u_state_regs.state_raw") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_tlul_lc_gate.u_tlul_err_resp.err_instr_type") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_tlul_err_resp__DOT__err_instr_type;
        else if (strcmp(n, "u_tlul_lc_gate.u_tlul_err_resp.err_opcode") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_tlul_err_resp__DOT__err_opcode;
        else if (strcmp(n, "u_tlul_lc_gate.u_tlul_err_resp.err_rsp_pending") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_tlul_err_resp__DOT__err_rsp_pending;
        else if (strcmp(n, "u_tlul_lc_gate.u_tlul_err_resp.err_size") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_tlul_err_resp__DOT__err_size;
        else if (strcmp(n, "u_tlul_lc_gate.u_tlul_err_resp.err_source") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_tlul_err_resp__DOT__err_source;
        else if (strcmp(n, "u_tlul_lc_gate.u_tlul_err_resp.tl_h_o_int") == 0) p = &rootp->sram_ctrl_perip_tb__DOT__u_dut__DOT__u_tlul_lc_gate__DOT__u_tlul_err_resp__DOT__tl_h_o_int;
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
        const char* argv[] = {"pf_sram_ctrl"};
        Verilated::commandArgs(1, (char**)argv);
        args_set = true;
    }
    if (dut) { dut->final(); delete dut; }
    g_snaps.clear();
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vsram_ctrl_perip_tb;
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
