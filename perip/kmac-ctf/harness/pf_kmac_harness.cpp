// PickerFuzz per-IP C++ harness — KMAC (kmac-ctf, Bug#26 静态掩码检测)
// ====================================================================
// 检测思路: EnMasking=1 时 msg_data_masked 应为 msg_data ^ 动态随机掩码。
// Bug#26 注入后掩码是静态全 1（cfg_msg_mask 恒定时）:
//   - 同一消息两次 hash（不同 PRNG 状态）应产生不同中间掩码值
//   - 静态掩码下 msg_data_masked 与 msg_data 的关系恒定（XOR 全 1 或 0）
// 白盒观测: msg_data / msg_data_masked / mux2fifo_mask
#include <verilated.h>
#include "Vkmac_perip_tb.h"
#include "Vkmac_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vkmac_perip_tb* dut = nullptr;
static Vkmac_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };
#define SIGD(n) rootp->kmac_perip_tb__DOT__u_dut__DOT__##n

static SigEntry g_sigs[] = {
    {"u_dut.msg_data",         nullptr, 2, true},   // 64bit MsgWidth
    {"u_dut.msg_data_masked",  nullptr, 4, true},   // [Share][MsgWidth]
    {"u_dut.mux2fifo_mask",    nullptr, 2, true},
    {"u_dut.u_kmac_core.kmac_valid", nullptr, 1, false},
    {"u_dut.msg_valid", nullptr, 1, false},
    {"u_dut.err_processed", nullptr, 1, false},
{"entropy_err", nullptr, 1, true },
{"entropy_in_keyblock", nullptr, 1, true },
{"gen_entropy.entropy_ack", nullptr, 1, true },
{"gen_entropy.entropy_req", nullptr, 1, true },
{"gen_entropy.u_entropy.aux_rand_q", nullptr, 1, true },
{"gen_entropy.u_entropy.aux_update", nullptr, 1, true },
{"gen_entropy.u_entropy.data_update", nullptr, 1, true },
{"gen_entropy.u_entropy.entropy_req_hold_q", nullptr, 1, true },
{"gen_entropy.u_entropy.hash_cnt_clr", nullptr, 1, true },
{"gen_entropy.u_entropy.hash_cnt_en", nullptr, 1, true },
{"gen_entropy.u_entropy.hash_progress_q", nullptr, 1, true },
{"gen_entropy.u_entropy.mode_latch", nullptr, 1, true },
{"gen_entropy.u_entropy.mode_q", nullptr, 1, true },
{"gen_entropy.u_entropy.non_zero_wait_timer_limit", nullptr, 1, true },
{"gen_entropy.u_entropy.prescaler_cnt", nullptr, 1, true },
{"gen_entropy.u_entropy.prng_data", nullptr, 1, true },
{"gen_entropy.u_entropy.prng_en", nullptr, 1, true },
{"gen_entropy.u_entropy.prng_en_rand_q", nullptr, 1, true },
{"gen_entropy.u_entropy.rand_data_q", nullptr, 1, true },
{"gen_entropy.u_entropy.rand_valid_clear", nullptr, 1, true },
{"gen_entropy.u_entropy.rand_valid_set", nullptr, 1, true },
{"gen_entropy.u_entropy.seed", nullptr, 1, true },
{"gen_entropy.u_entropy.seed_ack", nullptr, 1, true },
{"gen_entropy.u_entropy.seed_done", nullptr, 1, true },
{"gen_entropy.u_entropy.seed_req", nullptr, 1, true },
{"gen_entropy.u_entropy.st_d", nullptr, 1, true },
{"gen_entropy.u_entropy.threshold_hit", nullptr, 1, true },
{"gen_entropy.u_entropy.threshold_hit_clr", nullptr, 1, true },
{"gen_entropy.u_entropy.threshold_hit_q", nullptr, 1, true },
{"gen_entropy.u_entropy.timer_enable", nullptr, 1, true },
{"gen_entropy.u_entropy.timer_expired", nullptr, 1, true },
{"gen_entropy.u_entropy.timer_update", nullptr, 1, true },
{"gen_entropy.u_entropy.timer_value", nullptr, 1, true },
{"gen_entropy.u_entropy.u_hash_count.err_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__0__KET__.ext_cnt", nullptr, 1, true },
{"gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__1__KET__.ext_cnt", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.__VlemCall_0__bivium_generate_key_stream", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.seed_req_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.state_idx_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.state_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.state_seed", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.state_update", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.update", nullptr, 1, true },
{"gen_entropy.u_entropy.u_prim_trivium.wr_en_seed", nullptr, 1, true },
{"gen_entropy.u_entropy.u_state_regs.state_raw", nullptr, 1, true },
{"gen_entropy.u_entropy.wait_timer_prescaler_d", nullptr, 1, true },
{"gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.ack_sync.intq", nullptr, 1, true },
{"gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_ack_q", nullptr, 1, true },
{"gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_ack", nullptr, 1, true },
{"gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_ns", nullptr, 1, true },
{"key_data", nullptr, 1, true },
{"key_len", nullptr, 1, true },
{"msg_data_masked", nullptr, 1, true },
{"msg_mask_en", nullptr, 1, true },
{"mux2fifo_mask", nullptr, 1, true },
{"sha3_rand_valid", nullptr, 1, true },
{"sw_key_data_reg", nullptr, 1, true },
{"u_app_intf.keymgr_key", nullptr, 1, true },
{"u_errchk.cfg_entropy_ready", nullptr, 1, true },
{"u_kmac_core.clr_keyidx", nullptr, 1, true },
{"u_kmac_core.en_key_write", nullptr, 1, true },
{"u_kmac_core.inc_keyidx", nullptr, 1, true },
{"u_kmac_core.key_sliced", nullptr, 1, true },
{"u_kmac_core.u_key_index_count.err_q", nullptr, 1, true },
{"u_kmac_core.u_key_index_count.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_kmac_core.u_key_index_count.gen_cnts__BRA__0__KET__.ext_cnt", nullptr, 1, true },
{"u_kmac_core.u_key_index_count.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_kmac_core.u_key_index_count.gen_cnts__BRA__1__KET__.ext_cnt", nullptr, 1, true },
{"u_msgfifo.u_msgfifo.__Vxrand___0", nullptr, 1, true },
{"u_msgfifo.u_packer.stored_mask", nullptr, 1, true },
{"u_msgfifo.u_packer.stored_mask_next", nullptr, 1, true },
{"u_reg.cfg_shadowed_entropy_fast_process_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_entropy_fast_process_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_entropy_mode_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_entropy_mode_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_entropy_ready_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_entropy_ready_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_msg_mask_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_msg_mask_update_err", nullptr, 1, true },
{"u_reg.entropy_period_gated_we", nullptr, 1, true },
{"u_reg.entropy_refresh_threshold_shadowed_gated_we", nullptr, 1, true },
{"u_reg.entropy_refresh_threshold_shadowed_re", nullptr, 1, true },
{"u_reg.entropy_refresh_threshold_shadowed_storage_err", nullptr, 1, true },
{"u_reg.entropy_refresh_threshold_shadowed_update_err", nullptr, 1, true },
{"u_reg.key_len_gated_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_fast_process.committed_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_fast_process.committed_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_fast_process.shadow_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_fast_process.shadow_wd", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_fast_process.shadow_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_mode.committed_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_mode.committed_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_mode.shadow_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_mode.shadow_wd", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_mode.shadow_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_ready.committed_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_ready.committed_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_ready.shadow_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_ready.shadow_wd", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_entropy_ready.shadow_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_msg_mask.committed_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_msg_mask.committed_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_msg_mask.shadow_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_msg_mask.shadow_wd", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_msg_mask.shadow_we", nullptr, 1, true },
{"u_reg.u_entropy_refresh_hash_cnt.q", nullptr, 1, true },
{"u_reg.u_entropy_refresh_threshold_shadowed.committed_q", nullptr, 1, true },
{"u_reg.u_entropy_refresh_threshold_shadowed.committed_we", nullptr, 1, true },
{"u_reg.u_entropy_refresh_threshold_shadowed.shadow_q", nullptr, 1, true },
{"u_reg.u_entropy_refresh_threshold_shadowed.shadow_wd", nullptr, 1, true },
{"u_reg.u_entropy_refresh_threshold_shadowed.shadow_we", nullptr, 1, true },
{"u_sha3.u_keccak.dom_in_rand_ext_d", nullptr, 1, true },
{"u_sha3.u_keccak.dom_in_rand_ext_q", nullptr, 1, true },
{"u_sha3.u_keccak.keccak_rand_consumed", nullptr, 1, true },
{"u_sha3.u_keccak.u_keccak_p.__Vxrand___19", nullptr, 1, true },
{"u_sha3.u_keccak.u_keccak_p.__Vxrand___25", nullptr, 1, true },
{"u_sha3.u_keccak.u_keccak_p.__Vxrand___5", nullptr, 1, true },
{"u_sha3.u_keccak.u_keccak_p.__Vxrand___6", nullptr, 1, true },
{"kmac_app_state_error", nullptr, 1, true },
{"kmac_core_state_error", nullptr, 1, true },
{"kmac_state_error", nullptr, 1, true },
{"reg_state", nullptr, 1, true },
{"reg_state_tl", nullptr, 1, true },
{"sha3_fsm", nullptr, 1, true },
{"u_app_intf.fsm_err", nullptr, 1, true },
{"u_app_intf.u_state_regs.state_raw", nullptr, 1, true },
{"u_errchk.u_state_regs.state_raw", nullptr, 1, true },
{"u_kmac_core.u_state_regs.state_raw", nullptr, 1, true },
{"u_reg.cfg_shadowed_state_endianness_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_state_endianness_update_err", nullptr, 1, true },
{"u_reg.intr_state_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_state_endianness.committed_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_state_endianness.committed_we", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_state_endianness.shadow_q", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_state_endianness.shadow_wd", nullptr, 1, true },
{"u_reg.u_cfg_shadowed_state_endianness.shadow_we", nullptr, 1, true },
{"u_reg.u_reg_if.rdata_q", nullptr, 1, true },
{"u_sha3.keccak_round_state_error", nullptr, 1, true },
{"u_sha3.sha3_state_error", nullptr, 1, true },
{"u_sha3.sha3pad_state_error", nullptr, 1, true },
{"u_sha3.state_guarded", nullptr, 1, true },
{"u_sha3.state_valid", nullptr, 1, true },
{"u_sha3.u_keccak.u_keccak_p.state_in", nullptr, 1, true },
{"u_sha3.u_keccak.u_keccak_p.state_out", nullptr, 1, true },
{"u_sha3.u_keccak.u_round_count.err_q", nullptr, 1, true },
{"u_sha3.u_keccak.u_round_count.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_sha3.u_keccak.u_round_count.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_sha3.u_keccak.u_state_regs.state_raw", nullptr, 1, true },
{"u_sha3.u_pad.fsm_keccak_valid", nullptr, 1, true },
{"u_sha3.u_pad.u_sentmsg_count.err_q", nullptr, 1, true },
{"u_sha3.u_pad.u_sentmsg_count.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_sha3.u_pad.u_sentmsg_count.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"u_sha3.u_pad.u_state_regs.state_raw", nullptr, 1, true },
{"u_sha3.u_state_regs.state_raw", nullptr, 1, true },
{"u_state_regs.state_raw", nullptr, 1, true },
{"u_staterd.muxed_state", nullptr, 1, true },
{"u_staterd.tlram_addr", nullptr, 1, true },
{"u_staterd.tlram_gnt", nullptr, 1, true },
{"u_staterd.tlram_rdata", nullptr, 1, true },
{"u_staterd.tlram_req", nullptr, 1, true },
{"u_staterd.tlram_rvalid", nullptr, 1, true },
{"u_staterd.tlram_we", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.d_error", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.d_valid", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.error_det", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.missed_err_gnt_q", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.reqfifo_rdata", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.reqfifo_rready", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.reqfifo_wvalid", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.rspfifo_rdata", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.rspfifo_rvalid", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.rspfifo_wdata", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.sram_req_rdata", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.sramreqfifo_rready", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.u_reqfifo.gen_singleton_fifo.full_q", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.u_reqfifo.gen_singleton_fifo.storage", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.u_rspfifo.gen_singleton_fifo.full_q", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.u_rspfifo.gen_singleton_fifo.storage", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.u_sramreqfifo.gen_singleton_fifo.full_q", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.u_sramreqfifo.gen_singleton_fifo.storage", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.vld_rd_rsp", nullptr, 1, true },
{"alert_fatal", nullptr, 1, true },
{"alert_recov_operation", nullptr, 1, true },
{"alerts_q__BRA__1__KET__", nullptr, 1, true },
{"app_err", nullptr, 1, true },
{"err_processed", nullptr, 1, true },
{"event_error", nullptr, 1, true },
{"intr_kmac_err.g_intr_event.new_event", nullptr, 1, true },
{"lc_escalate_en", nullptr, 1, true },
{"sha3_err", nullptr, 1, true },
{"status_alert_fatal_fault", nullptr, 1, true },
{"status_alert_recov_ctrl_update_err", nullptr, 1, true },
{"u_app_intf.err_during_sw_q", nullptr, 1, true },
{"u_app_intf.mux_err", nullptr, 1, true },
{"u_app_intf.service_rejected_error", nullptr, 1, true },
{"u_errchk.block_swcmd", nullptr, 1, true },
{"u_errchk.err", nullptr, 1, true },
{"u_errchk.st_d", nullptr, 1, true },
{"u_kmac_core.st_err_ct", nullptr, 1, true },
{"u_kmac_core.st_err_ct_d", nullptr, 1, true },
{"u_msgfifo.error", nullptr, 1, true },
{"u_msgfifo.u_msgfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q", nullptr, 1, true },
{"u_msgfifo.u_msgfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q", nullptr, 1, true },
{"u_msgfifo.u_packer.g_pos_dupcnt.u_pos.err_q", nullptr, 1, true },
{"u_reg.cfg_shadowed_en_unsupported_modestrength_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_en_unsupported_modestrength_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_kmac_en_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_kmac_en_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_kstrength_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_kstrength_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_mode_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_mode_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_msg_endianness_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_msg_endianness_update_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_sideload_storage_err", nullptr, 1, true },
{"u_reg.cfg_shadowed_sideload_update_err", nullptr, 1, true },
{"u_reg.err_q", nullptr, 1, true },
{"u_reg.intg_err", nullptr, 1, true },
{"u_reg.reg_error", nullptr, 1, true },
{"u_reg.reg_we_err", nullptr, 1, true },
{"u_reg.u_err_code.q", nullptr, 1, true },
{"u_reg.u_reg_if.err_internal", nullptr, 1, true },
{"u_reg.u_reg_if.error_q", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.err_instr_type", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.err_opcode", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.err_rsp_pending", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.err_size", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.err_source", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.tl_h_o_int", nullptr, 1, true },
{"u_reg.u_socket.gen_err_resp.err_resp.u_intg_gen.gen_rsp_intg.rsp", nullptr, 1, true },
{"u_tlul_adapter_msgfifo.error_det", nullptr, 1, true },
{"u_tlul_adapter_msgfifo.missed_err_gnt_q", nullptr, 1, true },
{"gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__0__KET__.incr_en", nullptr, 1, true },
{"u_kmac_core.u_key_index_count.gen_cnts__BRA__0__KET__.incr_en", nullptr, 1, true },
{"u_reg.u_entropy_refresh_threshold_shadowed.phase_clear", nullptr, 1, true },
{"u_staterd.u_tlul_adapter.sramreqfifo_wvalid", nullptr, 1, true },
{"gen_alert_tx__BRA__0__KET__.u_prim_alert_sender.alert_req", nullptr, 1, true },
{"gen_alert_tx__BRA__1__KET__.u_prim_alert_sender.alert_req", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs)/sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "alerts_q__BRA__1__KET__") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__alerts_q__BRA__1__KET__;
        else if (strcmp(n, "app_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__app_err;
        else if (strcmp(n, "entropy_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__entropy_err;
        else if (strcmp(n, "entropy_in_keyblock") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__entropy_in_keyblock;
        else if (strcmp(n, "err_processed") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__err_processed;
        else if (strcmp(n, "gen_alert_tx__BRA__0__KET__.u_prim_alert_sender.alert_req") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_alert_tx__BRA__0__KET____DOT__u_prim_alert_sender__DOT__alert_req;
        else if (strcmp(n, "gen_alert_tx__BRA__1__KET__.u_prim_alert_sender.alert_req") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_alert_tx__BRA__1__KET____DOT__u_prim_alert_sender__DOT__alert_req;
        else if (strcmp(n, "gen_entropy.entropy_ack") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__entropy_ack;
        else if (strcmp(n, "gen_entropy.entropy_req") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__entropy_req;
        else if (strcmp(n, "gen_entropy.u_entropy.aux_rand_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__aux_rand_q;
        else if (strcmp(n, "gen_entropy.u_entropy.aux_update") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__aux_update;
        else if (strcmp(n, "gen_entropy.u_entropy.data_update") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__data_update;
        else if (strcmp(n, "gen_entropy.u_entropy.entropy_req_hold_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__entropy_req_hold_q;
        else if (strcmp(n, "gen_entropy.u_entropy.hash_cnt_clr") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__hash_cnt_clr;
        else if (strcmp(n, "gen_entropy.u_entropy.hash_progress_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__hash_progress_q;
        else if (strcmp(n, "gen_entropy.u_entropy.mode_latch") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__mode_latch;
        else if (strcmp(n, "gen_entropy.u_entropy.mode_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__mode_q;
        else if (strcmp(n, "gen_entropy.u_entropy.non_zero_wait_timer_limit") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__non_zero_wait_timer_limit;
        else if (strcmp(n, "gen_entropy.u_entropy.prescaler_cnt") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__prescaler_cnt;
        else if (strcmp(n, "gen_entropy.u_entropy.prng_data") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__prng_data;
        else if (strcmp(n, "gen_entropy.u_entropy.prng_en") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__prng_en;
        else if (strcmp(n, "gen_entropy.u_entropy.prng_en_rand_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__prng_en_rand_q;
        else if (strcmp(n, "gen_entropy.u_entropy.rand_data_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__rand_data_q;
        else if (strcmp(n, "gen_entropy.u_entropy.rand_valid_clear") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__rand_valid_clear;
        else if (strcmp(n, "gen_entropy.u_entropy.rand_valid_set") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__rand_valid_set;
        else if (strcmp(n, "gen_entropy.u_entropy.seed") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__seed;
        else if (strcmp(n, "gen_entropy.u_entropy.seed_ack") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__seed_ack;
        else if (strcmp(n, "gen_entropy.u_entropy.seed_done") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__seed_done;
        else if (strcmp(n, "gen_entropy.u_entropy.seed_req") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__seed_req;
        else if (strcmp(n, "gen_entropy.u_entropy.st_d") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__st_d;
        else if (strcmp(n, "gen_entropy.u_entropy.threshold_hit") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__threshold_hit;
        else if (strcmp(n, "gen_entropy.u_entropy.threshold_hit_clr") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__threshold_hit_clr;
        else if (strcmp(n, "gen_entropy.u_entropy.threshold_hit_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__threshold_hit_q;
        else if (strcmp(n, "gen_entropy.u_entropy.timer_enable") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__timer_enable;
        else if (strcmp(n, "gen_entropy.u_entropy.timer_expired") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__timer_expired;
        else if (strcmp(n, "gen_entropy.u_entropy.timer_update") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__timer_update;
        else if (strcmp(n, "gen_entropy.u_entropy.timer_value") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__timer_value;
        else if (strcmp(n, "gen_entropy.u_entropy.u_hash_count.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_hash_count__DOT__err_q;
        else if (strcmp(n, "gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_hash_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__0__KET__.ext_cnt") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_hash_count__DOT__gen_cnts__BRA__0__KET____DOT__ext_cnt;
        else if (strcmp(n, "gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__0__KET__.incr_en") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_hash_count__DOT__gen_cnts__BRA__0__KET____DOT__incr_en;
        else if (strcmp(n, "gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_hash_count__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "gen_entropy.u_entropy.u_hash_count.gen_cnts__BRA__1__KET__.ext_cnt") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_hash_count__DOT__gen_cnts__BRA__1__KET____DOT__ext_cnt;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.__VlemCall_0__bivium_generate_key_stream") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT____VlemCall_0__bivium_generate_key_stream;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.seed_req_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__seed_req_q;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.state_idx_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__state_idx_q;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.state_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__state_q;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.state_seed") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__state_seed;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.state_update") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__state_update;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.update") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__update;
        else if (strcmp(n, "gen_entropy.u_entropy.u_prim_trivium.wr_en_seed") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_prim_trivium__DOT__wr_en_seed;
        else if (strcmp(n, "gen_entropy.u_entropy.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "gen_entropy.u_entropy.wait_timer_prescaler_d") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_entropy__DOT__wait_timer_prescaler_d;
        else if (strcmp(n, "gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.ack_sync.intq") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__ack_sync__DOT__intq;
        else if (strcmp(n, "gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_ack_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__dst_ack_q;
        else if (strcmp(n, "gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_ack") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__src_ack;
        else if (strcmp(n, "gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "gen_entropy.u_prim_sync_reqack_data.u_prim_sync_reqack.gen_nrz_hs_protocol.src_fsm_ns") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__gen_entropy__DOT__u_prim_sync_reqack_data__DOT__u_prim_sync_reqack__DOT__gen_nrz_hs_protocol__DOT__src_fsm_ns;
        else if (strcmp(n, "intr_kmac_err.g_intr_event.new_event") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__intr_kmac_err__DOT__g_intr_event__DOT__new_event;
        else if (strcmp(n, "key_data") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__key_data;
        else if (strcmp(n, "key_len") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__key_len;
        else if (strcmp(n, "kmac_app_state_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__kmac_app_state_error;
        else if (strcmp(n, "kmac_core_state_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__kmac_core_state_error;
        else if (strcmp(n, "kmac_state_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__kmac_state_error;
        else if (strcmp(n, "msg_data_masked") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__msg_data_masked;
        else if (strcmp(n, "msg_mask_en") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__msg_mask_en;
        else if (strcmp(n, "mux2fifo_mask") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__mux2fifo_mask;
        else if (strcmp(n, "reg_state") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__reg_state;
        else if (strcmp(n, "reg_state_tl") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__reg_state_tl;
        else if (strcmp(n, "sha3_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__sha3_err;
        else if (strcmp(n, "sha3_fsm") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__sha3_fsm;
        else if (strcmp(n, "sha3_rand_valid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__sha3_rand_valid;
        else if (strcmp(n, "status_alert_fatal_fault") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__status_alert_fatal_fault;
        else if (strcmp(n, "status_alert_recov_ctrl_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__status_alert_recov_ctrl_update_err;
        else if (strcmp(n, "sw_key_data_reg") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__sw_key_data_reg;
        else if (strcmp(n, "u_app_intf.err_during_sw_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_app_intf__DOT__err_during_sw_q;
        else if (strcmp(n, "u_app_intf.fsm_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_app_intf__DOT__fsm_err;
        else if (strcmp(n, "u_app_intf.keymgr_key") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_app_intf__DOT__keymgr_key;
        else if (strcmp(n, "u_app_intf.mux_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_app_intf__DOT__mux_err;
        else if (strcmp(n, "u_app_intf.service_rejected_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_app_intf__DOT__service_rejected_error;
        else if (strcmp(n, "u_app_intf.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_app_intf__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.err_processed") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__err_processed;
        else if (strcmp(n, "u_dut.msg_data") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__msg_data;
        else if (strcmp(n, "u_dut.msg_data_masked") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__msg_data_masked;
        else if (strcmp(n, "u_dut.msg_valid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__msg_valid;
        else if (strcmp(n, "u_dut.mux2fifo_mask") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__mux2fifo_mask;
        else if (strcmp(n, "u_dut.u_kmac_core.kmac_valid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__kmac_valid;
        else if (strcmp(n, "u_errchk.block_swcmd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_errchk__DOT__block_swcmd;
        else if (strcmp(n, "u_errchk.cfg_entropy_ready") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_errchk__DOT__cfg_entropy_ready;
        else if (strcmp(n, "u_errchk.err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_errchk__DOT__err;
        else if (strcmp(n, "u_errchk.st_d") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_errchk__DOT__st_d;
        else if (strcmp(n, "u_errchk.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_errchk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_kmac_core.clr_keyidx") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__clr_keyidx;
        else if (strcmp(n, "u_kmac_core.en_key_write") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__en_key_write;
        else if (strcmp(n, "u_kmac_core.key_sliced") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__key_sliced;
        else if (strcmp(n, "u_kmac_core.st_err_ct") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__st_err_ct;
        else if (strcmp(n, "u_kmac_core.st_err_ct_d") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__st_err_ct_d;
        else if (strcmp(n, "u_kmac_core.u_key_index_count.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_key_index_count__DOT__err_q;
        else if (strcmp(n, "u_kmac_core.u_key_index_count.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_key_index_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_kmac_core.u_key_index_count.gen_cnts__BRA__0__KET__.ext_cnt") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_key_index_count__DOT__gen_cnts__BRA__0__KET____DOT__ext_cnt;
        else if (strcmp(n, "u_kmac_core.u_key_index_count.gen_cnts__BRA__0__KET__.incr_en") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_key_index_count__DOT__gen_cnts__BRA__0__KET____DOT__incr_en;
        else if (strcmp(n, "u_kmac_core.u_key_index_count.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_key_index_count__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_kmac_core.u_key_index_count.gen_cnts__BRA__1__KET__.ext_cnt") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_key_index_count__DOT__gen_cnts__BRA__1__KET____DOT__ext_cnt;
        else if (strcmp(n, "u_kmac_core.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_kmac_core__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_msgfifo.error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_msgfifo__DOT__error;
        else if (strcmp(n, "u_msgfifo.u_msgfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_msgfifo__DOT__u_msgfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_rptr__DOT__err_q;
        else if (strcmp(n, "u_msgfifo.u_msgfifo.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_msgfifo__DOT__u_msgfifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__gen_secure_ptrs__DOT__u_wptr__DOT__err_q;
        else if (strcmp(n, "u_msgfifo.u_packer.g_pos_dupcnt.u_pos.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_msgfifo__DOT__u_packer__DOT__g_pos_dupcnt__DOT__u_pos__DOT__err_q;
        else if (strcmp(n, "u_msgfifo.u_packer.stored_mask") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_msgfifo__DOT__u_packer__DOT__stored_mask;
        else if (strcmp(n, "u_msgfifo.u_packer.stored_mask_next") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_msgfifo__DOT__u_packer__DOT__stored_mask_next;
        else if (strcmp(n, "u_reg.cfg_shadowed_en_unsupported_modestrength_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_en_unsupported_modestrength_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_en_unsupported_modestrength_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_en_unsupported_modestrength_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_entropy_fast_process_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_entropy_fast_process_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_entropy_fast_process_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_entropy_fast_process_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_entropy_mode_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_entropy_mode_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_entropy_mode_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_entropy_mode_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_entropy_ready_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_entropy_ready_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_entropy_ready_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_entropy_ready_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_kmac_en_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_kmac_en_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_kmac_en_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_kmac_en_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_kstrength_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_kstrength_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_kstrength_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_kstrength_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_mode_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_mode_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_mode_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_mode_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_msg_endianness_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_msg_endianness_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_msg_endianness_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_msg_endianness_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_msg_mask_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_msg_mask_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_msg_mask_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_msg_mask_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_sideload_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_sideload_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_sideload_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_sideload_update_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_state_endianness_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_state_endianness_storage_err;
        else if (strcmp(n, "u_reg.cfg_shadowed_state_endianness_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__cfg_shadowed_state_endianness_update_err;
        else if (strcmp(n, "u_reg.entropy_refresh_threshold_shadowed_storage_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__entropy_refresh_threshold_shadowed_storage_err;
        else if (strcmp(n, "u_reg.entropy_refresh_threshold_shadowed_update_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__entropy_refresh_threshold_shadowed_update_err;
        else if (strcmp(n, "u_reg.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__err_q;
        else if (strcmp(n, "u_reg.intg_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__intg_err;
        else if (strcmp(n, "u_reg.reg_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_error;
        else if (strcmp(n, "u_reg.reg_we_err") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_we_err;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_fast_process.committed_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_fast_process__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_fast_process.committed_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_fast_process__DOT__committed_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_fast_process.shadow_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_fast_process__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_fast_process.shadow_wd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_fast_process__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_fast_process.shadow_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_fast_process__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_mode.committed_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_mode__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_mode.committed_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_mode__DOT__committed_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_mode.shadow_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_mode__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_mode.shadow_wd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_mode__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_mode.shadow_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_mode__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_ready.committed_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_ready__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_ready.committed_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_ready__DOT__committed_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_ready.shadow_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_ready__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_ready.shadow_wd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_ready__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_entropy_ready.shadow_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_entropy_ready__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_msg_mask.committed_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_msg_mask__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_msg_mask.committed_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_msg_mask__DOT__committed_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_msg_mask.shadow_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_msg_mask__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_msg_mask.shadow_wd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_msg_mask__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_msg_mask.shadow_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_msg_mask__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_state_endianness.committed_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_state_endianness__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_state_endianness.committed_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_state_endianness__DOT__committed_we;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_state_endianness.shadow_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_state_endianness__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_state_endianness.shadow_wd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_state_endianness__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_cfg_shadowed_state_endianness.shadow_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_cfg_shadowed_state_endianness__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_entropy_refresh_hash_cnt.q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_hash_cnt__DOT__q;
        else if (strcmp(n, "u_reg.u_entropy_refresh_threshold_shadowed.committed_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_threshold_shadowed__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_entropy_refresh_threshold_shadowed.committed_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_threshold_shadowed__DOT__committed_we;
        else if (strcmp(n, "u_reg.u_entropy_refresh_threshold_shadowed.phase_clear") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_threshold_shadowed__DOT__phase_clear;
        else if (strcmp(n, "u_reg.u_entropy_refresh_threshold_shadowed.shadow_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_threshold_shadowed__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_entropy_refresh_threshold_shadowed.shadow_wd") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_threshold_shadowed__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_entropy_refresh_threshold_shadowed.shadow_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_entropy_refresh_threshold_shadowed__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_err_code.q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_err_code__DOT__q;
        else if (strcmp(n, "u_reg.u_reg_if.err_internal") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__err_internal;
        else if (strcmp(n, "u_reg.u_reg_if.error_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__error_q;
        else if (strcmp(n, "u_reg.u_reg_if.rdata_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__rdata_q;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.err_instr_type") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__err_instr_type;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.err_opcode") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__err_opcode;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.err_rsp_pending") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__err_rsp_pending;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.err_size") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__err_size;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.err_source") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__err_source;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.tl_h_o_int") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__tl_h_o_int;
        else if (strcmp(n, "u_reg.u_socket.gen_err_resp.err_resp.u_intg_gen.gen_rsp_intg.rsp") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_socket__DOT__gen_err_resp__DOT__err_resp__DOT__u_intg_gen__DOT__gen_rsp_intg__DOT__rsp;
        else if (strcmp(n, "u_sha3.keccak_round_state_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__keccak_round_state_error;
        else if (strcmp(n, "u_sha3.sha3_state_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__sha3_state_error;
        else if (strcmp(n, "u_sha3.sha3pad_state_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__sha3pad_state_error;
        else if (strcmp(n, "u_sha3.state_guarded") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__state_guarded;
        else if (strcmp(n, "u_sha3.state_valid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__state_valid;
        else if (strcmp(n, "u_sha3.u_keccak.dom_in_rand_ext_d") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__dom_in_rand_ext_d;
        else if (strcmp(n, "u_sha3.u_keccak.dom_in_rand_ext_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__dom_in_rand_ext_q;
        else if (strcmp(n, "u_sha3.u_keccak.keccak_rand_consumed") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__keccak_rand_consumed;
        else if (strcmp(n, "u_sha3.u_keccak.u_keccak_p.state_in") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__u_keccak_p__DOT__state_in;
        else if (strcmp(n, "u_sha3.u_keccak.u_keccak_p.state_out") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__u_keccak_p__DOT__state_out;
        else if (strcmp(n, "u_sha3.u_keccak.u_round_count.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__u_round_count__DOT__err_q;
        else if (strcmp(n, "u_sha3.u_keccak.u_round_count.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__u_round_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_sha3.u_keccak.u_round_count.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__u_round_count__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_sha3.u_keccak.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_keccak__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_sha3.u_pad.fsm_keccak_valid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_pad__DOT__fsm_keccak_valid;
        else if (strcmp(n, "u_sha3.u_pad.u_sentmsg_count.err_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_pad__DOT__u_sentmsg_count__DOT__err_q;
        else if (strcmp(n, "u_sha3.u_pad.u_sentmsg_count.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_pad__DOT__u_sentmsg_count__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_sha3.u_pad.u_sentmsg_count.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_pad__DOT__u_sentmsg_count__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "u_sha3.u_pad.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_pad__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_sha3.u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_sha3__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_state_regs.state_raw") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_staterd.muxed_state") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__muxed_state;
        else if (strcmp(n, "u_staterd.tlram_addr") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__tlram_addr;
        else if (strcmp(n, "u_staterd.tlram_rdata") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__tlram_rdata;
        else if (strcmp(n, "u_staterd.tlram_req") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__tlram_req;
        else if (strcmp(n, "u_staterd.tlram_rvalid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__tlram_rvalid;
        else if (strcmp(n, "u_staterd.tlram_we") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__tlram_we;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.d_error") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__d_error;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.d_valid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__d_valid;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.error_det") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__error_det;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.missed_err_gnt_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__missed_err_gnt_q;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.reqfifo_rdata") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__reqfifo_rdata;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.reqfifo_rready") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__reqfifo_rready;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.reqfifo_wvalid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__reqfifo_wvalid;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.rspfifo_rdata") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__rspfifo_rdata;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.rspfifo_rvalid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__rspfifo_rvalid;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.rspfifo_wdata") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__rspfifo_wdata;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.sram_req_rdata") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__sram_req_rdata;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.sramreqfifo_rready") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__sramreqfifo_rready;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.sramreqfifo_wvalid") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__sramreqfifo_wvalid;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.u_reqfifo.gen_singleton_fifo.full_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__u_reqfifo__DOT__gen_singleton_fifo__DOT__full_q;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.u_reqfifo.gen_singleton_fifo.storage") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__u_reqfifo__DOT__gen_singleton_fifo__DOT__storage;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.u_rspfifo.gen_singleton_fifo.full_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__u_rspfifo__DOT__gen_singleton_fifo__DOT__full_q;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.u_rspfifo.gen_singleton_fifo.storage") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__u_rspfifo__DOT__gen_singleton_fifo__DOT__storage;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.u_sramreqfifo.gen_singleton_fifo.full_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__u_sramreqfifo__DOT__gen_singleton_fifo__DOT__full_q;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.u_sramreqfifo.gen_singleton_fifo.storage") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__u_sramreqfifo__DOT__gen_singleton_fifo__DOT__storage;
        else if (strcmp(n, "u_staterd.u_tlul_adapter.vld_rd_rsp") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_staterd__DOT__u_tlul_adapter__DOT__vld_rd_rsp;
        else if (strcmp(n, "u_tlul_adapter_msgfifo.error_det") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_msgfifo__DOT__error_det;
        else if (strcmp(n, "u_tlul_adapter_msgfifo.missed_err_gnt_q") == 0) p = &rootp->kmac_perip_tb__DOT__u_dut__DOT__u_tlul_adapter_msgfifo__DOT__missed_err_gnt_q;
        g_sigs[i].ptr = p;
    }
}

static void ec() { dut->clk_i=0; dut->eval(); dut->clk_i=1; dut->eval(); main_time+=10; }

extern "C" {
int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vkmac_perip_tb;
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
int pf_sig_bound(int i) { return (i >= 0 && i < g_nsig && g_sigs[i].ptr != nullptr) ? 1 : 0; }
int pf_sig_count(void) { return g_nsig; }
const char* pf_sig_name(int i) { return g_sigs[i].name; }
int pf_sig_words(int i) { return g_sigs[i].words; }
uint32_t pf_sig_value(int i, int w) {
    if (!g_sigs[i].ptr || w >= g_sigs[i].words) return 0;
    return reinterpret_cast<uint32_t*>(g_sigs[i].ptr)[w];
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i = 0; i < g_nsig; i++)
        if (strcmp(g_sigs[i].name, name) == 0) {
            if (!g_sigs[i].ptr || w >= g_sigs[i].words) return 0;
            return reinterpret_cast<uint32_t*>(g_sigs[i].ptr)[w];
        }
    return 0;
}
void pf_reset(void) {
    dut->rst_ni = 0;
    for (int i = 0; i < 5; i++) ec();
    dut->rst_ni = 1;
    ec();
}
uint64_t pf_get_cycle(void) { return main_time/2; }
void pf_final(void) { if (dut){dut->final(); delete dut; dut=nullptr; rootp=nullptr;} }
} // extern "C"

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    pf_init(0);
    printf("[kmac-harness] init OK\n");
    uint32_t st = pf_read(0x1c);
    printf("[kmac-harness] STATUS(reset) = 0x%08x\n", st);
    pf_final();
    return 0;
}
