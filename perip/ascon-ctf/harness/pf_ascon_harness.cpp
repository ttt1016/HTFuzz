// PickerFuzz per-IP C++ harness — ascon（重点: 密钥残留/wipe 失效检测）
#include <verilated.h>
#include "Vascon_perip_tb.h"
#include "Vascon_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vascon_perip_tb* dut = nullptr;
static Vascon_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

// Whitebox signals: key registers (O-A residual target, Bug#43 wipe) + wipe/lc (Bug#38)
static SigEntry g_sigs[] = {
    {"ascon_core.key_share0_in_q", nullptr, 4, true},
    {"ascon_core.key_share1_in_q", nullptr, 4, true},
    {"ascon_core.key_share0_in_new_q", nullptr, 1, false},
    {"ascon_core.key_share1_in_new_q", nullptr, 1, false},
{"ascon_core.ascon_duplex.sel_mux_key_word1", nullptr, 1, true },
{"ascon_core.ascon_duplex.sel_mux_key_word2", nullptr, 1, true },
{"ascon_core.ascon_duplex.sel_mux_key_word3", nullptr, 1, true },
{"u_reg.ctrl_shadowed_masked_ad_input_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_masked_ad_input_update_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_masked_msg_input_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_masked_msg_input_update_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_sideload_key_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_sideload_key_update_err", nullptr, 1, true },
{"u_reg.key_share0_0_we", nullptr, 1, true },
{"u_reg.key_share0_1_we", nullptr, 1, true },
{"u_reg.key_share0_2_we", nullptr, 1, true },
{"u_reg.key_share0_3_we", nullptr, 1, true },
{"u_reg.key_share1_0_we", nullptr, 1, true },
{"u_reg.key_share1_1_we", nullptr, 1, true },
{"u_reg.key_share1_2_we", nullptr, 1, true },
{"u_reg.key_share1_3_we", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_ad_input.committed_q", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_ad_input.shadow_q", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_ad_input.shadow_wd", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_ad_input.shadow_we", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_msg_input.committed_q", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_msg_input.shadow_q", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_msg_input.shadow_wd", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_masked_msg_input.shadow_we", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_sideload_key.committed_q", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_sideload_key.shadow_q", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_sideload_key.shadow_wd", nullptr, 1, true },
{"u_reg.u_ctrl_shadowed_sideload_key.shadow_we", nullptr, 1, true },
{"u_reg.u_error_no_key.q", nullptr, 1, true },
{"ascon_core.ascon_duplex.ascon_state_q", nullptr, 1, true },
{"ascon_core.ascon_duplex.fsm_state_d", nullptr, 1, true },
{"ascon_core.ascon_duplex.sparse_fsm_error", nullptr, 1, true },
{"ascon_core.ascon_duplex.u_round_counter.err_q", nullptr, 1, true },
{"ascon_core.ascon_duplex.u_round_counter.gen_cnts__BRA__0__KET__.cnt_unforced_q", nullptr, 1, true },
{"ascon_core.ascon_duplex.u_round_counter.gen_cnts__BRA__1__KET__.cnt_unforced_q", nullptr, 1, true },
{"ascon_core.ascon_duplex.u_state_regs.state_raw", nullptr, 1, true },
{"u_reg.fsm_state_regren_we", nullptr, 1, true },
{"u_reg.u_fsm_state_regren.q", nullptr, 1, true },
{"u_reg.u_reg_if.rdata_q", nullptr, 1, true },
{"ascon_core.flag_error", nullptr, 1, true },
{"ascon_core.nonce_error", nullptr, 1, true },
{"ascon_core.order_error", nullptr, 1, true },
{"u_reg.alert_test_we", nullptr, 1, true },
{"u_reg.block_ctrl_shadowed_data_type_last_storage_err", nullptr, 1, true },
{"u_reg.block_ctrl_shadowed_data_type_last_update_err", nullptr, 1, true },
{"u_reg.block_ctrl_shadowed_data_type_start_storage_err", nullptr, 1, true },
{"u_reg.block_ctrl_shadowed_data_type_start_update_err", nullptr, 1, true },
{"u_reg.block_ctrl_shadowed_valid_bytes_storage_err", nullptr, 1, true },
{"u_reg.block_ctrl_shadowed_valid_bytes_update_err", nullptr, 1, true },
{"u_reg.ctrl_aux_shadowed_force_data_overwrite_storage_err", nullptr, 1, true },
{"u_reg.ctrl_aux_shadowed_force_data_overwrite_update_err", nullptr, 1, true },
{"u_reg.ctrl_aux_shadowed_manual_start_trigger_storage_err", nullptr, 1, true },
{"u_reg.ctrl_aux_shadowed_manual_start_trigger_update_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_ascon_variant_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_ascon_variant_update_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_no_ad_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_no_ad_update_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_no_msg_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_no_msg_update_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_operation_storage_err", nullptr, 1, true },
{"u_reg.ctrl_shadowed_operation_update_err", nullptr, 1, true },
{"u_reg.err_q", nullptr, 1, true },
{"u_reg.intg_err", nullptr, 1, true },
{"u_reg.reg_error", nullptr, 1, true },
{"u_reg.reg_we_err", nullptr, 1, true },
{"u_reg.u_error_flag_input_missmatch.q", nullptr, 1, true },
{"u_reg.u_error_no_nonce.q", nullptr, 1, true },
{"u_reg.u_error_wrong_order.q", nullptr, 1, true },
{"u_reg.u_reg_if.err_internal", nullptr, 1, true },
{"u_reg.u_reg_if.error_q", nullptr, 1, true },
{"u_reg.u_status_alert_fatal_fault.q", nullptr, 1, true },
{"u_reg.u_status_alert_recov_ctrl_update_err.q", nullptr, 1, true },
{"u_reg.u_status_ascon_error.q", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "ascon_core.ascon_duplex.ascon_state_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__ascon_state_q;
        else if (strcmp(n, "ascon_core.ascon_duplex.fsm_state_d") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__fsm_state_d;
        else if (strcmp(n, "ascon_core.ascon_duplex.sel_mux_key_word1") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__sel_mux_key_word1;
        else if (strcmp(n, "ascon_core.ascon_duplex.sel_mux_key_word2") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__sel_mux_key_word2;
        else if (strcmp(n, "ascon_core.ascon_duplex.sel_mux_key_word3") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__sel_mux_key_word3;
        else if (strcmp(n, "ascon_core.ascon_duplex.sparse_fsm_error") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__sparse_fsm_error;
        else if (strcmp(n, "ascon_core.ascon_duplex.u_round_counter.err_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__u_round_counter__DOT__err_q;
        else if (strcmp(n, "ascon_core.ascon_duplex.u_round_counter.gen_cnts__BRA__0__KET__.cnt_unforced_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__u_round_counter__DOT__gen_cnts__BRA__0__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "ascon_core.ascon_duplex.u_round_counter.gen_cnts__BRA__1__KET__.cnt_unforced_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__u_round_counter__DOT__gen_cnts__BRA__1__KET____DOT__cnt_unforced_q;
        else if (strcmp(n, "ascon_core.ascon_duplex.u_state_regs.state_raw") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__ascon_duplex__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "ascon_core.flag_error") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__flag_error;
        else if (strcmp(n, "ascon_core.key_share0_in_new_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__key_share0_in_new_q;
        else if (strcmp(n, "ascon_core.key_share1_in_new_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__key_share1_in_new_q;
        else if (strcmp(n, "ascon_core.nonce_error") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__nonce_error;
        else if (strcmp(n, "ascon_core.order_error") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__order_error;
        else if (strcmp(n, "u_reg.alert_test_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__alert_test_we;
        else if (strcmp(n, "u_reg.block_ctrl_shadowed_data_type_last_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__block_ctrl_shadowed_data_type_last_storage_err;
        else if (strcmp(n, "u_reg.block_ctrl_shadowed_data_type_last_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__block_ctrl_shadowed_data_type_last_update_err;
        else if (strcmp(n, "u_reg.block_ctrl_shadowed_data_type_start_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__block_ctrl_shadowed_data_type_start_storage_err;
        else if (strcmp(n, "u_reg.block_ctrl_shadowed_data_type_start_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__block_ctrl_shadowed_data_type_start_update_err;
        else if (strcmp(n, "u_reg.block_ctrl_shadowed_valid_bytes_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__block_ctrl_shadowed_valid_bytes_storage_err;
        else if (strcmp(n, "u_reg.block_ctrl_shadowed_valid_bytes_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__block_ctrl_shadowed_valid_bytes_update_err;
        else if (strcmp(n, "u_reg.ctrl_aux_shadowed_force_data_overwrite_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_aux_shadowed_force_data_overwrite_storage_err;
        else if (strcmp(n, "u_reg.ctrl_aux_shadowed_force_data_overwrite_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_aux_shadowed_force_data_overwrite_update_err;
        else if (strcmp(n, "u_reg.ctrl_aux_shadowed_manual_start_trigger_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_aux_shadowed_manual_start_trigger_storage_err;
        else if (strcmp(n, "u_reg.ctrl_aux_shadowed_manual_start_trigger_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_aux_shadowed_manual_start_trigger_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_ascon_variant_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_ascon_variant_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_ascon_variant_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_ascon_variant_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_masked_ad_input_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_masked_ad_input_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_masked_ad_input_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_masked_ad_input_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_masked_msg_input_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_masked_msg_input_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_masked_msg_input_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_masked_msg_input_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_no_ad_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_no_ad_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_no_ad_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_no_ad_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_no_msg_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_no_msg_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_no_msg_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_no_msg_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_operation_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_operation_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_operation_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_operation_update_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_sideload_key_storage_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_sideload_key_storage_err;
        else if (strcmp(n, "u_reg.ctrl_shadowed_sideload_key_update_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__ctrl_shadowed_sideload_key_update_err;
        else if (strcmp(n, "u_reg.err_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__err_q;
        else if (strcmp(n, "u_reg.fsm_state_regren_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__fsm_state_regren_we;
        else if (strcmp(n, "u_reg.intg_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__intg_err;
        else if (strcmp(n, "u_reg.key_share0_0_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share0_0_we;
        else if (strcmp(n, "u_reg.key_share0_1_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share0_1_we;
        else if (strcmp(n, "u_reg.key_share0_2_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share0_2_we;
        else if (strcmp(n, "u_reg.key_share0_3_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share0_3_we;
        else if (strcmp(n, "u_reg.key_share1_0_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share1_0_we;
        else if (strcmp(n, "u_reg.key_share1_1_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share1_1_we;
        else if (strcmp(n, "u_reg.key_share1_2_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share1_2_we;
        else if (strcmp(n, "u_reg.key_share1_3_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__key_share1_3_we;
        else if (strcmp(n, "u_reg.reg_error") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_error;
        else if (strcmp(n, "u_reg.reg_we_err") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_we_err;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_ad_input.committed_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_ad_input__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_ad_input.shadow_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_ad_input__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_ad_input.shadow_wd") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_ad_input__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_ad_input.shadow_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_ad_input__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_msg_input.committed_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_msg_input__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_msg_input.shadow_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_msg_input__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_msg_input.shadow_wd") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_msg_input__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_masked_msg_input.shadow_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_masked_msg_input__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_sideload_key.committed_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_sideload_key__DOT__committed_q;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_sideload_key.shadow_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_sideload_key__DOT__shadow_q;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_sideload_key.shadow_wd") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_sideload_key__DOT__shadow_wd;
        else if (strcmp(n, "u_reg.u_ctrl_shadowed_sideload_key.shadow_we") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_ctrl_shadowed_sideload_key__DOT__shadow_we;
        else if (strcmp(n, "u_reg.u_error_flag_input_missmatch.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_error_flag_input_missmatch__DOT__q;
        else if (strcmp(n, "u_reg.u_error_no_key.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_error_no_key__DOT__q;
        else if (strcmp(n, "u_reg.u_error_no_nonce.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_error_no_nonce__DOT__q;
        else if (strcmp(n, "u_reg.u_error_wrong_order.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_error_wrong_order__DOT__q;
        else if (strcmp(n, "u_reg.u_fsm_state_regren.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_fsm_state_regren__DOT__q;
        else if (strcmp(n, "u_reg.u_reg_if.err_internal") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__err_internal;
        else if (strcmp(n, "u_reg.u_reg_if.error_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__error_q;
        else if (strcmp(n, "u_reg.u_reg_if.rdata_q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__rdata_q;
        else if (strcmp(n, "u_reg.u_status_alert_fatal_fault.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_status_alert_fatal_fault__DOT__q;
        else if (strcmp(n, "u_reg.u_status_alert_recov_ctrl_update_err.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_status_alert_recov_ctrl_update_err__DOT__q;
        else if (strcmp(n, "u_reg.u_status_ascon_error.q") == 0) p = &rootp->ascon_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_status_ascon_error__DOT__q;
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
    dut = new Vascon_perip_tb;
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

// lc escalation 控制（Bug#38 验证）: cb 写 0x8000 地址触发
static int g_escalate_on = 0;
void pf_set_escalate(int on) { g_escalate_on = on; }

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
