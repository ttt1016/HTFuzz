// PickerFuzz per-IP C++ harness — rstmgr
#include <verilated.h>
#include "Vrstmgr_perip_tb.h"
#include "Vrstmgr_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vrstmgr_perip_tb* dut = nullptr;
static Vrstmgr_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    {"i2c0_chk.dst_fsm_cs", nullptr, 1, false},
    {"i2c0_chk.src_fsm_cs", nullptr, 1, false},
    {"i2c0_chk.state_raw", nullptr, 1, false},
    {"alert_info.slots_q", nullptr, 4, true},
    {"cpu_info.slots_q", nullptr, 4, true},
{"u_d0_i2c0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_i2c0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_i2c0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_i2c0.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_i2c1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_i2c1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_i2c1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_i2c1.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_i2c2.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_i2c2.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_i2c2.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_i2c2.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_spi_device.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_spi_device.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_spi_device.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_spi_device.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_usb.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_usb.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_usb.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_usb.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs", nullptr, 1, true },
{"u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns", nullptr, 1, true },
{"u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs", nullptr, 1, true },
{"u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_state_regs.state_raw", nullptr, 1, true },
{"u_reg.u_reg_if.rdata_q", nullptr, 1, true },
{"u_alert_info.slots_q", nullptr, 1, true },
{"u_reg.alert_info_ctrl_gated_we", nullptr, 1, true },
{"u_reg.alert_regwen_we", nullptr, 1, true },
{"u_reg.err_q", nullptr, 1, true },
{"u_reg.intg_err", nullptr, 1, true },
{"u_reg.reg_error", nullptr, 1, true },
{"u_reg.reg_we_err", nullptr, 1, true },
{"u_reg.u_alert_regwen.q", nullptr, 1, true },
{"u_reg.u_reg_if.err_internal", nullptr, 1, true },
{"u_reg.u_reg_if.error_q", nullptr, 1, true }
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        (void)p;
        if (strcmp(n, "alert_info.slots_q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_alert_info__DOT__slots_q;
        else if (strcmp(n, "cpu_info.slots_q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_alert_info__DOT__slots_q;
        else if (strcmp(n, "i2c0_chk.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "i2c0_chk.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "i2c0_chk.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_alert_info.slots_q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_alert_info__DOT__slots_q;
        else if (strcmp(n, "u_d0_i2c0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_i2c0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_i2c0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_i2c0.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_i2c1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_i2c1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_i2c1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_i2c1.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_i2c2.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_i2c2.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_i2c2.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_i2c2.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_spi_device.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_spi_device.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_spi_device.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_spi_device.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_spi_host0.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_spi_host1.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_usb.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_usb.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_usb.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_usb.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_cs;
        else if (strcmp(n, "u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.dst_fsm_ns") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__dst_fsm_ns;
        else if (strcmp(n, "u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_child_handshake.gen_nrz_hs_protocol.src_fsm_cs") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_child_handshake__DOT__gen_nrz_hs_protocol__DOT__src_fsm_cs;
        else if (strcmp(n, "u_d0_usb_aon.gen_rst_chk.u_rst_chk.u_state_regs.state_raw") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_d0_i2c0__DOT__gen_rst_chk__DOT__u_rst_chk__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_reg.alert_info_ctrl_gated_we") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__alert_info_ctrl_gated_we;
        else if (strcmp(n, "u_reg.alert_regwen_we") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__alert_regwen_we;
        else if (strcmp(n, "u_reg.err_q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__err_q;
        else if (strcmp(n, "u_reg.intg_err") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__intg_err;
        else if (strcmp(n, "u_reg.reg_error") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_error;
        else if (strcmp(n, "u_reg.reg_we_err") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_we_err;
        else if (strcmp(n, "u_reg.u_alert_regwen.q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_alert_regwen__DOT__q;
        else if (strcmp(n, "u_reg.u_reg_if.err_internal") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__err_internal;
        else if (strcmp(n, "u_reg.u_reg_if.error_q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__error_q;
        else if (strcmp(n, "u_reg.u_reg_if.rdata_q") == 0) p = &rootp->rstmgr_perip_tb__DOT__u_dut__DOT__u_reg__DOT__u_reg_if__DOT__rdata_q;
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
    dut = new Vrstmgr_perip_tb;
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

} // extern "C"
