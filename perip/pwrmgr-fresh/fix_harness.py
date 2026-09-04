#!/usr/bin/env python3
"""pwrmgr harness 信号绑定修正"""
p = "/workspace/pickerfuzz/perip/pwrmgr-ctf/harness/pf_pwrmgr_harness.cpp"
s = open(p).read()

new_table = """// Whitebox signals: fast FSM state / slow FSM / power handshakes (verified in root header)
static SigEntry g_sigs[] = {
    {"u_fsm.state_raw", nullptr, 1, false},
    {"u_fsm.low_power_q", nullptr, 1, false},
    {"u_fsm.req_pwrdn_q", nullptr, 1, false},
    {"u_fsm.ack_pwrup_q", nullptr, 1, false},
    {"u_fsm.ip_clk_en_q", nullptr, 1, false},
    {"u_fsm.lc_done", nullptr, 1, false},
    {"u_fsm.fsm_invalid", nullptr, 1, false},
    {"u_slow_fsm.state_raw", nullptr, 1, false},
    {"u_dut.cause_q", nullptr, 1, false},
    {"u_dut.wake_ack_q", nullptr, 1, false},
};"""
start = s.index("static SigEntry g_sigs[] = {")
end = s.index("static const int g_nsig")
s = s[:start] + new_table + "\n" + s[end:]

bind_start = s.index("static void bind_signals()")
bind_end = s.index("static uint32_t sig_word")
new_bind = """static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        else if (strcmp(n, "u_fsm.state_raw") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_fsm.low_power_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__low_power_q;
        else if (strcmp(n, "u_fsm.req_pwrdn_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__req_pwrdn_q;
        else if (strcmp(n, "u_fsm.ack_pwrup_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__ack_pwrup_q;
        else if (strcmp(n, "u_fsm.ip_clk_en_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__ip_clk_en_q;
        else if (strcmp(n, "u_fsm.lc_done") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_fsm__DOT__lc_done;
        else if (strcmp(n, "u_fsm.fsm_invalid") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__fsm_invalid;
        else if (strcmp(n, "u_slow_fsm.state_raw") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__u_slow_fsm__DOT__u_state_regs__DOT__state_raw;
        else if (strcmp(n, "u_dut.cause_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__cause_q;
        else if (strcmp(n, "u_dut.wake_ack_q") == 0) p = &rootp->pwrmgr_perip_tb__DOT__u_dut__DOT__wake_ack_q;
        g_sigs[i].ptr = p;
    }
}

"""
s = s[:bind_start] + new_bind + s[bind_end:]
open(p, "w").write(s)
print("pwrmgr harness 信号绑定已修正")
