#!/usr/bin/env python3
"""rom_ctrl harness 信号绑定修正"""
p = "/workspace/pickerfuzz/perip/rom_ctrl-ctf/harness/pf_rom_ctrl_harness.cpp"
s = open(p).read()

new_table = """// Whitebox signals: bus response timing (Bug#2 target) + FSM
static SigEntry g_sigs[] = {
    {"u_dut.rom_rvalid", nullptr, 1, false},
    {"u_dut.reqfifo_rvalid", nullptr, 1, false},
    {"u_dut.rspfifo_rvalid", nullptr, 1, false},
    {"u_dut.rom_req", nullptr, 1, false},
    {"u_dut.alert_q", nullptr, 1, false},
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
        else if (strcmp(n, "u_dut.rom_rvalid") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__rom_rvalid;
        else if (strcmp(n, "u_dut.reqfifo_rvalid") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__reqfifo_rvalid;
        else if (strcmp(n, "u_dut.rspfifo_rvalid") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__rspfifo_rvalid;
        else if (strcmp(n, "u_dut.rom_req") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__rom_req;
        else if (strcmp(n, "u_dut.alert_q") == 0) p = &rootp->rom_ctrl_perip_tb__DOT__u_dut__DOT__alert_q;
        g_sigs[i].ptr = p;
    }
}

"""
s = s[:bind_start] + new_bind + s[bind_end:]
open(p, "w").write(s)
print("rom_ctrl harness 信号绑定已修正")
