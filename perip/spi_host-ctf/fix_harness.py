#!/usr/bin/env python3
"""修 spi_host harness 信号表（用 root 头文件确认存在的信号）"""
p = "/workspace/pickerfuzz/perip/spi_host-ctf/harness/pf_spi_host_harness.cpp"
s = open(p).read()

new_table = """// 白盒信号: FSM/FIFO/移位/命令队列（全部经 root 头文件确认存在）
static SigEntry g_sigs[] = {
    {"u_fsm.state_q", nullptr, 1, false},
    {"u_fsm.state_d", nullptr, 1, false},
    {"u_fsm.state_changing", nullptr, 1, false},
    {"u_fsm.fsm_en", nullptr, 1, false},
    {"u_fsm.bit_cntr_q", nullptr, 1, false},
    {"u_fsm.byte_cntr_cpha0_q", nullptr, 1, false},
    {"u_fsm.byte_cntr_cpha1_q", nullptr, 1, false},
    {"u_fsm.clk_cntr_q", nullptr, 1, false},
    {"u_fsm.clkdiv_q", nullptr, 1, false},
    {"u_fsm.cmd_rd_en_q", nullptr, 1, false},
    {"u_fsm.cmd_wr_en_q", nullptr, 1, false},
    {"u_fsm.cmd_speed_q", nullptr, 1, false},
    {"u_fsm.cpha_q", nullptr, 1, false},
    {"u_fsm.byte_starting", nullptr, 1, false},
    {"u_fsm.byte_incoming", nullptr, 1, false},
    {"u_cmd_queue.cmd_fifo.full_o", nullptr, 1, false},
    {"u_cmd_queue.cmd_fifo.under_rst", nullptr, 1, false},
    {"u_data_fifos.rx_depth", nullptr, 1, false},
};"""
import re
start = s.index("// 白盒信号:")
end = s.index("static const int g_nsig")
s = s[:start] + new_table + "\n" + s[end:]

bind_start = s.index("static void bind_signals()")
bind_end = s.index("static uint32_t sig_word")
new_bind = """static void bind_signals() {
    #define FSM(name) rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_core__DOT__u_fsm__DOT__##name
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        else if (strcmp(n, "u_fsm.state_q") == 0) p = &FSM(state_q);
        else if (strcmp(n, "u_fsm.state_d") == 0) p = &FSM(state_d);
        else if (strcmp(n, "u_fsm.state_changing") == 0) p = &FSM(state_changing);
        else if (strcmp(n, "u_fsm.fsm_en") == 0) p = &FSM(fsm_en);
        else if (strcmp(n, "u_fsm.bit_cntr_q") == 0) p = &FSM(bit_cntr_q);
        else if (strcmp(n, "u_fsm.byte_cntr_cpha0_q") == 0) p = &FSM(byte_cntr_cpha0_q);
        else if (strcmp(n, "u_fsm.byte_cntr_cpha1_q") == 0) p = &FSM(byte_cntr_cpha1_q);
        else if (strcmp(n, "u_fsm.clk_cntr_q") == 0) p = &FSM(clk_cntr_q);
        else if (strcmp(n, "u_fsm.clkdiv_q") == 0) p = &FSM(clkdiv_q);
        else if (strcmp(n, "u_fsm.cmd_rd_en_q") == 0) p = &FSM(cmd_rd_en_q);
        else if (strcmp(n, "u_fsm.cmd_wr_en_q") == 0) p = &FSM(cmd_wr_en_q);
        else if (strcmp(n, "u_fsm.cmd_speed_q") == 0) p = &FSM(cmd_speed_q);
        else if (strcmp(n, "u_fsm.cpha_q") == 0) p = &FSM(cpha_q);
        else if (strcmp(n, "u_fsm.byte_starting") == 0) p = &FSM(byte_starting);
        else if (strcmp(n, "u_fsm.byte_incoming") == 0) p = &FSM(byte_incoming);
        else if (strcmp(n, "u_cmd_queue.cmd_fifo.full_o") == 0) p = &rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_cmd_queue__DOT__cmd_fifo__DOT__full_o;
        else if (strcmp(n, "u_cmd_queue.cmd_fifo.under_rst") == 0) p = &rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_cmd_queue__DOT__cmd_fifo__DOT__under_rst;
        else if (strcmp(n, "u_data_fifos.rx_depth") == 0) p = &rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_data_fifos__DOT__rx_depth;
        g_sigs[i].ptr = p;
    }
    #undef FSM
}

"""
s = s[:bind_start] + new_bind + s[bind_end:]
open(p, "w").write(s)
print("spi_host harness 信号表已重写")
