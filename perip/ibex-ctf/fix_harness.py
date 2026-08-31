#!/usr/bin/env python3
"""重写 ibex harness 信号表（用 root 头文件确认存在的信号）"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/harness/pf_ibex_harness.cpp"
s = open(p).read()

new_table = """// 白盒信号: PC/FSM/流水线/LSU（全部经 root 头文件确认存在）
static SigEntry g_sigs[] = {
    {"u_dut.ctrl_fsm_cs", nullptr, 1, false},
    {"u_dut.ctrl_fsm_ns", nullptr, 1, false},
    {"u_dut.debug_mode_q", nullptr, 1, false},
    {"u_dut.nmi_mode_q", nullptr, 1, false},
    {"u_dut.exc_req_q", nullptr, 1, false},
    {"u_dut.illegal_insn_q", nullptr, 1, false},
    {"u_dut.load_err_q", nullptr, 1, false},
    {"u_dut.store_err_q", nullptr, 1, false},
    {"u_dut.lsu_err_q", nullptr, 1, false},
    {"u_dut.pmp_err_q", nullptr, 1, false},
    {"u_dut.alu_operator", nullptr, 1, false},
    {"u_dut.alu_operand_a", nullptr, 1, false},
    {"u_dut.alu_operand_b", nullptr, 1, false},
    {"u_dut.branch_set", nullptr, 1, false},
    {"u_dut.lsu_req_dec", nullptr, 1, false},
    {"u_dut.lsu_we", nullptr, 1, false},
    {"u_dut.lsu_type", nullptr, 1, false},
    {"u_dut.mcause_d", nullptr, 1, false},
    {"u_dut.mepc_d", nullptr, 1, false},
    {"u_dut.mstatus_d", nullptr, 1, false},
    {"u_dut.csr_wdata_int", nullptr, 1, false},
    {"u_dut.csr_we_int", nullptr, 1, false},
    {"u_dut.mcycle_q", nullptr, 1, false},
    {"u_dut.minstret_q", nullptr, 1, false},
    {"u_dut.md_state_q", nullptr, 1, false},
    {"u_dut.div_counter_q", nullptr, 1, false},
};"""
import re
start = s.index("// 白盒信号:")
end = s.index("static const int g_nsig")
s = s[:start] + new_table + "\n" + s[end:]

# 重写 bind_signals
bind_start = s.index("static void bind_signals()")
bind_end = s.index("static uint32_t sig_word")
new_bind = """static void bind_signals() {
    #define ROOT(name) rootp->ibex_mini_tb__DOT__u_dut__DOT__##name
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        else if (strcmp(n, "u_dut.ctrl_fsm_cs") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__ctrl_fsm_cs);
        else if (strcmp(n, "u_dut.ctrl_fsm_ns") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__ctrl_fsm_ns);
        else if (strcmp(n, "u_dut.debug_mode_q") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__debug_mode_q);
        else if (strcmp(n, "u_dut.nmi_mode_q") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__nmi_mode_q);
        else if (strcmp(n, "u_dut.exc_req_q") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__exc_req_q);
        else if (strcmp(n, "u_dut.illegal_insn_q") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__illegal_insn_q);
        else if (strcmp(n, "u_dut.load_err_q") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__load_err_q);
        else if (strcmp(n, "u_dut.store_err_q") == 0) p = &ROOT(id_stage_i__DOT__controller_i__DOT__store_err_q);
        else if (strcmp(n, "u_dut.lsu_err_q") == 0) p = &ROOT(load_store_unit_i__DOT__lsu_err_q);
        else if (strcmp(n, "u_dut.pmp_err_q") == 0) p = &ROOT(load_store_unit_i__DOT__pmp_err_q);
        else if (strcmp(n, "u_dut.alu_operator") == 0) p = &ROOT(id_stage_i__DOT__alu_operator);
        else if (strcmp(n, "u_dut.alu_operand_a") == 0) p = &ROOT(id_stage_i__DOT__alu_operand_a);
        else if (strcmp(n, "u_dut.alu_operand_b") == 0) p = &ROOT(id_stage_i__DOT__alu_operand_b);
        else if (strcmp(n, "u_dut.branch_set") == 0) p = &ROOT(id_stage_i__DOT__branch_set);
        else if (strcmp(n, "u_dut.lsu_req_dec") == 0) p = &ROOT(id_stage_i__DOT__lsu_req_dec);
        else if (strcmp(n, "u_dut.lsu_we") == 0) p = &ROOT(id_stage_i__DOT__lsu_we);
        else if (strcmp(n, "u_dut.lsu_type") == 0) p = &ROOT(id_stage_i__DOT__lsu_type);
        else if (strcmp(n, "u_dut.mcause_d") == 0) p = &ROOT(cs_registers_i__DOT__mcause_d);
        else if (strcmp(n, "u_dut.mepc_d") == 0) p = &ROOT(cs_registers_i__DOT__mepc_d);
        else if (strcmp(n, "u_dut.mstatus_d") == 0) p = &ROOT(cs_registers_i__DOT__mstatus_d);
        else if (strcmp(n, "u_dut.csr_wdata_int") == 0) p = &ROOT(cs_registers_i__DOT__csr_wdata_int);
        else if (strcmp(n, "u_dut.csr_we_int") == 0) p = &ROOT(cs_registers_i__DOT__csr_we_int);
        else if (strcmp(n, "u_dut.mcycle_q") == 0) p = &ROOT(cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q);
        else if (strcmp(n, "u_dut.minstret_q") == 0) p = &ROOT(cs_registers_i__DOT__minstret_counter_i__DOT__counter_q);
        else if (strcmp(n, "u_dut.md_state_q") == 0) p = &ROOT(ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q);
        else if (strcmp(n, "u_dut.div_counter_q") == 0) p = &ROOT(ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_q);
        g_sigs[i].ptr = p;
    }
    #undef ROOT
}

"""
s = s[:bind_start] + new_bind + s[bind_end:]
open(p, "w").write(s)
print("ibex harness 信号表已重写")
