// PickerFuzz mini-CPU harness — ibex_core
// CPU 自主运行（无寄存器总线），API: pf_init/pf_step/pf_sig_*/pf_read(读存储器)
#include <verilated.h>
#include "Vibex_mini_tb.h"
#include "Vibex_mini_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vibex_mini_tb* dut = nullptr;
static Vibex_mini_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

// 白盒信号: PC/FSM/流水线/LSU（全部经 root 头文件确认存在）
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
    {"u_dut.mcause_d", nullptr, 1, false},
    {"u_dut.mepc_d", nullptr, 1, false},
    {"u_dut.mstatus_d", nullptr, 1, false},
    {"u_dut.csr_wdata_int", nullptr, 1, false},
    {"u_dut.csr_we_int", nullptr, 1, false},
    {"u_dut.mcycle_q", nullptr, 1, false},
    {"u_dut.minstret_q", nullptr, 1, false},
    {"u_dut.md_state_q", nullptr, 1, false},
    {"u_dut.div_counter_q", nullptr, 1, false},
    {"u_dut.fetch_addr_q", nullptr, 1, false},
    {"tb.data_gnt", nullptr, 1, false},
    {"tb.data_rvalid", nullptr, 1, false},
    {"csr.pmp_cfg0", nullptr, 1, false},
    {"csr.pmp_cfg1", nullptr, 1, false},
    {"csr.pmp_addr0", nullptr, 1, false},
    {"csr.pmp_addr1", nullptr, 1, false},
    {"csr.mstatus", nullptr, 1, false},
    {"csr.mie", nullptr, 1, false},
    {"lsu.pmp_err_q", nullptr, 1, false},
    {"lsu.pmp_err_d", nullptr, 1, false},
    {"lsu.lsu_err_q", nullptr, 1, false},
    {"lsu.addr_last", nullptr, 1, false},
    {"lsu.data_we", nullptr, 1, false},
    {"lsu.ls_fsm_cs", nullptr, 1, false},
    {"csr.csr_we_int", nullptr, 1, false},
    {"csr.illegal_csr", nullptr, 1, false},
    {"csr.csr_wr", nullptr, 1, false},
    {"csr.csr_addr", nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
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
        else if (strcmp(n, "u_dut.mcause_d") == 0) p = &ROOT(cs_registers_i__DOT__mcause_d);
        else if (strcmp(n, "u_dut.mepc_d") == 0) p = &ROOT(cs_registers_i__DOT__mepc_d);
        else if (strcmp(n, "u_dut.mstatus_d") == 0) p = &ROOT(cs_registers_i__DOT__mstatus_d);
        else if (strcmp(n, "u_dut.csr_wdata_int") == 0) p = &ROOT(cs_registers_i__DOT__csr_wdata_int);
        else if (strcmp(n, "u_dut.csr_we_int") == 0) p = &ROOT(cs_registers_i__DOT__csr_we_int);
        else if (strcmp(n, "u_dut.mcycle_q") == 0) p = &ROOT(cs_registers_i__DOT__mcycle_counter_i__DOT__counter_q);
        else if (strcmp(n, "u_dut.minstret_q") == 0) p = &ROOT(cs_registers_i__DOT__minstret_counter_i__DOT__counter_q);
        else if (strcmp(n, "u_dut.md_state_q") == 0) p = &ROOT(ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__md_state_q);
        else if (strcmp(n, "u_dut.div_counter_q") == 0) p = &ROOT(ex_block_i__DOT__gen_multdiv_fast__DOT__multdiv_i__DOT__div_counter_q);
        else if (strcmp(n, "u_dut.fetch_addr_q") == 0) p = &ROOT(if_stage_i__DOT__gen_prefetch_buffer__DOT__prefetch_buffer_i__DOT__fetch_addr_q);
        else if (strcmp(n, "tb.data_gnt") == 0) p = &rootp->ibex_mini_tb__DOT__data_gnt;
        else if (strcmp(n, "tb.data_rvalid") == 0) p = &rootp->ibex_mini_tb__DOT__data_rvalid;
        else if (strcmp(n, "csr.pmp_cfg0") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__pmp_cfg_rdata[0];
        else if (strcmp(n, "csr.pmp_cfg1") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__pmp_cfg_rdata[8];
        else if (strcmp(n, "csr.pmp_addr0") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__pmp_addr_rdata[0];
        else if (strcmp(n, "csr.pmp_addr1") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__pmp_addr_rdata[8];
        else if (strcmp(n, "csr.mstatus") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__u_mstatus_csr__DOT__rdata_q;
        else if (strcmp(n, "csr.mie") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__u_mie_csr__DOT__rdata_q;
        else if (strcmp(n, "lsu.pmp_err_q") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__load_store_unit_i__DOT__pmp_err_q;
        else if (strcmp(n, "lsu.pmp_err_d") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__load_store_unit_i__DOT__pmp_err_d;
        else if (strcmp(n, "lsu.lsu_err_q") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__load_store_unit_i__DOT__lsu_err_q;
        else if (strcmp(n, "lsu.addr_last") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__load_store_unit_i__DOT__addr_last_q;
        else if (strcmp(n, "lsu.data_we") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__load_store_unit_i__DOT__data_we_q;
        else if (strcmp(n, "lsu.ls_fsm_cs") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__load_store_unit_i__DOT__ls_fsm_cs;
        else if (strcmp(n, "csr.csr_we_int") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__csr_we_int;
        else if (strcmp(n, "csr.illegal_csr") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__illegal_csr;
        else if (strcmp(n, "csr.csr_wr") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__cs_registers_i__DOT__csr_wr;
        else if (strcmp(n, "u_dut.pc_id") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__pc_id;
        else if (strcmp(n, "if.fetch_rdata") == 0) p = &rootp->ibex_mini_tb__DOT__u_dut__DOT__if_stage_i__DOT__fetch_rdata;
        else if (strcmp(n, "tb.instr_gnt") == 0) p = &rootp->ibex_mini_tb__DOT__instr_gnt;
        else if (strcmp(n, "tb.instr_rvalid") == 0) p = &rootp->ibex_mini_tb__DOT__instr_rvalid;
        g_sigs[i].ptr = p;
    }
    #undef ROOT
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
        int argc = 1;
        const char* argv[] = {"pf_ibex", "+prog"};
        Verilated::commandArgs(2, (char**)argv);
        args_set = true;
    }
    if (dut) { dut->final(); delete dut; }
    g_snaps.clear();
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vibex_mini_tb;
    rootp = dut->rootp;
    bind_signals();
    dut->clk_i = 0;
    dut->rst_ni = 0;
    dut->cb_valid = 0;
    for (int i = 0; i < 10; i++) { dut->clk_i = 0; dut->eval(); dut->clk_i = 1; dut->eval(); main_time += 2; }
    dut->rst_ni = 1;
    dut->eval();
    eval_cycle();
    // C++ 直接加载 PMP 测试程序到 imem[32..]（0x80，复位向量）
    // 必须在 initial 块（第一次 eval）之后，否则被 initial 的清零覆盖
    {
        static const uint32_t prog[] = {
            0x01800293, // addi t0, x0, 0x18
            0x3a029073, // csrrw x0, pmpcfg0, t0
            0x00f00293, // addi t0, x0, 0x0f
            0x3b029073, // csrrw x0, pmpaddr0, t0
            0x00002303, // lw t1, 0(x0)  ← PMP 违例
            0x00000013, 0x00000013, 0x00000013, 0x00000013
        };
        for (int i = 0; i < 9 && (32 + i) < 1024; i++)
            rootp->ibex_mini_tb__DOT__imem[32 + i] = prog[i];
    }
    take_snapshot();
    return 0;
}

int pf_write(uint32_t addr, uint32_t data, uint32_t mask = 0xF) {
    // CPU 无寄存器总线——写操作仅推进时钟（保持 API 兼容）
    (void)addr; (void)data; (void)mask;
    for (int i = 0; i < 4; i++) eval_cycle();
    take_snapshot();
    return 0;
}

uint32_t pf_read(uint32_t addr) {
    // 读 imem/dmem（cb 接口）
    dut->cb_valid = 1;
    dut->cb_addr = addr;
    dut->cb_write = 0;
    dut->cb_wdata = 0;
    dut->cb_wmask = 0xF;
    eval_cycle();
    uint32_t v = dut->cb_rdata;
    dut->cb_valid = 0;
    eval_cycle();
    return v;
}

void pf_step(int n) {
    for (int i = 0; i < n; i++) eval_cycle();
    take_snapshot();
}

int pf_poll(uint32_t addr, uint32_t mask, uint32_t expect, int max_cycles) {
    (void)addr; (void)mask; (void)expect;
    for (int i = 0; i < max_cycles; i++) { eval_cycle(); }
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
