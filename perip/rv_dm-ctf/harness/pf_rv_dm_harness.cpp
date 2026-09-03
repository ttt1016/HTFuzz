// PickerFuzz per-IP C++ harness — rv_dm（JTAG DMI 安全边界）
// ============================================================================
// API（extern "C"，供 Python ctypes 调用）:
//   pf_init(seed)            初始化
//   pf_step(n)               DMI 域推进 n 拍
//   jtag_ir(ir)              写 TAP IR（5bit）
//   jtag_dr(bits, n)         移位 DR，返回移出的值
//   pf_dmi_read(addr) -> u32 DMI 读
//   pf_dmi_write(addr, data) DMI 写
//   pf_sig_*                 白盒信号
// 自检 main: IDCODE + dmcontrol 读写 + dmstatus.authenticated 检查
// ============================================================================
#include <verilated.h>
#include "Vrv_dm_perip_tb.h"
#include "Vrv_dm_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

static Vrv_dm_perip_tb* dut = nullptr;
static Vrv_dm_perip_tb___024root* rootp = nullptr;
#if VM_TRACE
#include "verilated_vcd_c.h"
static VerilatedVcdC* g_tfp = nullptr;
static uint64_t g_time = 0;
static inline void vcd_dump() { if (g_tfp) g_tfp->dump(++g_time); }
#else
static inline void vcd_dump() {}
#endif

struct SigEntry {
    const char* name;
    void* ptr;
    int words;      // 32bit 字数
    bool is_wide;   // VlWide/QData 按字读
};

static SigEntry g_sigs[] = {
    // --- DMI/TAP 白盒 ---
    {"u_jtag.state_q",            nullptr, 1, false},  // DMI FSM（3b）
    {"u_jtag.address_q",          nullptr, 1, false},
    {"u_jtag.data_q",             nullptr, 1, false},
    {"u_jtag.tap.state_q",        nullptr, 1, false},  // TAP 16 态
    {"u_jtag.tap.ir_q",           nullptr, 1, false},  // 当前 IR
    // --- DM CSR 白盒 ---
    {"u_dm.dmcontrol_q",          nullptr, 1, false},
    {"u_dm.cmderr_q",             nullptr, 1, false},
    {"u_dm.sbcs_q",               nullptr, 1, false},
    {"u_dm.sbaddr_q",             nullptr, 2, true},   // 64b
    {"u_dm.sbdata_q",             nullptr, 2, true},   // 64b
    {"u_dm.data_q",               nullptr, 2, true},   // 64b abstract data
    {"u_dm.mem.halted_q",         nullptr, 1, false},
    {"u_dm.mem.state_q",          nullptr, 1, false},
    {"u_dm.sba.state_q",          nullptr, 1, false},
    {"u_dm.sberror",              nullptr, 1, false},
    {"u_jtag.cdc_req.dst_fsm_q",  nullptr, 1, false},
    {"u_jtag.cdc_req.src_fsm_q",  nullptr, 1, false},
    {"u_jtag.cdc_req.dst_req",    nullptr, 1, false},
    {"u_jtag.cdc_req.wr_en",      nullptr, 1, false},
    {"u_jtag.cdc_resp.wr_en",     nullptr, 1, false},
    {"u_jtag.error_q",            nullptr, 1, false},
    {"u_jtag.resp.src_fsm_q",     nullptr, 1, false},
    {"u_jtag.resp.dst_fsm_q",     nullptr, 1, false},
    {"u_jtag.resp.pending_q",     nullptr, 1, false},
    {"u_jtag.req.pending_q",      nullptr, 1, false},
    {"u_jtag.req.not_in_reset_q", nullptr, 1, false},
    {"u_jtag.resp.not_in_reset_q", nullptr, 1, false},
    {"u_dm.fifo_incr_wptr",       nullptr, 1, false},
    {"u_dm.fifo_wptr_cnt",        nullptr, 1, false},
    {"u_dm.fifo_rptr_cnt",        nullptr, 1, false},
    {"u_dm.resp_queue_inp",       nullptr, 3, true},
    {"u_dm.fifo_storage0",        nullptr, 3, true},
    {"u_jtag.dr_q",               nullptr, 2, false},  // QData 41bit -> 2 words
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (strcmp(n, "u_jtag.state_q") == 0)            p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__state_q;
        else if (strcmp(n, "u_jtag.address_q") == 0)     p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__address_q;
        else if (strcmp(n, "u_jtag.data_q") == 0)        p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__data_q;
        else if (strcmp(n, "u_jtag.tap.state_q") == 0)   p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_jtag_tap__DOT__tap_state_q;
        else if (strcmp(n, "u_jtag.tap.ir_q") == 0)      p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_jtag_tap__DOT__jtag_ir_q;
        else if (strcmp(n, "u_dm.dmcontrol_q") == 0)     p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__dmcontrol_q;
        else if (strcmp(n, "u_dm.cmderr_q") == 0)        p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__cmderr_q;
        else if (strcmp(n, "u_dm.sbcs_q") == 0)          p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__sbcs_q;
        else if (strcmp(n, "u_dm.sbaddr_q") == 0)        p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__sbaddr_q;
        else if (strcmp(n, "u_dm.sbdata_q") == 0)        p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__sbdata_q;
        else if (strcmp(n, "u_dm.data_q") == 0)          p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__data_q;
        else if (strcmp(n, "u_dm.mem.halted_q") == 0)    p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_mem__DOT__halted_q;
        else if (strcmp(n, "u_dm.mem.state_q") == 0)     p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_mem__DOT__state_q;
        else if (strcmp(n, "u_dm.sba.state_q") == 0)     p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_sba__DOT__state_q;
        else if (strcmp(n, "u_dm.sberror") == 0)         p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__sberror;
        else if (strcmp(n, "u_jtag.cdc_req.dst_fsm_q") == 0) p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_req__DOT__u_prim_sync_reqack__DOT__gen_rz_hs_protocol__DOT__dst_fsm_q;
        else if (strcmp(n, "u_jtag.cdc_req.src_fsm_q") == 0) p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_req__DOT__u_prim_sync_reqack__DOT__gen_rz_hs_protocol__DOT__src_fsm_q;
        else if (strcmp(n, "u_jtag.cdc_req.dst_req") == 0)   p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_req__DOT__dst_req;
        else if (strcmp(n, "u_jtag.cdc_req.wr_en") == 0)     p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_req__DOT__wr_en;
        else if (strcmp(n, "u_jtag.cdc_resp.wr_en") == 0)    p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_resp__DOT__wr_en;
        else if (strcmp(n, "u_jtag.error_q") == 0)           p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__error_q;
        else if (strcmp(n, "u_jtag.resp.src_fsm_q") == 0)    p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_resp__DOT__u_prim_sync_reqack__DOT__gen_rz_hs_protocol__DOT__src_fsm_q;
        else if (strcmp(n, "u_jtag.resp.dst_fsm_q") == 0)    p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_resp__DOT__u_prim_sync_reqack__DOT__gen_rz_hs_protocol__DOT__dst_fsm_q;
        else if (strcmp(n, "u_jtag.resp.pending_q") == 0)    p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_resp__DOT__pending_q;
        else if (strcmp(n, "u_jtag.req.pending_q") == 0)     p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_req__DOT__pending_q;
        else if (strcmp(n, "u_jtag.req.not_in_reset_q") == 0) p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_req__DOT__not_in_reset_q;
        else if (strcmp(n, "u_jtag.resp.not_in_reset_q") == 0) p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_cdc__DOT__i_cdc_resp__DOT__not_in_reset_q;
        else if (strcmp(n, "u_dm.fifo_incr_wptr") == 0)  p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__i_fifo__DOT__gen_normal_fifo__DOT__fifo_incr_wptr;
        else if (strcmp(n, "u_dm.fifo_wptr_cnt") == 0)   p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__i_fifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__wptr_wrap_cnt_q;
        else if (strcmp(n, "u_dm.fifo_rptr_cnt") == 0)   p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__i_fifo__DOT__gen_normal_fifo__DOT__u_fifo_cnt__DOT__rptr_wrap_cnt_q;
        else if (strcmp(n, "u_dm.resp_queue_inp") == 0)  p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__resp_queue_inp;
        else if (strcmp(n, "u_dm.fifo_storage0") == 0)   p = &rootp->rv_dm_perip_tb__DOT__u_dm__DOT__i_dm_csrs__DOT__i_fifo__DOT__gen_normal_fifo__DOT__storage;
        else if (strcmp(n, "u_jtag.dr_q") == 0)          p = &rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__dr_q;
        // (u_jtag.dmi_req_valid 仅 trace 版头文件存在)
        g_sigs[i].ptr = p;
    }
}

static uint32_t sig_word(const SigEntry& s, int w) {
    if (!s.ptr) return 0;
    if (s.is_wide) return reinterpret_cast<uint32_t*>(s.ptr)[w];
    return *reinterpret_cast<uint8_t*>(s.ptr);
}

// ---- TAP 状态编码（dmi_jtag_tap tap_state_e 顺序）----
enum { TLR=0, RTI=1, SELDR=2, CAPDR=3, SHDR=4, EX1DR=5, PDR=6, EX2DR=7,
       UPDR=8, SELIR=9, CAPIR=10, SHIR=11, EX1IR=12, PIR=13, EX2IR=14, UPIR=15 };

static int tap_state() {
    return rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_jtag_tap__DOT__tap_state_q;
}

static void eval_cycle() {
    rootp->clk_i = 0; dut->eval(); vcd_dump();
    rootp->clk_i = 1; dut->eval(); vcd_dump();
    if (getenv("PF_JTAG_DBG"))
        fprintf(stderr, "[clkdbg] clk_i member now = %u\n",
                (unsigned)rootp->clk_i);
    rootp->clk_i = 0; dut->eval(); vcd_dump();
}

// TCK 一个完整周期：tck 低时设置输入，上升沿采样；返回下降沿前的 tdo
static int jtag_tick(int tms, int tdi) {
    rootp->rv_dm_perip_tb__DOT__tck_i = 0;
    rootp->tms_i = tms;
    rootp->td_i  = tdi;
    dut->eval(); vcd_dump();
    rootp->rv_dm_perip_tb__DOT__tck_i = 1;
    dut->eval(); vcd_dump();
    int tdo = rootp->td_o & 1;   // 上升沿后、下降沿前采样
    rootp->rv_dm_perip_tb__DOT__tck_i = 0;
    dut->eval(); vcd_dump();
    // DMI 域时钟同时推进（CDC 需要）
    eval_cycle();
    return tdo;
}

static void jtag_tlr() {
    for (int i = 0; i < 5; i++) jtag_tick(1, 0);
    jtag_tick(0, 0);  // -> Run-Test/Idle
}

static void jtag_ir(int ir) {
    // TLR -> SelectIR -> CaptureIR -> ShiftIR
    jtag_tlr();
    jtag_tick(1, 0);  // SelectDR
    jtag_tick(1, 0);  // SelectIR
    jtag_tick(0, 0);  // CaptureIR
    jtag_tick(0, 0);  // ShiftIR
    for (int i = 0; i < 5; i++) {
        jtag_tick(i == 4 ? 1 : 0, (ir >> i) & 1);
    }
    jtag_tick(1, 0);  // UpdateIR
    jtag_tick(0, 0);  // RTI
}

static uint64_t jtag_dr(int nbits, uint64_t wdata);
extern "C" uint32_t pf_sig_value(int i, int w);

// DR 移位：LSB first，返回移出的值；从 Run-Test/Idle 进入
static uint64_t jtag_dr(int nbits, uint64_t wdata) {
    // RTI -> SelectDR -> CaptureDR -> ShiftDR
    jtag_tick(1, 0);              // SelectDR
    jtag_tick(0, 0);              // CaptureDR
    if (getenv("PF_JTAG_DBG"))
        fprintf(stderr, "[cap] tap=%u dr_q=0x%010llx addr_q=0x%02x data_q=0x%08x err_q=%u\n",
                tap_state(), (unsigned long long)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__dr_q,
                (unsigned)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__address_q,
                (unsigned)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__data_q,
                (unsigned)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__error_q);
    jtag_tick(0, 0);              // ShiftDR
    uint64_t out = 0;
    for (int i = 0; i < nbits; i++) {
        int tms = (i == nbits - 1) ? 1 : 0;
        int tdo = jtag_tick(tms, (int)((wdata >> i) & 1));
        if (getenv("PF_JTAG_DBG"))
            fprintf(stderr, "[dbg] i=%2d tap=%u tdi=%d tdo=%d dr_q=0x%010llx\n",
                    i, tap_state(), (int)((wdata >> i) & 1), tdo,
                    (unsigned long long)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__dr_q);
        out |= (uint64_t)tdo << i;
    }
    // ShiftDR(tms=1) -> Exit1DR -> UpdateDR -> RTI
    if (getenv("PF_JTAG_DBG"))
        printf("[dbg] pre-update: tap=%u dmi=%u addr=0x%02x data=0x%08x\n",
               tap_state(), pf_sig_value(0,0), pf_sig_value(1,0), pf_sig_value(2,0));
    jtag_tick(1, 0);              // UpdateDR
    jtag_tick(0, 0);              // RTI
    if (getenv("PF_JTAG_DBG"))
        printf("[dbg] post-update: tap=%u dmi=%u addr=0x%02x data=0x%08x\n",
               tap_state(), pf_sig_value(0,0), pf_sig_value(1,0), pf_sig_value(2,0));
    return out;
}

extern "C" {

int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vrv_dm_perip_tb;
    rootp = dut->rootp;
    rootp->clk_i = 0;
    rootp->rst_ni = 0;
    rootp->test_rst_ni = 0;
    rootp->trst_ni = 0;
    for (int i = 0; i < 10; i++) eval_cycle();
    rootp->rst_ni = 1;
    rootp->test_rst_ni = 1;
    rootp->trst_ni = 1;
    for (int i = 0; i < 5; i++) eval_cycle();
    fprintf(stderr, "[dbg] after init: rst_ni=%u clk=%u trst=%u tap=%u\n",
            (unsigned)rootp->rst_ni,
            (unsigned)rootp->clk_i,
            (unsigned)rootp->trst_ni,
            (unsigned)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__i_dmi_jtag_tap__DOT__tap_state_q);
    bind_signals();
    return 0;
}

void pf_step(int n) { for (int i = 0; i < n; i++) eval_cycle(); }

// 完整 DMI 事务。dmi_t packed 布局（首字段在高位）:
//   [40:34]=address[6:0]  [33:2]=data[31:0]  [1:0]=op
static int g_cur_ir = -1;
static uint64_t dmi_xact(int op, uint32_t addr, uint32_t data) {
    if (g_cur_ir != 0x11) {          // 只在必要时过 TLR：TLR 会脉冲 dmi_clear，
        jtag_ir(0x11);               // 清零 combined_rstn 并复位 clk 域 CDC
        g_cur_ir = 0x11;
    }
    uint64_t w = ((uint64_t)(addr & 0x7F) << 34) | ((uint64_t)data << 2) | (op & 0x3);
    uint64_t r = jtag_dr(41, w);
    if (getenv("PF_JTAG_DBG"))
        fprintf(stderr, "[xact-done] dr_q=0x%010llx dmcontrol_q=0x%08x addr_q=0x%02x data_q=0x%08x\n",
                (unsigned long long)rootp->rv_dm_perip_tb__DOT__u_jtag__DOT__dr_q,
                pf_sig_value(5,0), pf_sig_value(1,0), pf_sig_value(2,0));
    if (getenv("PF_JTAG_DBG"))
        fprintf(stderr, "[xact] op=%d addr=0x%x right-after: dmi.state=%u dmcontrol_q=0x%08x\n",
                op, addr, pf_sig_value(0,0), pf_sig_value(5,0));
    // 等 DMI FSM 彻底回到 Idle；调试期轮询打印 CDC 握手状态
    for (int i = 0; i < 2000 && pf_sig_value(0, 0) != 0; i++) {
        pf_step(10);
        if (getenv("PF_JTAG_DBG") && i < 12)
            fprintf(stderr, "[cdc] t=%d dmi.state=%u | req src=%u dst=%u dst_req=%u wr_en=%u pend=%u | resp src=%u dst=%u wr_en=%u pend=%u\n",
                    i, pf_sig_value(0,0),
                    pf_sig_value(16,0), pf_sig_value(15,0), pf_sig_value(17,0),
                    pf_sig_value(18,0), pf_sig_value(24,0),
                    pf_sig_value(21,0), pf_sig_value(22,0),
                    pf_sig_value(19,0), pf_sig_value(23,0));
    }
    pf_step(100);
    if (getenv("PF_JTAG_DBG"))
        fprintf(stderr, "[xact] op=%d after-settle: dmi.state=%u dmcontrol_q=0x%08x\n",
                op, pf_sig_value(0,0), pf_sig_value(5,0));
    return r;
}

// DMI 读：两次事务（第一次发起，第二次取回结果）
uint32_t pf_dmi_read(uint32_t addr) {
    dmi_xact(1, addr, 0);            // DTM_READ
    uint64_t r = dmi_xact(0, 0, 0);  // NOP，取回数据
    return (uint32_t)(r >> 2);
}

int pf_dmi_write(uint32_t addr, uint32_t data) {
    dmi_xact(2, addr, data);         // DTM_WRITE
    uint64_t r = dmi_xact(0, 0, 0);  // NOP，检查 op 域
    return (int)(r & 0x3);
}

uint32_t pf_read_idcode(void) {
    jtag_tlr();
    g_cur_ir = -1;                   // TLR 会重置 DMI 访问，标记需重新发 IR
    return (uint32_t)jtag_dr(32, 0);
}

// 清 DMI sticky error（dtmcs.dmireset=bit16, dmihardreset=bit17）
// dr 布局 [40:34]=addr [33:2]=data [1:0]=op → dtmcs 值放 data 域（dr[19:18]=bit17,16）
void pf_dmi_clear_error(void) {
    jtag_ir(0x10); g_cur_ir = 0x10;
    jtag_dr(41, (1ULL << (17 + 2)) | (1ULL << (16 + 2)));
    // 等 FSM 回 Idle
    for (int i = 0; i < 2000 && pf_sig_value(0, 0) != 0; i++) pf_step(10);
    pf_step(50);
    g_cur_ir = -1;
}

// ---- 白盒 API ----
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
int pf_tap_state(void) { return tap_state(); }
void pf_final(void) { if (dut) { dut->final(); delete dut; dut = nullptr; rootp = nullptr; } }

} // extern "C"

// ---------------------------------------------------------------------------
// 自检: IDCODE / DMI 读写 / dmstatus.authenticated
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    // PF_VCD=1 时抓 DMI 事务波形
    printf("[harness] init...\n");
    pf_init(0);
#if VM_TRACE
    if (getenv("PF_VCD") && dut) {
        g_tfp = new VerilatedVcdC;
        dut->trace(g_tfp, 99);
        g_tfp->open("/workspace/pickerfuzz/perip/rv_dm-ctf/obj_so/rv_dm.vcd");
        g_tfp->dump(g_time);
    }
#endif
    printf("[harness] signals bound: %d\n", pf_sig_count());

    uint32_t id = pf_read_idcode();
    printf("[harness] IDCODE = 0x%08x (expect 0x04f54847)\n", id);

    // clear_error 仅在 err!=0 时调用，避免 dmihardreset 清掉后续事务
    int err = pf_dmi_write(0x10, 0xA5A5A5A5);  // DMControl
    uint32_t dmc = pf_dmi_read(0x10);
    printf("[harness] write rc=%d dmcontrol_q=0x%08x readback=0x%08x\n",
           err, pf_sig_value(5, 0), dmc);

    bool ok = (id == 0x04f54847u) && (dmc == 0x1u);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
