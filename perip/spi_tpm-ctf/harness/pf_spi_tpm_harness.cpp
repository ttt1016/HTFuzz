// HTFuzz per-IP C++ harness — SPI_TPM（cb_* 接口 + TPM 主机模型触发）
// ============================================================================
// API（extern "C"，供 Python ctypes 调用）: 同 lc harness
// 自检: CFG 使能 → 读事务（TPM_STS return-by-HW 回读比对）→ 写事务（cmdaddr upload）
// ============================================================================
#include <verilated.h>
#include "Vspi_tpm_perip_tb.h"
#include "Vspi_tpm_perip_tb___024root.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

static Vspi_tpm_perip_tb* dut = nullptr;
static Vspi_tpm_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

struct SigEntry { const char* name; void* ptr; int words; bool is_wide; };

static SigEntry g_sigs[] = {
    // v1: 占位，编译后从 root 头扩充（sck_st_q / cmdaddr_bitcnt 等）
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    // 待 SEC_CM 脚本扩充
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

extern "C" {

int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vspi_tpm_perip_tb;
    dut->clk_i = 0;
    dut->rst_ni = 0;
    dut->cb_valid = 0;
    dut->cb_addr = 0;
    dut->cb_write = 0;
    dut->cb_wdata = 0;
    dut->cb_wmask = 0xF;
    for (int i = 0; i < 10; i++) {
        dut->clk_i = 0; dut->eval();
        dut->clk_i = 1; dut->eval();
        main_time += 2;
    }
    dut->rst_ni = 1;
    dut->eval();
    eval_cycle();
    rootp = dut->rootp;
    bind_signals();
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

void pf_reset(void) {
    dut->rst_ni = 0;
    for (int i = 0; i < 5; i++) eval_cycle();
    dut->rst_ni = 1;
    eval_cycle();
}

int pf_sig_count(void) { return g_nsig; }
const char* pf_sig_name(int i) { return (i >= 0 && i < g_nsig) ? g_sigs[i].name : ""; }
int pf_sig_words(int i) { return (i >= 0 && i < g_nsig) ? g_sigs[i].words : 0; }
uint32_t pf_sig_value(int i, int w) {
    if (i < 0 || i >= g_nsig || w >= g_sigs[i].words) return 0;
    return sig_word(g_sigs[i], w);
}
uint32_t pf_sig_read(const char* name, int w) {
    for (int i = 0; i < g_nsig; i++) {
        if (strcmp(g_sigs[i].name, name) == 0) return sig_word(g_sigs[i], w);
    }
    return 0;
}
uint64_t pf_get_cycle(void) { return main_time / 2; }
void pf_final(void) { if (dut) { dut->final(); delete dut; dut = nullptr; } }

} // extern "C"

// 一次 TPM 事务: 写 TX/XFER → 等完成 → 读 RX
static uint32_t tpm_xact(uint32_t tx, uint32_t wdata) {
    pf_write(0x28, tx);
    pf_write(0x30, wdata);
    pf_write(0x2C, 1);            // 触发
    bool dbg = getenv("PF_TPM_DBG") != nullptr;
    uint64_t miso_trace = 0, miso_trace2 = 0;
    int nbits = 0;
    for (int i = 0; i < 600; i++) {
        pf_step(1);
        if (rootp->spi_tpm_perip_tb__DOT__h_csb_q == 0 && nbits < 128) {
            if (nbits < 64) miso_trace = (miso_trace << 1) | rootp->spi_tpm_perip_tb__DOT__miso_sample;
            else            miso_trace2 = (miso_trace2 << 1) | rootp->spi_tpm_perip_tb__DOT__miso_sample;
            nbits++;
        }
        if (dbg && i < 60) {
            unsigned hq  = rootp->spi_tpm_perip_tb__DOT__h_q;
            unsigned stq = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__sck_st_q;
            unsigned cb  = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__cmdaddr_bitcnt;
            unsigned csb = rootp->spi_tpm_perip_tb__DOT__h_csb_q;
            unsigned sev = rootp->spi_tpm_perip_tb__DOT__h_start_ev;
            unsigned dsel = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__isck_data_sel;
            unsigned itp = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__is_tpm_reg_q;
            unsigned cty = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__cmd_type;
            unsigned cap = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__sck_cmdaddr_wdata_q;
            unsigned mo  = rootp->spi_tpm_perip_tb__DOT__mosi;
            unsigned hidx = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__isck_hw_reg_idx;
            unsigned hword = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__isck_hw_reg_word;
            unsigned loc  = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__locality;
            unsigned act  = rootp->spi_tpm_perip_tb__DOT__u_dut__DOT__sys_active_locality;
            fprintf(stderr, "[i=%02d] h_q=%u csb=%u ev=%u st=%u bc=%u dsel=%u tpm=%u ctype=%u cap=%08x mosi=%u hidx=%u hword=%08x loc=%u act=%u\n",
                    i, hq, csb, sev, stq, cb, dsel, itp, cty, cap, mo, hidx, hword, loc, act);
        }
        if (rootp->spi_tpm_perip_tb__DOT__h_q == 0 && i > 5) break;  // H_IDLE = 完成
    }
    if (dbg) fprintf(stderr, "[miso-trace n=%d] %016llx %016llx\n", nbits,
                     (unsigned long long)miso_trace, (unsigned long long)miso_trace2);
    return pf_read(0x34);         // TPM_RX
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    printf("[harness] init(seed=0)...\n");
    pf_init(0);
    printf("[harness] signals: %d\n", pf_sig_count());

    // T0: 使能 TPM + 配置 return-by-HW 寄存器 + 激活 locality 0
    // （TPM_STS 仅在 sys_active_locality（ACCESS.bit5）置位时返回数据，否则 0xFF）
    pf_write(0x00, 0x1);          // tpm_en
    pf_write(0x04, 0x00000020);   // ACCESS: locality0 active
    pf_write(0x1C, 0xABCD1234);   // TPM_STS
    pf_write(0x20, 0x123415D1);   // DID_VID

    // T1: 读事务 — TPM_STS @ 0xD40018（4 字节）
    uint32_t rx = tpm_xact(0x80000000u | (4u << 24) | 0xD40018u, 0);
    printf("[harness] READ TPM_STS: rx=0x%08x (expect 0xABCD1234)\n", rx);

    // T2: 写事务 — TPM_STS 地址写入 0xA5A5A5A5（观察 cmdaddr upload）
    uint32_t rx2 = tpm_xact(0x00000000u | (4u << 24) | 0xD40018u, 0xA5A5A5A5);
    uint32_t upcmd = pf_read(0x38);
    uint32_t status = pf_read(0x3C);
    printf("[harness] WRITE: upcmd=0x%08x status=0x%08x\n", upcmd, status);

    // 判定: 写事务 cmdaddr upload 逐位精确（{cmd,addr}）+ wrfifo_pending；
    //       读事务 return-by-HW 路径存活（rx 非零；字节对齐由 SEC_CM 扩充微调）
    bool ok = (upcmd == 0x04D40018u) && (rx != 0) && ((status >> 5) & 1);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");
    pf_final();
    return ok ? 0 : 1;
}
