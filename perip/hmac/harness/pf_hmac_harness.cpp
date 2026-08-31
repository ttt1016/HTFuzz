// PickerFuzz per-IP C++ harness — HMAC (M5-4: 双种子 + op 粒度快照 + 白盒信号)
// ============================================================================
// API（extern "C"，供 Python ctypes 调用）:
//   pf_init(seed)              初始化（seed: 0=全零, 2=随机, 其他=随机种子）
//   pf_write(addr, data, mask) TL-UL 写
//   pf_read(addr) -> u32       TL-UL 读
//   pf_step(n)                 推进 n 拍
//   pf_poll(addr, mask, expect, max) -> n
//   pf_reset()                 复位（保持种子）
//   pf_snapshot() -> n         op 粒度快照: 全量内部信号 → 内部缓冲
//   pf_sig_count() -> n        信号总数
//   pf_sig_name(i) -> str      信号名
//   pf_sig_value(i, w) -> u32  信号第 w 个 32bit 字
//   pf_sig_words(i) -> n       信号字数
//   pf_sig_read(name, w) -> u32      按名读
//   pf_snap_value(s, i, w)     快照 s 中信号 i 的第 w 字
//   pf_snap_diff(a, b) -> n    两快照差异字数
// 自检 main: 默认; --bench 加吞吐
// ============================================================================
#include <verilated.h>
#include "Vhmac_perip_tb.h"
#include "Vhmac_perip_tb___024root.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

static Vhmac_perip_tb* dut = nullptr;
static Vhmac_perip_tb___024root* rootp = nullptr;
static uint64_t main_time = 0;

// ---------------------------------------------------------------------------
// 白盒信号表（op 粒度快照；安全关键信号优先——密钥残留扫描目标）
// ---------------------------------------------------------------------------
struct SigEntry {
    const char* name;
    void* ptr;
    int words;      // 32bit 字数
    bool is_wide;   // VlWide
};


static SigEntry g_sigs[] = {
    // --- 安全关键: 密钥/摘要/中间状态（O3-③ zeroize 等价扫描目标）---
    {"u_dut.secret_key",   nullptr, 32, true},   // 1024bit 密钥寄存器
    {"u_dut.secret_key_d", nullptr, 32, true},
    {"sha2.hash_q",        nullptr, 16, true},   // 512bit SHA 状态
    {"sha2.hash_d",        nullptr, 16, true},
    {"sha2.digest_q",      nullptr, 16, true},
    {"sha2.digest_d",      nullptr, 16, true},
    {"sha2.w_q",           nullptr, 16, true},   // 消息调度中间值
    // --- 控制状态（O4 转移模式目标）---
    {"u_dut.cfg_reg",                 nullptr, 1, false},
    {"u_dut.cfg_block",               nullptr, 1, false},
    {"u_dut.hash_start",              nullptr, 1, false},
    {"u_dut.hash_continue",           nullptr, 1, false},
    {"u_dut.hash_start_active",       nullptr, 1, false},
    {"u_dut.done_state_q",            nullptr, 1, false},
    {"u_dut.fifo_empty_q",            nullptr, 1, false},
    {"u_dut.fifo_full_q",             nullptr, 1, false},
    {"u_dut.fifo_full_seen_q",        nullptr, 1, false},
    {"u_dut.message_length",          nullptr, 2, false},
    {"u_dut.message_length_d",        nullptr, 2, false},
    {"u_dut.msg_allowed",             nullptr, 1, false},
    {"u_dut.msg_push_not_allowed",    nullptr, 1, false},
    {"u_dut.invalid_config",          nullptr, 1, false},
    {"u_dut.invalid_config_atstart",  nullptr, 1, false},
    {"u_dut.digest_size_started_q",   nullptr, 1, false},
    {"u_dut.reg_hash_done",           nullptr, 1, false},
    {"u_dut.sha_hash_start",          nullptr, 1, false},
    {"u_dut.sha_hash_process",        nullptr, 1, false},
    {"u_dut.sha_hash_continue",       nullptr, 1, false},
    {"u_dut.sha_hash_done",           nullptr, 1, false},
    {"u_dut.update_seckey_inprocess", nullptr, 1, false},
    {"u_dut.digest_on_blk",           nullptr, 1, false},
    {"u_dut.hmac_fifo_wsel",          nullptr, 1, false},
    {"u_dut.hmac_fifo_wvalid",        nullptr, 1, false},
    {"u_dut.hmac_fifo_wdata_sel",     nullptr, 1, false},
    {"u_dut.fifo_wdata",              nullptr, 1, false},
    {"u_dut.fifo_rvalid",             nullptr, 1, false},
    {"u_dut.shaf_rvalid",             nullptr, 1, false},
};
static const int g_nsig = sizeof(g_sigs) / sizeof(g_sigs[0]);

static void bind_signals() {
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (strcmp(n, "u_dut.secret_key") == 0)                p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__secret_key;
        else if (strcmp(n, "u_dut.secret_key_d") == 0)         p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__secret_key_d;
        else if (strcmp(n, "sha2.hash_q") == 0)                p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__u_prim_sha2_512__DOT__gen_multimode_logic__DOT__u_prim_sha2_multimode__DOT__gen_multimode__DOT__hash_q;
        else if (strcmp(n, "sha2.hash_d") == 0)                p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__u_prim_sha2_512__DOT__gen_multimode_logic__DOT__u_prim_sha2_multimode__DOT__gen_multimode__DOT__hash_d;
        else if (strcmp(n, "sha2.digest_q") == 0)              p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__u_prim_sha2_512__DOT__gen_multimode_logic__DOT__u_prim_sha2_multimode__DOT__gen_multimode__DOT__digest_q;
        else if (strcmp(n, "sha2.digest_d") == 0)              p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__u_prim_sha2_512__DOT__gen_multimode_logic__DOT__u_prim_sha2_multimode__DOT__gen_multimode__DOT__digest_d;
        else if (strcmp(n, "sha2.w_q") == 0)                   p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__u_prim_sha2_512__DOT__gen_multimode_logic__DOT__u_prim_sha2_multimode__DOT__gen_multimode__DOT__w_q;
        else if (strcmp(n, "u_dut.cfg_reg") == 0)              p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__cfg_reg;
        else if (strcmp(n, "u_dut.cfg_block") == 0)            p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__cfg_block;
        else if (strcmp(n, "u_dut.hash_start") == 0)           p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__hash_start;
        else if (strcmp(n, "u_dut.hash_continue") == 0)        p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__hash_continue;
        else if (strcmp(n, "u_dut.hash_start_active") == 0)    p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__hash_start_active;
        else if (strcmp(n, "u_dut.done_state_q") == 0)         p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__done_state_q;
        else if (strcmp(n, "u_dut.fifo_empty_q") == 0)         p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__fifo_empty_q;
        else if (strcmp(n, "u_dut.fifo_full_q") == 0)          p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__fifo_full_q;
        else if (strcmp(n, "u_dut.fifo_full_seen_q") == 0)     p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__fifo_full_seen_q;
        else if (strcmp(n, "u_dut.message_length") == 0)       p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__message_length;
        else if (strcmp(n, "u_dut.message_length_d") == 0)     p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__message_length_d;
        else if (strcmp(n, "u_dut.msg_allowed") == 0)          p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__msg_allowed;
        else if (strcmp(n, "u_dut.msg_push_not_allowed") == 0) p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__msg_push_not_allowed;
        else if (strcmp(n, "u_dut.invalid_config") == 0)       p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__invalid_config;
        else if (strcmp(n, "u_dut.invalid_config_atstart") == 0) p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__invalid_config_atstart;
        else if (strcmp(n, "u_dut.digest_size_started_q") == 0) p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__digest_size_started_q;
        else if (strcmp(n, "u_dut.reg_hash_done") == 0)        p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__reg_hash_done;
        else if (strcmp(n, "u_dut.sha_hash_start") == 0)       p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__sha_hash_start;
        else if (strcmp(n, "u_dut.sha_hash_process") == 0)     p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__sha_hash_process;
        else if (strcmp(n, "u_dut.sha_hash_continue") == 0)    p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__sha_hash_continue;
        else if (strcmp(n, "u_dut.sha_hash_done") == 0)        p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__sha_hash_done;
        else if (strcmp(n, "u_dut.update_seckey_inprocess") == 0) p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__update_seckey_inprocess;
        else if (strcmp(n, "u_dut.digest_on_blk") == 0)        p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__digest_on_blk;
        else if (strcmp(n, "u_dut.hmac_fifo_wsel") == 0)       p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__hmac_fifo_wsel;
        else if (strcmp(n, "u_dut.hmac_fifo_wvalid") == 0)     p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__hmac_fifo_wvalid;
        else if (strcmp(n, "u_dut.hmac_fifo_wdata_sel") == 0)  p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__hmac_fifo_wdata_sel;
        else if (strcmp(n, "u_dut.fifo_wdata") == 0)           p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__fifo_wdata;
        else if (strcmp(n, "u_dut.fifo_rvalid") == 0)          p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__fifo_rvalid;
        else if (strcmp(n, "u_dut.shaf_rvalid") == 0)          p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__shaf_rvalid;
        g_sigs[i].ptr = p;
    }
}

static uint32_t sig_word(const SigEntry& s, int w) {
    if (!s.ptr) return 0;
    if (s.is_wide) {
        uint32_t* words = reinterpret_cast<uint32_t*>(s.ptr);
        return words[w];
    }
    // 单字信号是 CData/SData（1-2 字节），按 uint8 读避免越界拼合
    uint8_t* bytes = reinterpret_cast<uint8_t*>(s.ptr);
    return bytes[0];
}

static void eval_cycle() {
    dut->clk_i = 0; dut->eval();
    dut->clk_i = 1; dut->eval();
    main_time += 10;
}

// 快照缓冲（op 粒度）
struct Snapshot { std::vector<uint32_t> data; };
static std::vector<Snapshot> g_snaps;

static void take_snapshot() {
    Snapshot s;
    for (int i = 0; i < g_nsig; i++) {
        for (int w = 0; w < g_sigs[i].words; w++) {
            s.data.push_back(sig_word(g_sigs[i], w));
        }
    }
    g_snaps.push_back(std::move(s));
}

extern "C" {

int pf_init(unsigned seed) {
    if (dut) { dut->final(); delete dut; }
    g_snaps.clear();
    // randReset: 0=全零, 2=随机（seed>2 时同时固定 randSeed 保证可复现）
    Verilated::threadContextp()->randReset(seed == 0 ? 0 : 2);
    if (seed > 2) Verilated::threadContextp()->randSeed(seed);
    dut = new Vhmac_perip_tb;
    rootp = dut->rootp;
    bind_signals();
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
    take_snapshot();   // 复位后基线快照
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
    take_snapshot();   // op 粒度快照
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
        for (int w = 0; w < g_sigs[i].words; w++) {
            if (g_snaps[a].data[off + w] != g_snaps[b].data[off + w]) diff++;
        }
        off += g_sigs[i].words;
    }
    return diff;
}

uint64_t pf_get_cycle(void) { return main_time / 2; }

void pf_final(void) {
    if (dut) { dut->final(); delete dut; dut = nullptr; rootp = nullptr; }
}

} // extern "C"

// ---------------------------------------------------------------------------
// 自检 main: O1-lite + O2 NIST + O3-③ 密钥残留扫描演示 + 快照差异
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    bool do_bench = (argc > 1 && strcmp(argv[1], "--bench") == 0);

    printf("[harness] init(seed=0)...\n");
    pf_init(0);
    printf("[harness] signals bound: %d, snapshot words: %d\n",
           pf_sig_count(), (int)g_snaps[0].data.size());

    // O1-lite: 复位值
    uint32_t st = pf_read(0x18);
    printf("[harness] STATUS(reset) = 0x%08x (expect 0x3)\n", st);

    // O2: 完整 SHA256
    pf_write(0x10, 0x422);
    pf_write(0x14, 0x1);
    for (int w = 0; w < 8; w++) pf_write(0x1000, 0x61616161u);
    pf_write(0xE4, 256);
    pf_write(0x14, 0x2);
    int waited = pf_poll(0x0, 0x1, 0x1, 100000);
    pf_write(0x0, 0x1);
    uint32_t d0 = pf_read(0xA4);
    printf("[harness] SHA256 done after %d polls, DIGEST[0]=0x%08x (expect 0x3ba3f5f4)\n", waited, d0);

    // O3-③ 密钥残留扫描演示: 写 KEY[7] → 白盒读 → wipe → 白盒读
    pf_write(0x24 + 7*4, 0xDEADBEEF);   // KEY[7]
    uint32_t key7 = pf_sig_read("u_dut.secret_key", 24);  // KEY[7] -> secret_key[24] (31-7)
    printf("[harness] secret_key[24] after KEY[7] write = 0x%08x (expect 0xdeadbeef)\n", key7);
    pf_write(0x20, 0xFFFFFFFF);   // WIPE_SECRET
    uint32_t key7_after = pf_sig_read("u_dut.secret_key", 24);
    printf("[harness] secret_key[24] after wipe = 0x%08x (expect 0xffffffff)\n", key7_after);

    // 快照差异
    printf("[harness] snapshot diff(reset vs final) = %d words\n", pf_snap_diff(0, pf_snap_count() - 1));

    bool ok = (st == 0x3u) && (d0 == 0x3ba3f5f4u) &&
              (key7 == 0xdeadbeefu) && (key7_after == 0xFFFFFFFFu);
    printf("[harness] SELF-TEST %s\n", ok ? "PASS" : "FAIL");

    if (do_bench) {
        clock_t t0 = clock();
        const int N = 1000;
        for (int i = 0; i < N; i++) pf_read(0x18);
        clock_t t1 = clock();
        double secs = double(t1 - t0) / CLOCKS_PER_SEC;
        printf("[bench] %d reads (with snapshot) in %.3fs => %.0f ops/s\n", N, secs, N / secs);
    }
    pf_final();
    return ok ? 0 : 1;
}
