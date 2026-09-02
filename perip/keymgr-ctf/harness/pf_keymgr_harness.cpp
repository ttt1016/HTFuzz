// PickerFuzz keymgr C harness (no-timing, C-side full manual drive)
#include <cstdio>
#include <cstdint>
#include "svdpi.h"
#include "Vkeymgr_perip_tb.h"
#include "Vkeymgr_perip_tb___024root.h"
#include "Vkeymgr_perip_tb__Dpi.h"

static Vkeymgr_perip_tb* dut = nullptr;

// TLUL host 状态（C 侧维护）
struct TlHost {
  int a_valid = 0;
  int a_opcode = 0;
  unsigned a_address = 0;
  unsigned a_data = 0;
  unsigned a_mask = 0xF;
  unsigned a_user = 0; // 简化: intg 由 SV 侧函数算（见下）
  int d_ready = 0;
} tl;

extern "C" {

// 白盒 DPI imports（SV export）
int pf_wb_aes_key_en(void);
int pf_wb_aes_key_word(int idx);
int pf_wb_kmac_key_en(void);
int pf_wb_kmac_key_word(int idx);
int pf_wb_otbn_key_en(void);
int pf_wb_otbn_key_word(int idx);
int pf_wb_state(void);
int pf_wb_op_done(void);
int pf_wb_key_state_word(int cdi, int share, int word);
int pf_wb_d_error(void);
int pf_wb_d_valid(void);
int pf_wb_a_ready(void);
int pf_wb_d_data(void);
int pf_wb_clk_cnt(void);
void pf_tl_set_cmd(int opcode, int addr, int data, int auser);
void pf_tl_clear(void);
void pf_tl_set_dready(int v);

// SV 侧 intg 计算函数（Dpi.h 已声明）

static void eval2() {
  dut->eval();
  dut->eval();
}

void pf_set_dut(void* p) { dut = (Vkeymgr_perip_tb*)p; }

void pf_tick(int half_cycles) {
  if (!dut) return;
  for (int i = 0; i < half_cycles; i++) {
    dut->rootp->keymgr_perip_tb__DOT__clk = !dut->rootp->keymgr_perip_tb__DOT__clk;
    dut->rootp->keymgr_perip_tb__DOT__clk_edn = dut->rootp->keymgr_perip_tb__DOT__clk;
    eval2();
  }
}

// ---- pf_* API ----
void pf_init(void) {
  if (!dut) {
    dut = new Vkeymgr_perip_tb();
    svScope scope = svGetScopeFromName("TOP.keymgr_perip_tb");
    if (!scope) scope = svGetScopeFromName("keymgr_perip_tb");
    if (scope) svSetScope(scope);
    // 初始复位
    dut->rootp->keymgr_perip_tb__DOT__rst_n = 0;
    dut->rootp->keymgr_perip_tb__DOT__rst_shadowed_n = 0;
    dut->rootp->keymgr_perip_tb__DOT__rst_edn_n = 0;
    pf_tick(10);
  }
}

void pf_reset(void) {
  if (!dut) pf_init();
  dut->rootp->keymgr_perip_tb__DOT__rst_n = 0;
  dut->rootp->keymgr_perip_tb__DOT__rst_shadowed_n = 0;
  dut->rootp->keymgr_perip_tb__DOT__rst_edn_n = 0;
  pf_tick(10);
  dut->rootp->keymgr_perip_tb__DOT__rst_n = 1;
  dut->rootp->keymgr_perip_tb__DOT__rst_shadowed_n = 1;
  dut->rootp->keymgr_perip_tb__DOT__rst_edn_n = 1;
  pf_tick(10);
}

void pf_step(int n) { pf_tick(2 * n); }

// TLUL 写（带真实 intg，经 SV DPI 函数驱动）
void pf_write(uint32_t addr, uint32_t data) {
  if (!dut) pf_init();
  unsigned a_user = (unsigned)pf_calc_cmd_intg(1 /*PutFullData*/, (int)addr, 0xF);
  pf_tl_set_cmd(1, (int)addr, (int)data, (int)a_user);
  for (int i = 0; i < 1000; i++) {
    pf_tick(2);
    if (pf_wb_a_ready()) break;
  }
  // 等 a_ack 完成（a_ready 高时 a_valid 保持一拍）
  pf_tick(2);
  pf_tl_clear();
  // 等 d_valid（写响应）
  for (int i = 0; i < 1000; i++) {
    pf_tick(2);
    if (pf_wb_d_valid()) break;
  }
  pf_tick(2);
}

uint32_t pf_read(uint32_t addr) {
  if (!dut) pf_init();
  unsigned a_user = (unsigned)pf_calc_cmd_intg(4 /*Get*/, (int)addr, 0xF);
  pf_tl_set_cmd(4, (int)addr, 0, (int)a_user);
  for (int i = 0; i < 1000; i++) {
    pf_tick(2);
    if (pf_wb_a_ready()) break;
  }
  pf_tick(2);
  pf_tl_clear();
  uint32_t result = 0;
  for (int i = 0; i < 1000; i++) {
    pf_tick(2);
    if (pf_wb_d_valid()) { result = (uint32_t)pf_wb_d_data(); break; }
  }
  pf_tick(2);
  return result;
}

int pf_sig_count(void) { return 10; }
const char* pf_sig_name(int i) {
  static const char* names[] = {
    "aes_key_en", "aes_key_word", "kmac_key_en", "kmac_key_word",
    "otbn_key_en", "otbn_key_word", "state", "op_done",
    "key_state_word", "d_error"
  };
  if (i >= 0 && i < 10) return names[i];
  return "";
}
int pf_sig_words(int i) { return 1; }
uint32_t pf_sig_read_idx(int sig, int idx);
uint32_t pf_sig_read(const char* name, int w) {
  // 字符串接口：映射到数字接口
  if (strstr(name, "state") && !strstr(name, "fsm")) return pf_sig_read_idx(6, 0);
  if (strstr(name, "op_done")) return pf_sig_read_idx(7, 0);
  if (strstr(name, "key_state")) return pf_sig_read_idx(8, w);
  if (strstr(name, "aes_key")) return pf_sig_read_idx(1, w);
  if (strstr(name, "kmac_key")) return pf_sig_read_idx(3, w);
  if (strstr(name, "otbn_key")) return pf_sig_read_idx(5, w);
  if (strstr(name, "d_error")) return pf_sig_read_idx(9, 0);
  return 0;
}
uint32_t pf_sig_read_idx(int sig, int idx) {
  switch (sig) {
    case 0: return (uint32_t)pf_wb_aes_key_en();
    case 1: return (uint32_t)pf_wb_aes_key_word(idx);
    case 2: return (uint32_t)pf_wb_kmac_key_en();
    case 3: return (uint32_t)pf_wb_kmac_key_word(idx);
    case 4: return (uint32_t)pf_wb_otbn_key_en();
    case 5: return (uint32_t)pf_wb_otbn_key_word(idx);
    case 6: return (uint32_t)pf_wb_state();
    case 7: return (uint32_t)pf_wb_op_done();
    case 8: return (uint32_t)pf_wb_key_state_word(idx & 0xF, (idx >> 4) & 0xF, (idx >> 8) & 0xF);
    case 9: return (uint32_t)pf_wb_d_error();
    case 10: return (uint32_t)pf_wb_d_valid();
    case 11: return (uint32_t)pf_wb_a_ready();
    case 12: return (uint32_t)pf_wb_d_data();
    case 13: return (uint32_t)pf_wb_clk_cnt();
    default: return 0;
  }
}
} // extern "C"
