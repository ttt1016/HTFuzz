// OT-SecFuzz-v2 Common Header — auto-merged by run.sh
// Only defines BASE addresses and compatibility macros.

#define AES_BASE       0x41100000
#define HMAC_BASE      0x41110000
#define KMAC_BASE      0x41120000
#define OTBN_BASE      0x41130000
#define KEYMGR_BASE    0x41140000
#define CSRNG_BASE     0x41150000
#define ES_BASE        0x41160000
#define ENTROPY_SRC_BASE 0x41160000
#define SRAM_BASE      0x411C0000
#define SRAM_CTRL_BASE 0x411C0000
#define ROM_BASE       0x411E0000
#define ROM_CTRL_BASE  0x411E0000
#define FLASH_BASE     0x41000000
#define OTP_BASE       0x40130000
#define LC_BASE        0x40140000
#define AH_BASE        0x40150000
#define AON_TIMER_BASE 0x40470000
#define RV_TIMER_BASE  0x40100000
#define RV_DM_BASE     0x40110000
#define PWRMGR_BASE    0x40400000
#define RSTMGR_BASE    0x40410000
#define CLKMGR_BASE    0x40420000
#define PATTGEN_BASE   0x404E0000
#define UART0_BASE     0x40000000
#define GPIO_BASE      0x40040000
#define SPI_BASE       0x40050000
#define SPI_DEVICE_BASE 0x40050000
#define SPI_HOST0_BASE 0x40060000
#define I2C0_BASE      0x40080000
#define I2C1_BASE      0x40090000
#define I2C2_BASE      0x400A0000
#define USBDEV_BASE    0x40120000
#define DMA_BASE       0x40160000
#define ASCON_BASE     0x40170000
#define ADC_CTRL_BASE  0x40440000
#define SENSOR_CTRL_BASE 0x40490000
#define SYSRST_CTRL_BASE 0x40450000
#define PWM_BASE       0x404A0000
#define EDN_BASE       0x41170000
#define IBEX_BASE      0x40180000

/* Step macros */
#define INJ_STEP(id, name, code) do { LOG_INFO("===== [INJ-%02d] %s =====", id, name); LOG_INFO("  RTL: %s", code); } while(0)
#define DFT_STEP(id, name, code) do { LOG_INFO("===== [DFT-%02d] %s =====", id, name); LOG_INFO("  RTL: %s", code); } while(0)
#define PRB_STEP(id, name, code) do { LOG_INFO("===== [PRB-%02d] %s =====", id, name); LOG_INFO("  RTL: %s", code); } while(0)
#define FUZZ_STEP(id, name, code) do { LOG_INFO("===== [FUZZ-%02d] %s =====", id, name); LOG_INFO("  RTL: %s", code); } while(0)
#define CVE_STEP(id, name, code) do { LOG_INFO("===== [CVE-%03d] %s =====", id, name); LOG_INFO("  RTL: %s", code); } while(0)

/* Result macros */
#define INJ_PASS(id, msg)  LOG_INFO("  [INJ-%02d PASS] %s", id, msg)
#define INJ_FAIL(id, msg)  LOG_INFO("  [INJ-%02d FAIL] %s", id, msg)
#define DFT_PASS(id, msg)  LOG_INFO("  [DFT-%02d PASS] %s", id, msg)
#define DFT_LEAK(id, msg)  LOG_INFO("  [DFT-%02d LEAK] %s", id, msg)
#define PRB_OK(id, msg)    LOG_INFO("  [PRB-%02d OK] %s", id, msg)
#define PRB_ANOM(id, msg)  LOG_INFO("  [PRB-%02d ANOMALY] %s", id, msg)
#define PROBE_OK(id, msg)  LOG_INFO("  [PROBE-%02d OK] %s", id, msg)
#define PROBE_ANOM(id, msg) LOG_INFO("  [PROBE-%02d ANOMALY] %s", id, msg)
#define PROBE_STEP(id, name, code) do { LOG_INFO("===== [PROBE-%02d] %s =====", id, name); LOG_INFO("  RTL: %s", code); } while(0)
#define PROBE_LOG(id, addr, exp, act) LOG_INFO("  [PROBE-%02d ANOMALY] @0x%08x exp=0x%08x act=0x%08x", id, addr, exp, act)
#define FUZZ_PASS(id, msg) LOG_INFO("  [FUZZ-%02d PASS] %s", id, msg)
#define FUZZ_FAIL(id, msg) LOG_INFO("  [FUZZ-%02d FAIL] %s", id, msg)
#define CVE_PASS(id, msg)  LOG_INFO("  [CVE-%03d NOT_PRESENT] %s", id, msg)
#define CVE_CONFIRMED(id, msg) LOG_INFO("  [CVE-%03d CONFIRMED] %s", id, msg)

/* Log macros */
#define INJ_LOG(id, addr, exp, act) LOG_INFO("  [INJ-%02d VIOLATION] @0x%08x exp=0x%08x act=0x%08x", id, addr, exp, act)
#define DFT_LOG(id, addr, exp, act) LOG_INFO("  [DFT-%02d LEAK] @0x%08x exp=0x%08x act=0x%08x", id, addr, exp, act)
#define PRB_LOG(id, addr, exp, act) LOG_INFO("  [PRB-%02d ANOMALY] @0x%08x exp=0x%08x act=0x%08x", id, addr, exp, act)
#define FUZZ_LOG(id, addr, exp, act) LOG_INFO("  [FUZZ-%02d VIOLATION] @0x%08x exp=0x%08x act=0x%08x", id, addr, exp, act)
#define CVE_LOG(id, addr, exp, act)  LOG_INFO("  [CVE-%03d CONFIRMED] @0x%08x exp=0x%08x act=0x%08x", id, addr, exp, act)

/* Summary macros */
#define inj_print_summary() LOG_INFO("=== INJ SUMMARY: done ===")
#define dft_print_summary() LOG_INFO("=== DFT SUMMARY: done ===")
#define prb_print_summary() LOG_INFO("=== PRB SUMMARY: done ===")
#define fuzz_print_summary() LOG_INFO("=== FUZZ SUMMARY: done ===")
#define cve_print_summary() LOG_INFO("=== CVE SUMMARY: done ===")

#define DFT_PATTERN_A 0xDEADBEEF
#define DFT_PATTERN_B 0xCAFEBABE
#define DFT_PATTERN_C 0xBAADF00D
#define DFT_PATTERN_D 0xFEEDFACE
#define SEEDS_SIZE 8
#define SEED_CNT  16

/* Old SEEDS array — used by some legacy tests */
__attribute__((unused)) static const uint32_t SEEDS[16] = {
  0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321,
  0x00000000, 0xFFFFFFFF, 0xAAAAAAAA, 0x55555555,
  0xBAADF00D, 0xFEEDFACE, 0x8BADF00D, 0xFEEDBEEF,
  0x00000001, 0xFFFFFFFE, 0x7FFFFFFF, 0x80000000,
};

/* Missing string literals from old common headers */
#define CSR_READ(str)  str
#define SEEDS_CNT 16

__attribute__((unused)) static uint32_t s_violations;
__attribute__((unused)) static uint32_t s_anomalies;
__attribute__((unused)) static uint32_t s_confirmed;
__attribute__((unused)) static uint32_t s_logc;
__attribute__((unused)) static uint32_t s_tid[512];
__attribute__((unused)) static uint32_t s_addr[512];
__attribute__((unused)) static uint32_t s_exp[512];
__attribute__((unused)) static uint32_t s_act[512];

/* Hardware MMIO helpers */
static inline uint32_t rd(uint32_t a) {
  return mmio_region_read32(mmio_region_from_addr(a), 0);
}
static inline void wr(uint32_t a, uint32_t v) {
  mmio_region_write32(mmio_region_from_addr(a), 0, v);
}
