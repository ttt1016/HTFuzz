#!/bin/bash
# ============================================================================
# HTFuzz Runner — 在 opentitan-fresh 中构建并运行变异固件
# 复用已验证的 Verilator 5.050 仿真环境（含 TL-UL monitor）
#
# 用法:
#   ./pickerfuzz_runner.sh            # 运行 manifest.json 中全部变异
#   ./pickerfuzz_runner.sh 3          # 只运行 mut_id=3
# ============================================================================
set +e

PF_DIR="/workspace/pickerfuzz"
OT_DIR="/workspace/opentitan-fresh"
OUT_DIR="$PF_DIR/fuzz/out"
LOG_DIR="$PF_DIR/fuzz/logs"
TESTS_DIR="$OT_DIR/sw/device/tests/pickerfuzz_tests"

VERILATOR_BIN=/tools/verilator/v5.050/bin
TOOLCHAIN=/tools/lowrisc-toolchain-rv32imcb-x86_64-20260224-1/bin

mkdir -p "$LOG_DIR"

GREEN='\033[0;32m' RED='\033[0;31m' CYAN='\033[0;36m' NC='\033[0m' BOLD='\033[1m'

# 只运行指定 id（可选）
ONLY_ID="$1"

# 读取 manifest
if [ ! -f "$OUT_DIR/manifest.json" ]; then
    echo -e "${RED}错误: $OUT_DIR/manifest.json 不存在。先运行 fuzz_engine.py${NC}"
    exit 1
fi

IDS=$(python3 -c "
import json
m = json.load(open('$OUT_DIR/manifest.json'))
for e in m:
    if '$ONLY_ID' == '' or str(e['id']) == '$ONLY_ID':
        print(e['id'], e['target'])
")

total=0; pass=0; vuln=0; fail=0

while read -r mid target; do
    [ -z "$mid" ] && continue
    total=$((total+1))
    echo ""
    echo -e "${BOLD}===== HTFuzz #$mid: $target =====${NC}"

    # Step 1: 部署固件源码（合并公共头文件，同 run.sh 机制）
    rm -rf "$TESTS_DIR"
    mkdir -p "$TESTS_DIR"
    {
        cat > /tmp/pf_syshdr.c << 'SYSHDR'
#include <stdint.h>
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

SYSHDR
        cat /tmp/pf_syshdr.c
        cat "$PF_DIR/scripts/include/ot_secfuzz.h" "$OUT_DIR/${target}.c" | sed \
            -e '/^#include "ot_secfuzz.h"/d' \
            -e '/^OTTF_DEFINE_TEST_CONFIG/d'
        echo ""
        echo "OTTF_DEFINE_TEST_CONFIG();"
    } > "$TESTS_DIR/${target}.c"

    # Step 2: 写 BUILD 文件
    cat > "$TESTS_DIR/BUILD" << BUILDSTART
load("@bazel_skylib//lib:dicts.bzl", "dicts")
load(
    "//rules/opentitan:defs.bzl",
    "EARLGREY_TEST_ENVS",
    "opentitan_test",
    "verilator_params",
)

package(default_visibility = ["//visibility:public"])

opentitan_test(
    name = "${target}",
    srcs = ["${target}.c"],
    exec_env = dicts.add(
        EARLGREY_TEST_ENVS,
        {"//hw/top_earlgrey:sim_verilator": None},
    ),
    verilator = verilator_params(timeout = "long"),
    deps = [
        "//hw/top_earlgrey/sw/autogen:top_earlgrey",
        "//sw/device/lib/base:mmio",
        "//sw/device/lib/base:csr",
        "//sw/device/lib/runtime:log",
        "//sw/device/lib/testing/test_framework:ottf_main",
    ],
)
BUILDSTART

    # Step 3: 构建（固件编译，sim 已缓存）
    cd "$OT_DIR"
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
    export PATH="$VERILATOR_BIN:$TOOLCHAIN:$PATH"
    export VERILATOR="$VERILATOR_BIN/verilator"

    build_log="$LOG_DIR/${target}_build.log"
    bazel build "//sw/device/tests/pickerfuzz_tests:${target}_sim_verilator" \
        --jobs=4 > "$build_log" 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}  BUILD FAIL${NC} (log: $build_log)"
        grep -E "ERROR|error:" "$build_log" | head -5
        fail=$((fail+1))
        continue
    fi

    # Step 4: 直接运行仿真二进制（绕过 bazel test 的 runfiles 开销）
    RUNDIR=$(bazel info execution_root 2>/dev/null)/bazel-out/k8-fastbuild-ST-1df456420242/bin/sw/device/tests/pickerfuzz_tests/${target}_sim_verilator.bash.runfiles
    if [ ! -d "$RUNDIR" ]; then
        # fallback: 找 runfiles 目录
        RUNDIR=$(find "$(bazel info execution_root 2>/dev/null)/bazel-out" -maxdepth 8 -name "${target}_sim_verilator.bash.runfiles" -type d 2>/dev/null | head -1)
    fi
    if [ ! -d "$RUNDIR" ]; then
        echo -e "${RED}  RUNFILES NOT FOUND${NC}"
        fail=$((fail+1))
        continue
    fi

    sim_log="$LOG_DIR/${target}_sim.log"
    cd "$RUNDIR/_main"
    timeout 300 ./hw/build.verilator_real/lowrisc_dv_top_earlgrey_chip_verilator_sim_0.1/sim-verilator/Vchip_sim_tb \
        --meminit=rom0,sw/device/lib/testing/test_rom/test_rom_sim_verilator.39.scr.vmem \
        --meminit=rram,sw/device/tests/pickerfuzz_tests/${target}_sim_verilator.128.scr.vmem \
        --meminit=otp,sw/device/tests/pickerfuzz_tests/${target}_sim_verilator.otp.rram.vmem \
        > "$sim_log" 2>&1
    rc=$?

    # Step 5: 解析结果（漏斗 L2: UART 日志分析 + 误报抑制）
    uart="$RUNDIR/_main/uart0.log"
    if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
        echo -e "${RED}  SIM CRASH (rc=$rc)${NC} — 可能触发仿真器/RTL 崩溃!"
        echo "$target SIM_CRASH rc=$rc" >> "$LOG_DIR/summary.txt"
        vuln=$((vuln+1))
    elif grep -q "Access Fault" "$uart" 2>/dev/null && ! grep -qE '\[FUZZ-[0-9]+ FAIL\]' "$uart" 2>/dev/null; then
        # 误报抑制: Access Fault = PMP/译码正确拦截越界访问 → 安全行为（BLOCKED）
        fault_addr=$(grep -o "MTVAL=[0-9a-f]*" "$uart" | head -1 | cut -d= -f2)
        echo -e "${GREEN}  BLOCKED (Access Fault @ 0x$fault_addr — 硬件正确拦截)${NC}"
        echo "$target BLOCKED addr=0x$fault_addr" >> "$LOG_DIR/summary.txt"
        pass=$((pass+1))
    elif grep -qE '\[FUZZ-[0-9]+ FAIL\]|\[O1\]|\[O2\]|\[O3\]|\[O4\]' "$uart" 2>/dev/null; then
        echo -e "${RED}  ANOMALY DETECTED:${NC}"
        grep -E '\[FUZZ-[0-9]+ FAIL\]|\[O1\]|\[O2\]|\[O3\]|\[O4\]' "$uart" | head -8
        echo "$target ANOMALY" >> "$LOG_DIR/summary.txt"
        vuln=$((vuln+1))
    elif grep -qE '\[FUZZ-[0-9]+ PASS\]' "$uart" 2>/dev/null; then
        echo -e "${GREEN}  PASS${NC}"
        echo "$target PASS" >> "$LOG_DIR/summary.txt"
        pass=$((pass+1))
    else
        echo -e "${CYAN}  NO OUTPUT / TIMEOUT${NC} (rc=$rc)"
        tail -3 "$sim_log" 2>/dev/null | head -3
        echo "$target NO_OUTPUT" >> "$LOG_DIR/summary.txt"
        fail=$((fail+1))
    fi

    # Step 6: 清理
    rm -rf "$TESTS_DIR"
done <<< "$IDS"

echo ""
echo -e "${BOLD}===== HTFuzz 汇总 =====${NC}"
echo -e "  总数: $total  ${GREEN}PASS/BLOCKED: $pass${NC}  ${RED}ANOMALY/CRASH: $vuln${NC}  ${CYAN}FAIL: $fail${NC}"
[ -f "$LOG_DIR/summary.txt" ] && echo -e "  详情: $LOG_DIR/summary.txt"
