#!/bin/bash
# 自动递归收集 per-IP RTL 依赖（迭代 grep 模块实例化直到无 MODMISSING）
# 用法: collect_deps.sh <ip> <top_sv> ...
IP=$1; shift
PERIP=/workspace/HTFuzz/perip/$IP
OT=${PF_TARGET_RTL:-/workspace/opentitan}  # 比赛提供的 RTL
cd $OT
for round in 1 2 3 4 5 6 7 8; do
  MISSING=$(cd $PERIP && verilator --cc --lint-only -Wno-fatal \
    -Ihw/ip/prim/rtl -Ihw/ip/prim_generic/rtl -Ihw/ip/tlul/rtl -Ihw/ip/$IP/rtl \
    -Ihw/ip/keymgr/rtl -Ihw/ip/edn/rtl -Ihw/ip/lc_ctrl/rtl -Ihw/ip/entropy_src/rtl \
    -Ihw/ip/csrng/rtl -Ihw/top_earlgrey/rtl \
    $(find $PERIP/hw -name "*.sv" | sed "s|$PERIP/||") 2>&1 | grep -oE "Cannot find file containing module: .[a-z_0-9]+" | grep -oE "[a-z_0-9]+$" | sort -u)
  [ -z "$MISSING" ] && echo "round $round: 依赖完整 ✓" && exit 0
  echo "round $round: 缺失 $MISSING"
  for m in $MISSING; do
    src=$(find hw -name "$m.sv" -not -path "*dv*" -not -path "*xilinx*" | head -1)
    [ -n "$src" ] && cp --parents "$src" $PERIP/ && echo "  + $src"
  done
done
echo "8 轮后仍有缺失，手动检查"
exit 1
