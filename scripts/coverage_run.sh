#!/usr/bin/env bash
# 开环覆盖率采集：对已构建 obj_cov（--coverage 插桩模型）的 DUT，
# 用开环引擎（discover_engine，全部 oracle）跑一轮并收集 RTL 行/翻转/分支覆盖率。
#
# 用法: coverage_run.sh <module> <regmap可选>
# 前提: perip/<module>-ctf/obj_cov/ 存在（verilator --coverage 构建）
set +e
M=$1
BASE=/workspace/HTFuzz/perip/$M-ctf
cd $BASE

# 1) 备份常规 .so，放入插桩 .so（引擎按 api 库优先加载）
mkdir -p obj_so/.cov_backup
for f in obj_so/*.so; do [ -e "$f" ] && mv "$f" obj_so/.cov_backup/ 2>/dev/null; done
cp obj_cov/libpf_${M}_cov.so obj_so/ 2>/dev/null || cp obj_cov/*.so obj_so/ 2>/dev/null

# 2) 开环引擎跑一轮（全 oracle），coverage.dat 落在 DUT 根目录
cd /workspace/HTFuzz
REG=$2
if [ -z "$REG" ] && [ -e "traces/${M}_regmap.json" ]; then REG="traces/${M}_regmap.json"; fi
python3 scripts/discover_engine.py perip/$M-ctf $M $REG > /tmp/cov_run_$M.log 2>&1

# 3) 收集
COVDAT=$BASE/coverage.dat
[ -e $COVDAT ] && mv $COVDAT $BASE/obj_cov/coverage_open.dat
verilator_coverage $BASE/obj_cov/coverage_open.dat 2>&1 | head -6

# 4) 恢复常规 .so
rm -f $BASE/obj_so/*.so
for f in $BASE/obj_so/.cov_backup/*.so; do [ -e "$f" ] && mv "$f" $BASE/obj_so/ 2>/dev/null; done
echo "=== done: $M"
