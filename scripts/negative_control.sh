#!/usr/bin/env bash
# 阴性对照实验: 对全部 fresh(干净 RTL) DUT 运行 12-oracle 引擎
# 干净 RTL 上任何 finding 均为纯误报 → 直接量出工具本征误报率
# 注意: discover_engine 输出路径硬编码 fuzz/discover_<m>.json(会覆盖 CTF 结果),
#       每跑完一个模块立即把输出改名到 fuzz/nc_discover_<m>.json
set -u
cd /workspace/HTFuzz
echo "module,findings" > /workspace/HTFuzz/fuzz/nc_summary.csv
for d in perip/*-fresh; do
    m=$(basename "$d" -fresh)
    regmap="traces/${m}_regmap.json"
    [ -f "$regmap" ] || { echo "$m,NO_REGMAP" >> /workspace/HTFuzz/fuzz/nc_summary.csv; continue; }
    [ -d "$d/obj_so" ] || { echo "$m,NO_SO" >> /workspace/HTFuzz/fuzz/nc_summary.csv; continue; }
    out=$(timeout 300 python3 scripts/discover_engine.py "$d" "$m" "/workspace/HTFuzz/$regmap" 2>&1)
    rc=$?
    if [ -f "fuzz/discover_${m}.json" ]; then
        mv "fuzz/discover_${m}.json" "fuzz/nc_discover_${m}.json"
        n=$(python3 -c "import json;print(len(json.load(open('fuzz/nc_discover_${m}.json'))['findings']))" 2>/dev/null || echo ERR)
    else
        n="CRASH"
    fi
    echo "$m,$n" >> /workspace/HTFuzz/fuzz/nc_summary.csv
    echo "[nc] $m rc=$rc findings=$n"
done
echo "=== 阴性对照完成 ==="
cat /workspace/HTFuzz/fuzz/nc_summary.csv
