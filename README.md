# HTFuzz-OT — OpenTitan RTL 安全模糊测试框架

> 按《项目计划书 v1.2》实现的 hjson 规格 oracle + 元变关系 fuzzing 框架
> （不依赖 golden model 差分，自主设计的硬件木马检测框架）

## 目录结构

```
pickerfuzz/
├── scripts/              # 引擎脚本
│   ├── fuzz_engine.py    # M4 变异引擎（7 算子，全芯片回放模式）
│   ├── pickerfuzz_runner.sh  # 全芯片回放 runner（Tier 3）
│   ├── mass_fuzz.py      # 大规模 fuzzing（per-IP DUT 模式，Tier 1）
│   ├── sched_fuzz.py     # M9 语料库调度（seed trace 片段 + AFL 加权）
│   ├── o1_spec_checker.py    # M6-O1 hjson 规格 checker
│   ├── o3_metamorphic.py     # M6-O3 元变三合一（双种子/复位重放/zeroize）
│   ├── o4_signal_modes.py    # M6-O4 信号转移模式
│   ├── triage.py         # M7 三级漏斗（规则引擎+known-safe+LLM 接口）
│   ├── ddmin.py          # M8 delta debugging 最小化
│   ├── report_gen.py     # M10 CWE 映射报告生成器
│   ├── coverage_stats.py # 覆盖率统计
│   ├── parse_trace_test.py   # trace 语义解析验证
│   └── include/ot_secfuzz.h  # 固件公共头（全芯片回放模式用）
├── perip/                # M5 per-IP DUT（独立 Verilator 仿真器）
│   ├── hmac/             # 106k ops/s，自检 PASS
│   ├── kmac/             # 编译中
│   └── aes/              # 编译中
├── traces/               # M1 TL-UL trace + M3 regmap
│   ├── hmac_smoketest_tlul.log
│   ├── hmac_regmap.json / kmac_regmap.json / aes_regmap.json
│   └── ...
├── fuzz/                 # fuzzing 输出
│   ├── mass/             # 大规模 fuzzing 结果（140k 迭代基线）
│   ├── sched/            # 语料调度结果（98% 覆盖）
│   ├── out/              # 变异固件
│   ├── logs/             # 运行日志
│   ├── known_safe.json   # M7 known-safe 库
│   └── llm_cache.json    # M7 LLM 判定缓存
└── reports_new/          # 报告
    ├── PICKERFUZZ-DEMO-REPORT.md
    ├── MASS-FUZZ-REPORT.md
    └── bugs/             # M10 生成的 bug 报告
```

## 快速开始

```bash
# 1. per-IP HMAC 自检
/workspace/pickerfuzz/perip/hmac/obj_dir/pf_hmac

# 2. 大规模 fuzzing（per-IP 模式）
python3 scripts/mass_fuzz.py --iters 20000 --seed-base 1000

# 3. 语料库调度 fuzzing（98% 覆盖）
python3 scripts/sched_fuzz.py --iters 20000

# 4. Oracle 回归
python3 scripts/o1_spec_checker.py   # O1 规格 checker
python3 scripts/o3_metamorphic.py    # O3 元变三合一
python3 scripts/o4_signal_modes.py   # O4 信号模式

# 5. 全芯片回放模式（Tier 3）
python3 scripts/fuzz_engine.py && ./scripts/pickerfuzz_runner.sh
```

## 关键指标

| 指标 | 数值 |
|---|---|
| per-IP 吞吐 | 106k ops/s（计划书 ≥100） |
| 大规模基线 | 140k 迭代 0 误报（干净 RTL） |
| 语料调度覆盖 | 98%（纯随机 13%） |
| 误报抑制率 | 100%（100 条已知误报） |
| ddmin | 120-op → 2-op |

老工具数据（296 固件测试/VULN 报告）已归档至 `/workspace/ot-secfuzz-archive/`。
