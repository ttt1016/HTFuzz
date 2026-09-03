# HTFuzz — OpenTitan 硬件安全漏洞自动挖掘工具

> HACK@CHES 2026 参赛工具：per-IP Verilator DUT + 14 层属性族驱动 oracle
> （不依赖漏洞先验、不 diff 官方代码、不需要 clean DUT 的盲测框架）

## 当前架构

```
┌────────────────────────────────────────────────────────────┐
│ 第 4 层  闭环 fuzzing（ol_full_loop.py，覆盖率引导）          │
├────────────────────────────────────────────────────────────┤
│ 第 3 层  LLM 三件套                                          │
│   llm_deep_audit.py  静态审计（读 RTL 抓行为盲区）            │
│   llm_agent.py       DutHandle + ReAct 动态验证（PoC 证据链） │
│   O-K gen            从 SEC_CM 合成不变量（知识编译器）        │
├────────────────────────────────────────────────────────────┤
│ 第 2 层  Oracle 判定引擎（14 个，属性族驱动）                 │
│   discover_engine.py: O-A 残留 / O-B 确定性 / O-C 等价类     │
│   / O-D FSM / O-E FIFO / O-F 流式 / O-G 脉冲                 │
│   / O-J 错误传播 / O-L 密码符合性 KAT / O-N 多轨一致性        │
│   / O-M MUBI 合法性 + O-K 不变量(12 规则)                    │
│   + O-H PMP / O-I 特权（ibex 单元 TB，fork-vs-clean）        │
├────────────────────────────────────────────────────────────┤
│ 第 1 层  per-IP DUT：23 个（cb_* TL 接口 + 白盒信号表）       │
│   aes hmac kmac ascon keymgr csrng entropy_src uart gpio     │
│   adc_ctrl tlul rom_ctrl rstmgr clkmgr aon_timer pwrmgr      │
│   pattgen spi_host sram_ctrl alert_handler rv_dm ...         │
└────────────────────────────────────────────────────────────┘
```

属性分类学基础：目标 RTL 实测 **278 类 SEC_CM** 归纳为十大属性族
（冗余一致性 / 可用性 / MUBI 合法性等为既有 7 大类的补充），
oracle 按属性族实现、不针对具体漏洞——换注入手法仍可检出。

## 目录结构

```
HTFuzz/
├── AGENT-HANDOFF.md          # 接手指南（任务/流水线/坑清单）
├── SUBMISSION.md             # 比赛提交材料
├── scripts/                  # 11 个活跃脚本
│   ├── discover_engine.py    # 盲测引擎（O-A~O-M 一体化）
│   ├── batch_discover.py     # 全量引擎扫描
│   ├── ok_invariant.py       # O-K 不变量 gen + check（12 规则）
│   ├── batch_ok_check.py     # 全量 O-K 检查
│   ├── llm_agent.py / llm_deep_audit.py
│   ├── keymgr_full_flow.py   # keymgr derivation 流程
│   ├── ol_full_loop.py       # 闭环 fuzzing
│   ├── pf_profile.py / triage_nofresh.py / environments/
│   └── legacy/               # 26 个已归档旧脚本
├── perip/<module>-ctf/       # per-IP DUT（wrapper + harness + obj_so）
├── reports/YYYYMMDD/         # 报告按日期归档 + CTF-SUMMARY-REPORT.md（38 章）
├── traces/                   # regmap JSON + 采样 trace
└── fuzz/                     # 引擎发现 JSON + O-K 结果
```

## 快速开始

```bash
# 1. 全量盲测（21 DUT × 12 oracle，实测 2.8s）
python3 scripts/batch_discover.py

# 2. O-K 不变量全量检查（12 模块 107 条）
python3 scripts/batch_ok_check.py

# 3. 单 DUT 扫描
python3 scripts/discover_engine.py perip/hmac-ctf hmac traces/hmac_regmap.json

# 4. 新建 DUT（依赖闭包自动解析，见报告 37.4 流水线）
bash autobuild.sh <module> <module>_perip_tb

# 5. O-K 不变量生成（LLM，每模块一次）
python3 scripts/ok_invariant.py gen <module>
```

## 当前状态（2026-09-03）

| 指标 | 数值 |
|---|---|
| per-IP DUT | 23 个（21 个可用 .so；待建 otp/spi_tpm/lc/mbx/otbn）|
| Oracle | 14 个（十大属性族 + 密码符合性 KAT + PMP/特权语义）|
| 全量检出 | 引擎 25 条/12 模块 + O-K 5 条 + 单元 TB 3 条 = **33 条，0 误报** |
| 单 DUT 扫描 | 0.1~0.25s，峰值内存 28 MB |
| 全量扫描 | 2.8s（21 DUT 串行，10 核/8GB 容器）|

## 文档索引

| 文档 | 内容 |
|------|------|
| `AGENT-HANDOFF.md` | 接手指南（任务/流水线/坑清单）|
| `reports/CTF-SUMMARY-REPORT.md` | 主报告 38 章（累计追加）|
| `reports/20260903/ORACLE-TAXONOMY.md` | 属性分类学（SEC_CM 278 类 → 十大族）|
| `reports/20260903/GAP-ANALYSIS.md` | P1/P2 清单 vs 工具能力差距分析 |
| `reports/20260803/` `reports/20260831/` | 早期 bug 报告归档 |

## 基准测试（2026-09-04 实测，10 核/8GB 容器，单进程串行）

### 开环 fuzzing（batch_discover.py，21 DUT × 12 oracle）

| 指标 | 数值 |
|---|---|
| 全量耗时 | **2.9s**（21 DUT 串行）|
| 单模块耗时 | 0.11~0.34s（hmac 0.14 / aes 0.24 / kmac 0.34，最大 csrng 0.14）|
| 单模块峰值内存 | 27~28 MB（全 DUT 一致，与设计规模弱相关）|
| CPU | 单核（编译型仿真，~10M cycles/s）|
| 检出 | 25 条唯一发现 / 12 模块，0 误报 |

### 闭环 fuzzing（ol_full_loop.py，80 迭代/模块，覆盖率引导 + O-K 判定）

| 模块 | 耗时 | 覆盖（状态+pairwise）| 峰值内存 | 不变量违反 |
|------|------|---------------------|---------|-----------|
| hmac | 0.3s | 377（pw 59）| 28 MB | 1（wipe 残留）|
| aes | 0.6s | 516 | 27 MB | 1 |
| ibex | 0.2s | 371 | 23 MB | 0 |
| ascon | 0.1s | 68 | 23 MB | 1 |
| entropy_src | 0.2s | 23 | 25 MB | 0 |
| clkmgr | 0.1s | 17 | 25 MB | 0 |
| 其余（kmac/rom_ctrl/pattgen/rv_timer/sram/aon/rstmgr/alert/pwrmgr/spi_host） | 各 0.1~0.2s | 0~37 | 23~28 MB | 0 |
| **全量（16 模块）** | **3.0s** | — | — | **2** |

注：keymgr 闭环 SKIP（缺 traces/keymgr_regmap.json，待补）。
覆盖率 = 已执行状态/信号模式组合计数（含 pairwise 信号两两组合）。

### 资源结论

- 任意单模块：**< 1 秒、< 30 MB、单核**——笔记本即可全量回归
- 全套（开环 21 DUT + 闭环 16 模块 + O-K + 单元 TB）**合计 < 10s、峰值 < 300 MB**
- LLM 层为按需触发（O-K gen 每模块一次调用，~30-120s；负载在自建 vLLM 服务端）
- 扩容方向：并行化受限于单核模型实例；加大 trials/campaign 时间线性增长，内存恒定

### 代码覆盖率（RTL 行/翻转/分支，Verilator --coverage 插桩实测）

以 hmac 为例（全部 12 个 oracle 的激励灌入后，verilator_coverage 统计）：

| 覆盖类型 | 数值 |
|---|---|
| 行覆盖 line | **64.1%**（280/437）|
| 翻转覆盖 toggle | 48.6%（14637/30106）|
| 分支覆盖 branch | **67.9%**（341/502）|
| 表达式覆盖 expr | 55.6%（953/1715）|

说明：①单轮全 oracle（约 0.15s 激励）即可达 64% 行/68% 分支——剩余部分主要是
未被任何场景触达的错误/保持路径与深状态组合，正是加大 fuzzing campaign 的增长空间；
②覆盖率插桩模型（--coverage）构建方法：`verilator ... --coverage` + harness
`contextp()->coveragep()->write("coverage.dat")` + `verilator_coverage`（构建脚本要点见
报告 38 章）；③数据文件 `fuzz/hmac_oracle_coverage.dat/.info` 可复现。
