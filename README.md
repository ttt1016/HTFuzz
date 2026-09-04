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
│ 第 1 层  per-IP DUT：28 个（cb_* TL 接口 + 白盒信号表）       │
│   aes hmac kmac ascon keymgr csrng entropy_src uart gpio     │
│   adc_ctrl tlul rom_ctrl rstmgr clkmgr aon_timer pwrmgr      │
│   pattgen spi_host sram_ctrl alert_handler rv_dm otp_ctrl    │
│   lc_ctrl spi_tpm mbx otbn ...                               │
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
# 1. 全量盲测（28 DUT × 12 oracle，实测 ~3s）
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
| per-IP DUT | **28 个全量可用**（lc_ctrl/spi_tpm/mbx/otbn/rv_dm 本轮收官）|
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
| `reports/20260904/FINAL-VERIFICATION.md` | 最终全量验证 + 性能基准 + 覆盖率 |
| `reports/20260803/` `reports/20260831/` | 早期 bug 报告归档 |

## 基准测试（2026-09-04 实测，10 核/8GB 容器，单进程串行）

### 开环 fuzzing（batch_discover.py，28 DUT × 12 oracle）

| 指标 | 数值 |
|---|---|
| 全量耗时 | **~3s**（28 DUT 串行）|
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

### 开环也支持代码覆盖率（对比闭环）

| 模式 | hmac 覆盖率（行 / 翻转 / 分支 / expr）|
|------|--------------------------------------|
| 开环（batch_discover/discover_engine，全 12 oracle 一轮）| **75.3% / 62.5% / 77.3% / 65.5%** |
| 闭环（ol_full_loop，80 迭代） | 64.1% / 48.6% / 67.9% / 55.6% |

开环反而更高：12 个 oracle 的定向激励（KAT、错误注入、FSM 边界）比覆盖率引导的
随机变异更快触达安全关键路径。两者可叠加（verilator_coverage 支持多 .dat 合并）。

开环覆盖率采集方法（已固化 `scripts/coverage_run.sh`）：
1. 插桩构建：`verilator ... --coverage` → obj_cov/（harness 需 `-fPIC` 重编，
   `atexit`/显式 `pf_final` 写 coverage.dat）
2. 引擎侧：`discover_engine.py` main 结束时调用 `dut.api.pf_final()`（普通模型静默跳过）
3. `verilator_coverage` 统计；数据 `fuzz/hmac_openloop_coverage.dat` 可复现

## 60% 检出率攻坚方案（2026-09-04 立项 · 持续更新）

**目标**：CSV 清单 ~80 个独立 bug 的动态检出 ≥ 60%（即 ≥ 48 个 bug ID）。
基线：~20 个独立特征（开环 27 条记录 / 14 模块 + O-K 8 真检 + 闭环 2 + 单元 TB 3）。

### 缺口分解（对照 GAP-ANALYSIS 六大根因，42 章后更新）

| 根因 | 2026-09-03 状态 | 当前状态 | 剩余动作 |
|------|----------------|---------|---------|
| ① 模块无 DUT（~18 条载体） | 18 条无载体 | **已解决**：24 模块全有 DUT | 检测面仍需白盒扩充 |
| ③ O-K 规则桩（~10 条） | 9 桩 | **已全部实现**（12 规则） | 覆盖面验证 |
| ⑤ oracle 盲区 alert 类 | ~6 条 | **O-J 已上线** | 继续覆盖 |
| ④ 白盒缺口（~12 条） | aes 6→29 已扩，ascon/otp_ctrl/kmac/gpio 仍薄 | **进行中** | Phase A |
| ② 激励到不了（~8 条） | 需 CPU 指令级 | 部分 | Phase C/D |
| ⑥ O-A 位级局限 | ~10 条 | 部分（O-J 缓解） | Phase C |
| ② lc/keymgr TB 场景（~6 条） | 未做 | | Phase D |

### 执行路线（每大项一个 git 存档）
- **Phase A（最高 ROI）白盒表自动扩充**：SEC_CM 注释 + reg_pkg 信号自动生成
  g_sigs 候选表（aes +20 / kmac +10 / hmac_core / rom_ctrl / ascon / otp_ctrl），
  目标根因④ ~12 条。验证：重建后引擎全量不回归 + 新信号面生效。
- **Phase B（并行）**：pwrmgr 慢 FSM 卡死定性 TB、clkmgr fatal_err_code 对照 CSV。
- **Phase C**：O-K2 中途复位 oracle + 定向 wipe/trigger 种子（闭合 ascon TRIGGER 面）。
- **Phase D**：ibex CSR 单元 TB（mseccfg/icache 三条）+ keymgr sideload 消费者。
- 验收口径：每阶段 batch_discover + batch_ok_check 全量，检出 ID 对照 CSV 记账。

### 进度表
| 阶段 | 状态 | 新增检出 | 提交 |
|------|------|---------|------|
| 基线 | 27 条 / 14 模块（~20 独立 ID） | — | 05314bd |
| Phase A-① ascon 白盒 4→78 | 完成 | **ascon 2→21 条检出**（key_share/duplex 面打开） | 本提交 |
| Phase A-② kmac 白盒 3→248 | 完成 | kmac 2→3 条（#26 静态掩码 O-B 命中确认） | 已推送 |
| Phase A-② rom_ctrl/otp_ctrl 推广 | 进行中 | rom_ctrl 候选仅 4（RTL 侧信号面薄, 需 wrapper 暴露内部） | — |
| Phase A-② ascon 重建修正 | 完成 | ascon 重建后 58 条检出记录（key_share 4 词全绑定 + 78 信号面） | 601b1da 后续 |
| Phase A-② rom_ctrl 白盒 2→4(alert/error_det/mem) | 完成 | rom_ctrl O-G 脉冲电平化 1 条（#26 alert 抑制面） | 本提交 |
| 构建基建沉淀 | 完成 | gen_bindings 词切分数组兜底绑定(BRA/KET 形态)；模块 filelist 必须含 incdir；-Wno-ENUMVALUE/WIDTH 全局放宽 | 本提交 |

## 安全属性分类学：论文依据与有效性论证

### 权威来源背书

十大属性族不是本项目发明的分类，每族都有可直接引用的标准或论文依据：

| # | 属性族 | 权威依据 |
|---|--------|---------|
| 1 | 数据完整性-擦除 | **FIPS 140-3**（密码模块零化要求，Cryptographic Erase）；OpenTitan `DATA_REG.SEC_WIPE` |
| 2 | 访问控制 | ISO/IEC 15408（Common Criteria）FMT 类（安全管理/访问控制）；RISC-V **Smepmp** 规范；OpenTitan `CONFIG.REGWEN` |
| 3 | 随机性/掩码 | FIPS 140-3 随机数生成与 SCA 要求；OpenTitan `KEY.MASKING`、`DATA_REG_SW.SCA` |
| 4 | FSM 稀疏编码+故障恢复 | OpenTitan `CTRL.FSM.SPARSE`(9)+`LOCAL_ESC`/`GLOBAL_ESC`(16)；CC FPT.1（失效安全 fail-secure）|
| 5 | 总线完整性 | OpenTitan `BUS.INTEGRITY`（**目标 RTL 中频次最高的对策，43 处**）；TL-UL ECC 规范 |
| 6 | 信息泄露 | ISO/IEC 15408 FDP 类（机密性）；OpenTitan `KEY.SW_UNREADABLE` |
| 7 | 时序安全 | CC FPT 类（安全功能时序）；比赛已知注入（alert 延迟 100 拍）|
| 8 | **冗余一致性** | NIST SP 800-193 **Detect** 维度；TMR/双轨比较（CTR.REDUN 33 处）；经典 N-modular redundancy 理论 |
| 9 | **可用性** | NIST SP 800-193 **Recover** 维度；Farzana et al. ITC 2019 属性验证框架含 availability |
| 10 | **MUBI 编码** | OpenTitan `INTERSIG.MUBI`/`CONFIG.MUBI`（31+ 处）；本质是 **Hamming 距离≥3 的容错编码**（编码理论）|
| 11 | **密码符合性** | NIST **CAVP/FTS 已知答案测试（KAT）**制度；FIPS 140-3 §自测要求 |

### 核心学术论文

- **Farzana, Rahman, Tehranipoor, Farimah Farahmandi, "SoC Security Verification using Property Checking", ITC 2019（IEEE, DOI: 10.1109/ITC44170.2019.9000170）**
  —— 工业级 SoC 安全属性验证框架，**验证了属性检查在 SoC 安全中的可扩展性**。
  （注：论文正文的属性子分类未核实——IEEE 付费墙内，本分类学的 availability
  来源是 NIST SP 800-193 的 Recover 维度而非此论文。）
- **Common Criteria (ISO/IEC 15408)** FPT/FCS/FDP 类——国际公认的安全评估标准。
- **NIST SP 800-193**（Platform Firmware Resiliency）——PDR（Protect/Detect/Recover）三元组，
  与本分类的"访问控制/错误检测/擦除恢复"一一对应。
- **MITRE CWE View-1194（Hardware Design）**——硬件弱点枚举（含 CWE-1197 调试锁旁路等）。
- **MITRE EMEA**——硬件攻击者画像与效应分析框架。
- **HACK@CHES / Hack@DAC 系列比赛**——注入手法分类与 SEC_CM 体系的实践渊源。

### 有效性论证（三支柱 + 边界声明）

1. **内生验证（最强证据）**：比赛目标 RTL 实测含 **278 个 SEC_CM 标注**，全部落入十大属性族——
   分类学是**从目标本身的对策体系归纳的**，不是外挂假设。主办方设计注入点时必须打破某个 SEC_CM，
   即必然落入某一族。
2. **回溯审计**：本工具动态发现的 **20 个独立漏洞特征 + 清单已确认的 bug** 全部可映射进十大族
   （样本内 0 遗漏）。
3. **权威背书**：上表——分类不是自创，是 SP 800-193 PDR、CC FPT、FIPS 140-3、ITC 2019 属性分类
   在 OpenTitan 语境下的实例化。

**边界声明（诚实声明当前证据的限度）**：
- 回溯审计是**样本内**验证；对**样本外**（主办方未公开的注入手法）的有效性，需要
  **变异测试**（向干净副本注入按族合成的变异体、统计杀伤率）补完——已列入待办。
- LLM 合成的不变量存在标签错误风险（本会话实测 12 条中 2 条误报），O-K 检查器
  必须与人工/自动 triage 双重把关，不能将 LLM 输出直接当作真值。
- GLITCH_DETECT 等物理层机制超出寄存器级仿真能力，不在本分类覆盖范围。
