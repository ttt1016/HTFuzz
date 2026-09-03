# HTFuzz —— HACK@CHES 2026 参赛工具

## 一句话

基于 per-IP Verilator DUT + 14 层 oracle（属性族驱动，O-A~O-N + O-H/O-I）+ LLM 三件套（深度审计/动态验证 agent/
不变量提取）的硬件安全漏洞自动挖掘工具，无需漏洞先验知识、无需 diff 官方代码、
无需 clean DUT，从零构建单个模块 DUT 并完成盲测的周期约 1 小时。

## 核心架构

```
┌─────────────────────────────────────────────────────┐
│  target_gen.py     靶点自动生成（SEC_CM/断言/参数）    │
│       ↓ 399 靶点                                     │
│  discover_engine.py  oracle 盲测引擎                  │
│    O-A 残留    敏感数据擦除失效（密钥残留）            │
│    O-B 确定性  掩码静态/PRNG 不动                     │
│    O-C 等价类  配置解码/相位错误                      │
│    O-D FSM     卡死/无超时恢复（busy 基线对照）        │
│    O-E FIFO    溢出破坏状态                           │
│    O-F 流式    计数器冻结/数据流卡死                  │
│    O-G 脉冲    握手脉冲宽度/电平化                    │
│       ↓ 候选                                         │
│  llm_deep_audit.py   LLM 深度审计                     │
│    ±30 行 RTL 上下文 + SEC_CM 清单 + hjson 定义        │
│    → 注入点定位（与 RTL diff 逐字吻合）+ PoC 建议      │
│       ↓                                              │
│  llm_agent.py        ReAct 动态验证 agent              │
│    action: write/read/step/sig_read/reset/conclude     │
│    → 自主执行 PoC → confirmed/refuted/inconclusive     │
│       ↓                                              │
│  ok_invariant.py     O-K 不变量 oracle（12 规则）        │
│    LLM 从 SEC_CM/hjson 提取不变量 JSON（数据非代码）    │
│    → 通用检查器动态执行 → 违反即检出（新发现引擎）       │
│       ↓                                              │
│  triage_nofresh.py   置信度分级 → 人工只看 confirmed    │
└─────────────────────────────────────────────────────┘
```

## 关键指标

| 指标 | 数值 |
|------|------|
| 已验证 DUT | 24 个（含 ibex CPU 核 + 10 个 O-K 不变量模块）|
| Oracle | 11 层（O-A~K）|
| CSV 覆盖 | **26/26（100%）**——21 动态确认 + 2 静态确认 + 3 单元 TB 对照 |
| 动态确认 bug | 21 个（含 agent 自主复现 hmac Bug#20/60、rom_ctrl Bug#2）|
| O-K 不变量 | 10 模块 82 条，6 条 VIOLATION 全对应已知注入，0 误报 |
| LLM 深度审计 | hmac wipe 极性 / aes data_out 行 873——注入点推断与 RTL diff 逐字吻合 |
| agent 能力 | confirmed/refuted 双向判定（可证伪 oracle 误报）|
| 误报率 | 全模块 0 误报（O-D 基线 + EXCLUDE_PATTERNS + O-K 规范不变量）|
| 单 op 速度 | 1.7μs（217k ops/s，比全芯片仿真快 2000×）|
| 新模块接入 | ~1 小时（唯一必填配置: rtl_path）；O-K 接入 = 一次 LLM gen，零代码 |

## 检出漏洞清单（26/26）

| 模块 | Bug | 检出 oracle |
|------|-----|------------|
| hmac | #20/60 WIPE_SECRET 极性反转 | O-A + agent confirmed + O-K VIOLATION |
| hmac | #83 SHA512 OPad 长度 | O2 NIST 向量（逐位一致）|
| aes | #12 DIP_CLEAR 映射错误 | O3-③ 白盒残留 |
| aes | #82 KEY wipe 擦除变注入 | O3-③ + O-K VIOLATION |
| aes | #32 data_out reset 条件化 | O3-③ + LLM 定位行 873 + O-K VIOLATION |
| aes | #6/9 key_expand 分支 | O2 NIST SP800-38A |
| aes | #31 强制掩码硬编码 | O1 配置面 |
| aes | #81 KEY_SHARE 读回 | O1 规格比对 |
| aes | #34 CTR alert 延迟 | RTL 静态确认 |
| kmac | #26 静态掩码 | O4 掩码静态性 |
| keymgr | #21/64 StCtrlInvalid 暴露 | O4 白盒对照 |
| keymgr | #11 ECC 脱钩 | RTL 静态确认 |
| lc_ctrl | #28 token 全宽比较 | 单元 TB 对照 |
| uart | #1 LSIO DMA handshake | 单元 TB 对照 |
| prim | #7 shadow error_s | 单元 TB 对照 |
| ascon | #43 TRIGGER.wipe 无效 | O-A + agent + O-K（三重印证）|
| ascon | #38 escalation 无 fanout | escalation 序列注入 |
| rom_ctrl | #2 rvalid 电平化 | O-G 脉冲宽度 + agent confirmed |
| ibex | #27 PMP 极性反转 | O-H 语义 oracle |
| ibex | #45 PMP 违例吞没 | O-H 语义 oracle |
| ibex | #5 U-mode 特权放行 | O-I 语义 oracle |
| ibex | #13 CSR 写保护失效 | O-I 语义 oracle |

## 合规性

- 只读比赛提供的 RTL（/workspace/opentitan），无 diff、无外部对照
- oracle 全部基于通用安全语义（残留/确定性/等价类/卡死/溢出/冻结/PMP 规范/
  特权级规范/安全不变量），不依赖任何已知漏洞信息
- O-K 不变量来自 SEC_CM/hjson 规范语义，比赛合规（不依赖 clean DUT）
- 干净 RTL 对照仅在开发阶段用于验证误报率，比赛工具链不包含
- LLM 为自建本地服务（GLM-5.3-Flash @ vLLM），无外部 API 依赖

## 目录结构

- `scripts/` 核心引擎（discover_engine/llm_deep_audit/llm_agent/ok_invariant/
  llm_triage/target_gen/triage_nofresh/pf_profile）
- `perip/` 24 个自包含 per-IP DUT（wrapper + harness + filelist，编译产物可重建）
- `invariants/` O-K 不变量配置（10 模块 82 条，LLM 生成）
- `profiles/` 芯片配置（opentitan.json + template.json）
- `fuzz/` 盲测结果 + agent 验证 trace + 不变量检查结果
- `reports/` 检测报告（CTF-SUMMARY-REPORT.md 23 章为主报告）

## 快速上手

```bash
# 1. 生成靶点
PF_PROFILE=profiles/opentitan.json python3 scripts/target_gen.py

# 2. 对某模块跑 oracle 盲测
PF_PROFILE=profiles/opentitan.json python3 scripts/discover_engine.py \
    perip/hmac-ctf hmac traces/hmac_regmap.json

# 3. LLM 深度审计（注入点定位 + PoC 建议）
PF_LLM_BASE=http://127.0.0.1:18000/v1 PF_LLM_MODEL=zai-org/GLM-5.3-Flash \
    python3 scripts/llm_deep_audit.py fuzz/discover_hmac.json hmac

# 4. Agent 动态验证（自主执行 PoC）
python3 scripts/llm_agent.py perip/hmac-ctf hmac \
    traces/hmac_regmap.json fuzz/discover_hmac_deep.json --max-steps 15

# 5. O-K 不变量（提取 + 检查）
python3 scripts/ok_invariant.py gen hmac
python3 scripts/ok_invariant.py check hmac --dut-dir perip/hmac-ctf \
    --regmap traces/hmac_regmap.json

# 6. 置信度分级
python3 scripts/triage_nofresh.py fuzz/discover_hmac.json hmac
```

## 换芯片环境

复制 `profiles/template.json`，填 `rtl_path`（唯一必填项），
有安全标注则补 `security_annotations.pattern`，即可接入新环境。
O-K 不变量对新模块零代码：`python3 scripts/ok_invariant.py gen <module>` 即可。
