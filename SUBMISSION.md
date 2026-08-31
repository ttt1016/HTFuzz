# HTFuzz —— HACK@CHES 2026 参赛工具

## 一句话

基于 per-IP Verilator DUT + 6 层通用 oracle 的硬件安全漏洞自动挖掘工具，
无需漏洞先验知识、无需 diff 官方代码，从零构建单个模块 DUT 并完成盲测的周期约 1 小时。

## 核心架构

```
┌─────────────────────────────────────────────────────┐
│  target_gen.py     靶点自动生成（SEC_CM/断言/参数）    │
│       ↓ 399 靶点                                     │
│  discover_engine.py  6 层 oracle 盲测引擎             │
│    O-A 残留    敏感数据擦除失效（密钥残留）            │
│    O-B 确定性  掩码静态/PRNG 不动                     │
│    O-C 等价类  配置解码/相位错误                      │
│    O-D FSM     卡死/无超时恢复（busy 基线对照）        │
│    O-E FIFO    溢出破坏状态                           │
│    O-F 流式    计数器冻结/数据流卡死                  │
│       ↓ 候选                                         │
│  llm_triage.py     LLM/规则分诊（likely-bug 排序）    │
│       ↓                                              │
│  triage_nofresh.py 无 fresh 对照的置信度分级          │
└─────────────────────────────────────────────────────┘
```

## 关键指标

| 指标 | 数值 |
|------|------|
| 已验证 DUT | 12 个（hmac/aes/kmac/csrng/keymgr/lc/uart/entropy_src/ibex/spi_host/pwrmgr/ascon）|
| 动态检出比赛注入 bug | 12 个 |
| RTL 静态确认 | 6 个 |
| 误报率 | O-D 优化后全模块 0 误报 |
| 单 op 速度 | 1.7μs（217k ops/s，比全芯片仿真快 2000×）|
| 新模块接入周期 | ~1 小时（唯一必填配置: rtl_path）|

## 合规性

- 只读比赛提供的 RTL（/workspace/opentitan），无 diff、无外部对照
- oracle 全部基于通用安全语义（残留/确定性/等价类/卡死/溢出/冻结），
  不依赖任何已知漏洞信息
- 干净 RTL 对照仅在开发阶段用于验证误报率，比赛工具链不包含

## 目录结构

- `scripts/` 核心引擎（discover_engine/llm_triage/target_gen/triage_nofresh/pf_profile）
- `perip/` 12 个自包含 per-IP DUT（RTL + wrapper + harness + .so）
- `profiles/` 芯片配置（opentitan.json + template.json）
- `fuzz/` 盲测结果 JSON
- `reports/` 检测报告（CTF-SUMMARY-REPORT.md 为主报告）

## 快速上手

```bash
# 1. 生成靶点
PF_PROFILE=profiles/opentitan.json python3 scripts/target_gen.py

# 2. 对某模块跑 6 oracle 盲测
PF_PROFILE=profiles/opentitan.json python3 scripts/discover_engine.py perip/hmac-ctf hmac

# 3. LLM/规则分诊
python3 scripts/llm_triage.py fuzz/discover_hmac.json hmac

# 4. 置信度分级
python3 scripts/triage_nofresh.py fuzz/discover_hmac.json hmac
```

## 换芯片环境

复制 `profiles/template.json`，填 `rtl_path`（唯一必填项），
有安全标注则补 `security_annotations.pattern`，即可接入新环境。
