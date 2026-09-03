# 最终全量验证与基准（2026-09-04）

## 1. 全量漏洞挖掘结果

| oracle 层 | 检出 |
|-----------|------|
| 引擎 O-A~O-M（21 DUT） | 22 条 / 12 模块 |
| O-K 不变量（12 模块） | 12 条（10 真检出 + 2 不变量标签误报）|
| 闭环 fuzzing（16 模块 × 80 迭代） | 2 条 + 覆盖率数据 |
| 单元 TB（lc/uart/prim） | 3 条全确认 |
| **合计** | **41 条记录 / 20 个独立漏洞特征 / 0 漏报已知 bug** |

20 个独立特征明细见主报告 39 章；其中 5 个（标🆕）为清单外新特征候选：
hmac FSM 卡死、aes key_init 残留、ibex 错误吞没、clkmgr/rstmgr alert 传播异常。

## 2. 性能基准（实测）

| 模式 | 单模块 | 全量 |
|------|--------|------|
| 开环（21 DUT × 12 oracle） | 0.11~0.34s | 2.9s |
| 闭环（80 迭代，16 模块） | 0.1~0.6s | 3.0s |
| O-K（12 模块 107 条） | — | ~30s |
| 峰值内存 | 23~28 MB/进程 | <300 MB |

## 3. RTL 代码覆盖率（hmac，12 oracle 激励）

| 类型 | 开环 | 闭环 |
|------|------|------|
| 行 | **75.3%** | 64.1% |
| 翻转 | 62.5% | 48.6% |
| 分支 | **77.3%** | 67.9% |
| expr | 65.5% | 55.6% |

## 4. 遗留待办
1. 分类学有效性验证：回溯审计（清单 bug→十大族）+ 变异测试（杀伤率）
2. gpio regmap hjson 解析修复（当前 gpio O-K 空转）
3. 剩余 5 DUT：otp_ctrl / spi_tpm / lc_ctrl / mbx / otbn
4. O-K gen 后置校验：write-only 标签仅接受 CSR 名单内信号（修 2 条标签误报）

## 5. 数据文件
- `fuzz/full_sweep.json` / `fuzz/ok_check_summary.json` — 检出明细
- `fuzz/bench_closed_loop.json` — 闭环基准
- `fuzz/hmac_openloop_coverage.dat` / `fuzz/hmac_oracle_coverage.dat` — 覆盖率原始数据
