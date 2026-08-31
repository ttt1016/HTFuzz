# HTFuzz 大规模 Fuzzing 报告 — per-IP HMAC DUT（Tier 1）

> 日期: 2026-08-30
> 模式: per-IP Verilator DUT + Python ctypes API（计划书 M5 Tier 1 主力）
> 方法: hjson 规格 oracle + 元变关系（无 golden diff）

## 一、执行摘要

| 指标 | 数值 |
|---|---|
| 总迭代 | **140,000**（7 段 × 20,000，seed 段 1000~25000） |
| 总序列 | 279,784 |
| 总总线操作 | **3,663,379** |
| 总耗时 | 34.5 秒 |
| 平均吞吐 | **106,101 ops/s**（计划书验收 ≥100 ops/s，超额 1000 倍） |
| O1 规格违规 | 0 |
| O3 双种子差异 | 0 |
| 崩溃库条目 | 0 |
| **结论** | **CLEAN ✓ — 干净 OpenTitan RTL 基线确认（零误报）** |

## 二、Oracle 有效性验证（mutant 测试）

防止"假 CLEAN"——用 4 个 mutant 验证检测路径真的在工作:

| Mutant | 预期 | 实测 |
|---|---|---|
| RO 写穿（STATUS 写 0xA5A5A5A5） | 硬件拒绝 | ✓ 拒绝 |
| 密钥白盒可见性（KEY[0]→secret_key[31]） | 可读 0xDEADBEEF | ✓ 可读 |
| O3-① 双种子比较路径 | 读值一致 | ✓ 一致 |
| 密钥残留（KEY 写后不 wipe） | 扫描报残留 | ✓ 报 2 词残留 |

## 三、覆盖率（140k 迭代静态统计）

- 寄存器触达: 8/60 位置（13%）——随机序列集中在控制/中断/FIFO
- 控制字段: 16 个字段全部触达非零值
- WIPE_SECRET: 38,519 个不同 wipe 值（密钥清除路径充分激励）
- 未触达: KEY[0..31] multireg 大部分、DIGEST[0..15]、MSG_LENGTH（随机序列少写这些）

## 四、发现的工程问题（本轮修复）

1. `pf_sig_read` ctypes restype 有符号 int → 0xDEADBEEF 读成负数 → O3-3 判定失效（已修复 c_uint32）
2. per-IP DUT 无 PMP: 越界写 err=0、读=0（地址译码不命中）——OOB 拦截验证需全芯片（Tier 3）

## 五、与计划书验收标准对照

| 计划书 DoD | 状态 |
|---|---|
| M5 吞吐 ≥100 op/s | ✓ 106k ops/s |
| M5 双种子基建 | ✓ O3-① 通过 |
| M6-O1 mutant 验收（W1C 反转/REGWEN） | 部分（RO/W1C/cfg_block/掩码已验） |
| M6-O3 mutant 验收（密钥残留） | ✓ 检测能力确认 |
| 干净 RTL 零误报基线 | ✓ 140k 迭代 0 误报 |

## 六、下一步

1. 语料库调度（M9）: 用 seed trace 片段替代纯随机，提升 KEY/DIGEST 覆盖
2. ddmin 最小化（M8）: 对未来 ANOMALY 自动约简
3. LLM 分诊（M7）: O4 高权重发现批量分诊
4. 扩展 KMAC/AES per-IP DUT（管线已通用化）
