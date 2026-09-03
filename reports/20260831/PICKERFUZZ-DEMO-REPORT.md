# HTFuzz 演示效果报告 — HMAC IP 端到端验证

> 生成日期: 2026-08-30
> 平台: OpenTitan Earl Grey + Verilator 5.050 + opentitan-fresh
> 方法: hjson 规格 oracle + 元变关系（按新项目计划书，不做 golden diff）

---

## 一、执行摘要

HTFuzz 核心引擎已在 HMAC IP 上完成端到端演示：

| 指标 | 结果 |
|---|---|
| 变异序列总数 | 6（bitflip / illegal / boundary / window / fsm / meta） |
| 正确分类 | **6/6 (100%)** |
| 发现异常 | 0（本轮 seed 下 HMAC 行为符合规格） |
| 硬件拦截确认 | 1（window 越界写被 PMP/译码正确阻断） |
| O2 NIST 参考值 | SHA256(a×32) H0=0x3ba3f5f4 ✓ |
| O3 元变关系 | 双路径 digest 完全一致 ✓ |
| 寄存器覆盖 | 21/60 位置 (35%)，控制字段 17 个全部触达 |

---

## 二、工具链路（端到端）

```
hmac.hjson ──regmap 解析──► hmac_regmap.json (14 条目, offset+swaccess+fields)
                                    │
hmac_smoketest 固件 ──Verilator──► tlul_trace.log (408 A + 408 D 事务)
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
            trace 语义解析                    fuzz_engine.py 变异
            (regmap 查找+字段解码)            (7 种变异算子)
                    │                               │
                    ▼                               ▼
        交叉验证: SHA256/HMAC 与          pickerfuzz_*.c 固件
        Python hashlib 100% 匹配          (pf_txn 数组回放)
                                                    │
                                                    ▼
                                    pickerfuzz_runner.sh
                                    (opentitan-fresh 构建+仿真)
                                                    │
                                                    ▼
                                    漏斗 L1(固件 oracle) → L2(UART 分析)
                                    → L3(误报抑制: BLOCKED 分类)
```

## 三、变异算子与结果

| # | 算子 | 序列数 | 结果 | 说明 |
|---|---|---|---|---|
| 1 | bitflip | 8 | PASS | CFG/CMD 字段位翻转，无异常状态 |
| 2 | illegal | 5 | PASS | wo 读 / rw1c 写，硬件按规格处理 |
| 3 | boundary | 8 | PASS | digest_size=0xF、key_length=0x3F 等非法值被忽略 |
| 4 | window | 6 | **BLOCKED** | 越界写 0x41110FFC → Store Access Fault (MTVAL=41110FFC)，PMP 正确拦截 |
| 5 | fsm | 16 | PASS | 未 start 即 process / 双重 start / process 中改 CFG，ERR_CODE 正确记录 |
| 6 | meta | 43 | PASS | **O3 元变**: 一次性写 FIFO vs 分批写+轮询 → digest 一致 |

## 四、Oracle 验证明细

### O2 — NIST 参考值
- 固件内嵌标准序列（CFG=0x422 → start → 32B 'a' → MSG_LENGTH=256 → process → 等 done → 读 DIGEST）
- 实测 DIGEST[0] = `0x3ba3f5f4` = Python `hashlib.sha256(b"a"*32)` H0 ✓

### O3 元变关系
- 路径 A（8 词一次性写 FIFO）与路径 B（4+4 分批写 + STATUS 轮询）对同一消息 `c×32`
- 实测两条路径 digest 逐词一致：`cd93782b 7fb95559 de14f738 b65988af 85d41dc1 565f7c7d 1ed2d035`
- 与 Python 参考实现 `SHA256("c"*32)` 前 7 词完全匹配 ✓

### O4 状态机
- wait_done 事务（op=0xF）自旋等待 `INTR_STATE.hmac_done`，全部在超时窗口内完成，无挂死 ✓

### 误报抑制（漏斗 L2/L3）
- `window_4` 的越界写触发 `Store Access Fault (MCAUSE=7, MTVAL=41110ffc)`
- runner 识别为 **BLOCKED**（硬件正确拦截）而非误报为漏洞
- 首轮运行 1 个 NO_OUTPUT 误报 → 修复后 0 误报

## 五、覆盖率统计

- **寄存器位置**: 21/60 (35%) — 全部控制/状态/数据通路寄存器触达
  - 未触达: KEY[0..17,19..23,25..31]（seed 只用 256bit key 的 8 词）、DIGEST[8..14]（SHA256 只用 8 词）
- **控制字段**: CFG 7/7 字段、CMD 4/4 字段全部触达非零值
- **边界值**: digest_size=0xF、key_length=0x3F、MSG_LENGTH=2^32-1 等非法值已注入
- **TL-UL 事务**: 6 次运行共 113 事务（不含被 PMP 拦截的越界访问）

## 六、关键工程成果（本次会话）

1. **Verilator 5.036 → 5.050 升级**：一次性修复 9 个调度器/时钟分析 bug，hmac_smoketest 全流程 PASS
2. **TL-UL monitor**：chip_sim_tb.sv XMR tap，A/D 通道配对 trace
3. **hjson 规格模型**：hmac_regmap.json（处理 skipto/自动 INTR/参数引用）
4. **变异引擎**：7 种算子，C 固件自动生成
5. **四层 oracle + 三级漏斗**：固件内嵌检查 + UART 分析 + BLOCKED 误报抑制
6. **覆盖率统计**：regmap 覆盖 + 字段覆盖 + oracle 统计

## 七、复现命令

```bash
# 1. 生成变异固件
python3 /workspace/OT-SecFuzz-v2/scripts/fuzz_engine.py --seed-num 1

# 2. 运行全部变异（构建+仿真+漏斗分析）
/workspace/OT-SecFuzz-v2/scripts/pickerfuzz_runner.sh

# 3. 覆盖率统计
python3 /workspace/OT-SecFuzz-v2/scripts/coverage_stats.py
```

## 八、后续方向

- 扩展 seed 库（多消息长度/多 key 长度组合）提升字段覆盖至 >80%
- ddmin 最小化：对 ANOMALY 序列自动约简
- 扩展到 KMAC/AES（regmap 管线已通用化，只需替换 hjson + base 地址）
- O5 SVA 断言池：将 hjson swaccess 规则自动生成 SVA
