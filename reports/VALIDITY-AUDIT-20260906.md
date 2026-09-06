# 工具有效性审查（2026-09-06）

## 背景与动机

36/50（72%）检出率是在"提升检出率"这一 goal 的迭代驱动下产生的。本审查回答一个问题：
**这个数字度量的是工具能力，还是对已知清单的靶向拟合？** 比赛会更换环境，靶向拟合的
数字在新环境下无价值。

## 一、完整性检查：运行时无作弊 ✅

- 管线代码（discover_engine / triage_nofresh / diff_* / llm_*）**不消费** CSV/漏洞清单，
  无 bug ID 查表逻辑。
- 设计靶向确实存在（GAP-ANALYSIS 逐 bug ID 驱动了 oracle 补齐与阈值调参），但属于
  设计时导向，不构成运行时数据泄漏。

## 二、阴性对照实验（本审查核心，2026-09-06 执行）

**方法**：对全部 fresh（干净 RTL）DUT 运行完整 12-oracle 引擎与 O-K 不变量检查器。
干净 RTL 上任何 finding 均为纯误报（无注入则无真阳性）。此前报告从未做过该对照。

### 2.1 开环 oracle 层：70 条误报 / 22 模块

| 模块 | 误报 | 构成 |
|------|------|------|
| aes | 37 | O-B 12 / O-C 16 / O-K2 6 / O-A 2 / O-J 1 |
| hmac | 23 | O-A 12 / O-K2 6 / O-D 3 / O-J 1 / O-L 1 |
| kmac | 3 | O-B 2 / O-J 1 |
| rom_ctrl | 1 | **O-G（正是 #2 的记账依据，干净 RTL 上原样触发）** |
| clkmgr/csrng/entropy_src/ibex/rstmgr/rv_dm | 各 1 | 全部 O-J |
| 其余 12 模块 | 0 | — |

（keymgr/lc/uart 缺 regmap、otbn/sram_ctrl 缺 fresh .so，未纳入；见行动项）

### 2.2 判别力检验：开环检出对"是否注入"零判别力

CTF 开环记为"检出"的 (oracle, signal) 组合与干净 RTL 上的误报**完全重合**：

- aes：CTF 9 个组合 ↔ 干净 RTL 9 个，**重合 9/9，CTF 独有 0**
- hmac：CTF 6 个组合，**重合 6/6，CTF 独有 0**
- O-K 层：hmac 3/3 重合、aes 1/1 重合（wipe_clears 规则）

### 2.3 根因：属性规范错误（不是实现 bug）

| Oracle | 规范错误 | 干净 RTL 的真实行为 |
|--------|---------|-------------------|
| O-A 残留 / O-K2 / O-K wipe_clears | 要求"擦除后**归零**" | OpenTitan wipe = **随机化覆写**（XOR 随机值），擦除后非零是正确行为 |
| O-B 确定性 | 同输入两遍 → 掩码类信号相同即可疑 | 确定性仿真里 PRNG 序列天然逐位可复现，触发与注入无关 |
| O-C 等价类 | 中间插读 → 终态不同即可疑 | 中间读副作用是合法行为（oracle 自己的 desc 都承认这点） |
| O-J 错误传播 | 40 拍内不告警即报 | 合法设计存在不告警/迟告警路径，8/22 模块干净 RTL 上触发 |
| O-G 脉冲 | residual>0 即电平化 | rom_ctrl 干净 RTL 上 residual 非零（harness 计数伪影或上游行为） |

### 2.4 仍然站得住的证据

1. **差分层（DIVERGENT / DIFF-CONFIRMED）**——内建干净基线对比，是唯一对注入
   有判别力的自动机制。hmac secret_key 78 拍偏离、aes data_out_we idx=0、kmac
   msg_valid、keymgr FSM、entropy_src err、clkmgr/pwrmgr/rv_timer 等。
2. **单元 TB**（lc/uart/prim/ibex/keymgr 手写断言）——验证具体错误行为，有效，
   但属人工分析产出。
3. O-K 的非 wipe 规则（access_control/fsm_sparse/bus_intg 等）阴性对照 0 误报，
   质量合格。

### 2.5 修正后的可信口径（待逐条重审后定稿）

| 口径 | 估计 | 说明 |
|------|------|------|
| 原口径 | 36/50 (72%) | 含大量不可判别证据，**不成立** |
| 修正口径（差分确认 + 单元 TB） | **~20/50 (≈40%)** | 需对 36 条逐条重审证据链后定稿 |
| 工具自动+可判别 | ~10/50 | 纯差分层——换环境可复现的核心能力 |

每条历史检出按"差分确认 / 单元 TB / 仅开环"三档重新标注前，不得对外引用 72% 数字。

## 三、口径拆分与靶向问题

- 手写定向 TB（lc_fsm T4"hash 截断"等）是看着已知 bug 描述写的，换环境需人工重写。
- diff_hunt DIRECTED 序列同理，且其 diff_traces 未复用 diff_replay 的两遍稳定集
  过滤，假偏离可能混入 157 条差分记录（待修复后重算）。

## 四、变异测试扩族计划（样本外有效性）

现注册表仅 hmac/wipe_noop。**前提：先修 2.3 的属性规范**，否则测的是坏 oracle 的
杀伤率。扩族矩阵（每属性族 ≥2 变异体，先 hmac/aes 试点）：

| 属性族 | 变异手法 | 预期杀伤 oracle |
|--------|---------|----------------|
| 数据擦除 | wipe_secret_we 极性反转 / 擦除只写低位 | O-A(修正后), O-K2, 差分 |
| 访问控制 | REGWEN 锁检查删除 / cfg_block 门控反转 | O-K access_control, O-J |
| 随机性/掩码 | PRNG 挂起 / 掩码 share 恒零 | O-B(加基线后), O-K changes_across_runs |
| FSM 稀疏编码 | 状态编码位翻转 / next_state 卡死 | O-D, O-K fsm_sparse |
| 总线完整性 | 越界响应 error 置位删除 | O-J T2, O-K bus_intg |
| 冗余一致性 | 比较器输出恒真 / 单轨化 | O-N |
| MUBI | True/False 编码交换 | O-M |
| 错误传播 | alert 抑制 / err_code 不更新 | O-J(加基线后) |
| 时序安全 | done 脉冲电平化 | O-G(修伪影后) |
| 密码符合性 | KAT 路径提前 done | O-L |

验收口径：杀伤率 <100% 的族即工具盲区，直接转化为 oracle 改进项。

## 五、换环境预期（诚实评估）

| 资产 | 换环境后 |
|------|---------|
| **差分层（判别力核心）** | 保留，但依赖干净 RTL 可得性；不可得时需"单 DUT 模式"替代 |
| O-K 非 wipe 规则 | 保留（阴性对照 0 误报） |
| 白盒自动扩表 / gen_bindings / gen_filelist | 保留 |
| 开环 oracle 现状 | **必须先修属性规范（2.3），否则输出不可用** |
| 手写定向 TB + diff_hunt DIRECTED | 归零重来（人工分析） |
| DUT 加载器 ×3 / 硬编码路径 / TL-UL wrapper | 每模块数小时手工重建 ×28 |

## 六、行动项（按优先级）

- [ ] **P0 修属性规范**：O-A/O-K2/O-K wipe_clears 改为"marker 消失"判据（非"归零"）；
  O-B 加两遍非确定性基线；O-J/O-C 加干净基线校准。修完重跑阴性对照，目标误报 →0
- [ ] **P0 重记账**：36 条历史检出按证据链三档重标（差分确认 / 单元 TB / 仅开环），
  对外只引用前两档
- [ ] **P0 差分确认设为检出必要条件**：triage 的 DIFF-CONFIRMED 机制已有，
  升级为管线强制门（无 fresh 参照的模块显式标注"未验证"）
- [ ] P1 补齐对照盲区：keymgr/lc/uart regmap、otbn/sram_ctrl fresh .so
- [ ] P1 diff_hunt 补两遍稳定集过滤
- [ ] P2 变异扩族（第四节矩阵，在 P0 修复后执行）
- [ ] P2 盲测演练：清单外 IP 全管线冷启动

## 七、实验产物与复现

- `fuzz/nc_discover_<module>.json`：22 模块干净 RTL 开环检出原始记录
- `fuzz/nc_invariant_<module>.json`：O-K 阴性对照原始记录
- `fuzz/nc_summary.csv`：开环阴性对照汇总
- 复现：`docker exec opentitan-env-fwt bash /workspace/HTFuzz/scripts/negative_control.sh`
  （注意：会临时覆盖 fuzz/discover_*.json，跑完 `git checkout -- fuzz/` 还原）
