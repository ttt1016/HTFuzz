# HTFuzz 检出能力差距分析 —— 对照 P1/P2 提交清单（2026-09-03）

## 0. 结论摘要

P1+P2 提交清单去重后约 **80 个独立 bug**（P1 38 条记录、P2 73 条记录，含同一 bug 的多版本）。
工具当前动态检出覆盖其中 **约 16 个 bug ID**（本轮全量扫描 21 条记录对应 10 个 ID + 历史检出）。
其余约 64 个检不出的 bug 归因为 **6 大结构性根因**，按修复 ROI 排序见第 3 节。

## 1. 工具构成（深读代码后的准确画像）

### 1.1 激励层（第 1 层：DUT 构建）
- 21 个 `perip/*-ctf` 目录，其中 **18 个有编译好的 .so**（lc/uart/csrng 无 obj_so、prim 无 -ctf）。
- 每个 DUT = SV wrapper（IP + 邻居 tie-off）+ C++ harness。
- **激励只有 4 种动作**：`pf_write`(TL-UL 寄存器写)、`pf_read`、`pf_step`(推拍)、`pf_reset`。
- 时钟由 harness C++ 驱动；`--lib-create` 模式，DPI export 不可用。

### 1.2 观察层（白盒信号表）
- 每个 harness 一个**手工维护的静态 `g_sigs[]` 表**，只有表内信号可观测（`pf_sig_read(name,w)`）。
- 实测规模：aes 6 个、kmac 3 个、ascon 4 个、rom_ctrl 3 个、hmac 43 个（P2 扩展后）、entropy_src 36 个、keymgr 10 个（指向修正常）。

### 1.3 Oracle 层（discover_engine.py，7 个盲测 oracle）
| Oracle | 机制 | 检测目标 |
|--------|------|---------|
| O-A 残留 | marker(0xDEADxxBE) 写 key/wdata 类寄存器 → 随机 clear 序列 → 扫描敏感信号残留 **marker 高16位** | 擦除失效/残留 |
| O-B 确定性 | 名字含 mask/entropy/rnd/lfsr 的信号，两次执行逐位相同 | 静态掩码/PRNG 不动 |
| O-C 等价类 | cfg/ctrl 寄存器"两阶段写"vs"中间插读"→ 控制信号终态差异 | 读副作用/相位错误 |
| O-D FSM | 边界值写 ctrl → FSM 卡死/非法编码 | 状态机注入 |
| O-E FIFO | 溢出写+空读+压力后两次一致性 | 溢出破坏 |
| O-F 流式 | 计数器 300 拍冻结/倒退 | 数据流卡死 |
| O-G 脉冲 | 需 harness 提供 pf_rvalid_cycles/pf_done_residual（**仅 rom_ctrl 实现了**）| 脉冲电平化 |

- 信号自动分类按**名字关键字**（sensitive: key/secret/seed/digest/hash/mask/entropy...；
  control: state_q/_q/fsm/ctrl/cfg/sm_）。

### 1.4 专用与 LLM 层
- O-H/O-I：ibex 专用单元 TB（PMP/特权），**fork 注入版 vs clean 版对比**判定。
- O-K（ok_invariant.py）：LLM 生成不变量 + 通用检查器。
  **12 种规则只实现 3 种**（wipe_clears / changes_across_runs / read_only_leak），
  **9 种是 `pass` 桩**：reg_core_consistent、access_control、cfg_block_gating、
  fsm_sparse_encoding、err_code_coherent、interrupt_first_event、bus_intg_check、
  monotonic_counter、debug_lock_enforce。
- llm_deep_audit（静态审计）、llm_agent（ReAct 动态验证）——未进入自动批量回路。

## 2. 六大根因 ↔ P1/P2 bug 映射

### 根因 1：模块没有 DUT（约 18 条 bug 直接无载体）
| 模块 | 受影响 bug | 数量 |
|------|-----------|------|
| otbn（无 otbn-ctf） | P1 #7/#15/#35/#36、P2 #12/#13/#14（secure_wipe_req 硬线0、dmem_rerror=0、imem/dmem blanker 旁路） | 7 |
| otp_ctrl（无 otp-ctf） | P1 #16/#17/#37、P2 #46/#57（DAI predictor 锁、seed_valid 校验、debug lock） | 5 |
| gpio | P1 #13 | 1 |
| adc_ctrl | P1 #21（FSM 永久锁死） | 1 |
| tlul_adapter | P1 #34（地址截断，横切原语） | 1 |
| mbx_imbx | P2 #55（abort-clear 授权） | 1 |
| spi_device/spi_tpm | P2 #58（locality 门控） | 1 |
| csrng（obj_so 为空） | P1 #31（RESEED_INTERVAL） | 1 |

### 根因 2：激励到不了（CPU 指令级/多域场景，约 8 条）
- ibex msecfg.MML/MMWP 可清零（P1 #5/#6）、icache 强开（P1 #32/P2 #23）：
  需要 **M-mode 指令序列**（写 mseccfg → 读回验证位不可清）。TL-UL 寄存器激励原理上无法触达 CSR 语义；
  ibex-ctf 是最小核 TB，无固件执行通路。O-H/O-I 的 fork-vs-clean 模式可复用，但需要新建 CSR 单元 TB。
- lc_ctrl（P1 #2/#3/#14/#22、P2 #3/#4/#17）：lc-ctf 无 obj_so，只有 lc_fsm_test 单元 TB（覆盖 Bug#28）。
  hash 校验截断/IdleSt 非法转移需要扩展该 TB 场景。
- keymgr Invalid State 暴露（P1 #4、P2 #5/#52）：任务 3 已打通 harness 到 StCtrlInvalid，
  但判定需要的 **key_o 输出被 Verilator 剪除**（悬空端口）——需在 wrapper 里接上 aes/kmac sideload 消费者。

### 根因 3：O-K 规则桩（约 10 条，修复性价比最高）
| 桩规则 | 直接对应的 P2 bug |
|--------|------------------|
| cfg_block_gating | #33 hmac cfg_block 写门控 |
| err_code_coherent | #42 hmac ERR_CODE 置位 |
| interrupt_first_event | P2-None hmac 中断首次事件 |
| fsm_sparse_encoding | #45 keymgr_data_en_state 非法态检测 |
| bus_intg_check | #34 tlul 地址截断 |
| access_control | #54 kmac_core key-ready 门控、#58 spi_tpm locality |
| reg_core_consistent | #35/#40 entropy_src MUBI 同步/CSR 锁 |
| monotonic_counter | #16 otp lock_counter predictor |
| debug_lock_enforce | #46 otp_ctrl_pkg debug lock |

### 根因 4：白盒观察表缺口（约 12 条）
- **aes 仅 6 个信号**（data_in_prev_q/key_init/data_out_q/key_full_q/key_dec_q/data_out_we）。
  P2 新 bug 的目标信号全部不可见：
  - aes_cipher_core 轮密钥寄存器（#25 SEC_WIPE）
  - aes_ctr/aes_ctr_fsm 状态与 alert（#27/#28/#29）
  - aes_mix_columns（#30/#39）、aes_shift_rows（#32/#48）
  - aes_key_expand（#37/#38/#51）
- kmac 仅 3 个信号：kmac_core（#54）、kmac.sv entropy 路径（#53）不可见。
- hmac：hmac_core（#43 SHA-512）、hmac.sv cfg_block（#33）信号未暴露。
- rom_ctrl 仅 3 个：#26 alert 抑制信号缺。

### 根因 5：oracle 语义盲区（信号可见也检不出，约 10 条）
- **中途复位场景缺失**：P2 #21/#22（aes data_in_prev/data_out SEC_WIPE on reset）
  ——O-A 只做"写→清→扫"，从不做"操作中途 pf_reset"。
- **alert/error 传播 oracle 缺失**：P2 #26/#27/#28/#29/#19（alert 抑制、多轨故障检测、
  alert 门控）——需要"注入错误 → alert_o/err_q 必须置位"的负向测试；
  且 `classify()` 的关键字表 **不含 alert/err**，alert 类信号自动归入 other 不被任何 oracle 观察。
- **掩码结构盲区**：P2 #15/#30/#32/#47/#48/#56（一阶布尔掩码 share 独立性、
  SecAllowForcingMasks 强制）——O-B 只检"静态"不检"结构"。
- **健康检查 bypass**：P1 #11 markov HT —— 需要"制造病态熵 → 检查告警"，属负向注入。

### 根因 6：O-A marker 匹配的原理性局限
- 只匹配 marker 高 16 位、只写 4 word×4 target、clear 动作从 regmap 名字猜——
  对"擦除后回读注入"（P2 #44 unmapped read error）、"部分位宽擦除"（P2 #2 wipe 只写 32bit）
  依赖的**读路径/位级语义**没有对应检查。

## 3. 修复路线（按 ROI 排序）

| 优先级 | 动作 | 预期新增检出 | 成本 |
|--------|------|-------------|------|
| P0 | **实现 O-K 的 9 个规则桩**（纯 Python，无需新 DUT；baseline 对比 + 寄存器读回即可） | 直接覆盖根因 3 的 ~10 条 | 1-2 天 |
| P0 | **classify() 关键字表加 alert/err/status** + 新增 **O-J：错误传播 oracle**（写非法配置/触发错误 → alert/err 信号必须置位） | 根因 5 的 alert 类 ~6 条 | 1 天 |
| P1 | **补 4 个 DUT**：csrng（重编 obj_so）、otbn、otp_ctrl、mbx/spi_tpm | 根因 1 的 ~18 条载体 | 每个 0.5-1 天 |
| P1 | **扩充观察表**：用 SEC_CM 注释+reg_pkg 自动生成候选信号表再人工筛选（aes 需 +20 信号） | 根因 4 的 ~12 条 | 1 天 |
| P2 | 新增 **O-K2：中途复位 oracle**（活动操作中 pf_reset → 敏感信号必须归零） | P2 #21/#22 类 | 0.5 天 |
| P2 | ibex **CSR 单元 TB**（fork-vs-clean：mseccfg/icache） | P1 #5/#6/#32 | 1 天 |
| P3 | lc_fsm/keymgr 单元 TB 扩场景；keymgr wrapper 接 sideload 消费者 | lc/keymgr ~6 条 | 1-2 天 |

## 4. 数据来源
- P1 清单：`🇲🇾P1-Bug Submission.xlsx`（38 条记录）
- P2 清单：`🇲🇾P2-Bug Submission.xlsx`（73 条记录）
- 工具代码：`scripts/discover_engine.py`（7 oracle 全文）、`scripts/ok_invariant.py`（12 规则 3 实现）、
  `perip/*-ctf/harness/*.cpp`（g_sigs 观察表实测）
