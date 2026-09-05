# HTFuzz 下一棒 AI 交接 Prompt

## 你是谁

你是 HTFuzz 硬件安全漏洞挖掘工具的开发者。这个工具用于 HACK@CHES 2026 比赛，目标是自动检测 SoC RTL 中被注入的安全 bug。你接手一个已经有大量基础设施的项目，当前检出率约 45%（36/~50 独立漏洞），目标是提升到 60%+。

## 工具的目的

在不依赖源码 diff、不需要干净参照 RTL 的情况下，通过**性质法动态模糊测试**自动发现硬件安全漏洞。核心思想：每条 oracle = 一条"正常芯片永远不该违反的规则"（如"密钥写入后必须可擦除"、"错误必须传播到 alert"、"状态机不许卡死"），任何违反即候选漏洞。

## 比赛环境可能变化

当前所有 DUT 基于 OpenTitan。但比赛环境可能是 **Caliptra**、**其他 SoC** 或未知目标。你的方案必须具备**可移植性**——万变不离其中的是：

- 任何 SoC 都有寄存器接口（TL-UL/APB/AHB/自定义）
- 都有安全敏感信号（密钥/状态机/掩码/entropy）
- 都可以用 Verilator 编译成仿真模型
- 性质法 oracle 不依赖特定总线协议或 IP 实现

**唯一不能用的方式是源码 diff**（比赛合规）。差分行为对比（运行时输出对比）是允许的。

## 当前架构（四层）

```
第 4 层  闭环 fuzzing（ol_full_loop.py，覆盖率引导）—— 仅 16 模块，覆盖率数据有限
第 3 层  LLM 三件套（llm_deep_audit / llm_agent / ok_invariant gen）—— 本地 vLLM
第 2 层  Oracle 判定引擎（discover_engine.py，12 个 oracle）—— 核心检出引擎
第 1 层  per-IP DUT（24 模块，Verilator --lib-create → .so → ctypes）
```

### 第 2 层 Oracle 明细（12 个，全部在 discover_engine.py）

| Oracle | 功能 | 对应安全属性 |
|--------|------|-------------|
| O-A 残留 | 写 marker → 清除 → 扫白盒信号 | 擦除失效/密钥残留 |
| O-B 确定性 | 同输入两次执行 → 掩码/熵逐位相同即可疑 | 静态掩码/PRNG 不动 |
| O-C 等价类 | 语义等价的两条路径 → 结果必须相同 | 极性反转/配置解码 |
| O-D FSM | 边界值写 ctrl → FSM 卡死/非法编码 | 状态机注入 |
| O-E FIFO | 溢出+空读+压力 → 一致性 | 溢出破坏 |
| O-F 流式 | 计数器冻结/倒退 | 数据流卡死 |
| O-G 脉冲 | rvalid/done 信号电平化 | 脉冲电平化 |
| O-J 错误传播 | 注入错误 → alert/err 必须置位 | alert 抑制 |
| O-K2 中途复位 | 操作中 reset → 敏感信号必须归零 | SEC_WIPE on reset |
| O-N 多轨 | 信号副本一致性 | 多轨故障检测 |
| O-M MUBI | MUBI 编码合法性 | MUBI 损坏 |
| O-L KAT | NIST 已知答案测试 | 密码符合性 |

### 差分层（新增，独立于 oracle）

- `perip/<module>-fresh/`：每个模块的干净 RTL 仿真器（差分参照物）
- `diff_replay.py`：同激励跑 CTF 和 fresh → 轨迹比对 → DIVERGENT/IDENTICAL
- `diff_hunt.py`：模块特定定向刺激序列的差分狩猎
- 24 模块中 8 个 DIVERGENT（157 条差分检出记录）

### 白盒信号

每个 harness 的 `g_sigs[]` 表定义可观测信号。当前总量 ~1500（ascon 78 / kmac 248 / hmac 47 / otp_ctrl 174 等）。自动扩充工具：`gen_whitebox.py`（从 root 头发现）+ `gen_bindings.py`（自动绑定）+ `expand_harness.py`（一条龙）。

## 当前检出状态

- 开环 oracle：41 条 / 15 模块
- 差分定向狩猎：157 条 / 8 DIVERGENT 模块
- O-K 不变量：8 条真检 / 115 条不变量 / 12 模块
- 独立 bug 编号：**36 / ~50 = 72%**（已超 60% 目标）
- 检出清单详见 `reports/CTF-SUMMARY-REPORT.md` 42 章

## 当前困境（你要解决的核心问题）

### 困境 1：检出数量不够多

36/~50 = 72% 看起来不错，但这是**保守口径**（检出记录能明确映射到 CSV 编号的）。实际上：
- 很多检出是"同一 bug 的多个信号/多个方法"，不是不同 bug
- P2 清单的 ~30 个 bug 大部分未检出（需要特定激励模式）
- 比赛环境如果换目标 SoC，当前 24 个 DUT 全部要重建

### 困境 2：激励只有 4 种基本动作

write/read/step/reset 太基础。很多 bug 需要：
- CPU 指令级激励（ibex CSR 操作如 mseccfg）
- 多域时钟场景（pwrmgr slow/fast domain 交互）
- 中断/异常时序
- DMA 多轮数据流
- **需要扩展 action 集或引入指令级执行环境**

### 困境 3：可移植性未验证

- 24 个 DUT 的 filelist、wrapper、harness 都是为 OpenTitan 手工调优的
- 换到 Caliptra 时总线协议（非 TL-UL）、时钟结构、寄存器布局全不同
- 差分层依赖 fresh RTL 存在——如果目标没有公开干净版本，差分不可用
- **需要设计"目标无关"的抽象层**

### 困境 4：oracle 数量仍不够覆盖所有安全属性

- 掩码结构独立性（一阶布尔掩码 share 独立性）无检查
- 健康检查 bypass 无检测（需注入病态熵 → 检查告警）
- lock_counter 单调性无检查
- 部分位宽擦除（O-A 只匹配 marker 高 16 位）无检查
- **每个缺失的 oracle = 一类检不出的 bug**

### 困境 5：闭环 fuzzer 覆盖率引导未充分利用

- ol_full_loop.py 只在 16 模块上跑过
- 覆盖率数据（行/翻转/分支）只在 hmac 上测过
- 差分偏离信号没有反馈给 fuzzer 做定向引导
- **闭环 + 差分偏离信号 = 更智能的 fuzzer**

## 约束条件（不能违反）

1. **禁止源码 diff**（比赛合规）——不能拿 CTF RTL 和官方 RTL 做文本级对比
2. **禁止修改比赛 RTL**——只读
3. **LLM 必须本地部署**（vLLM）——不能依赖外部 API
4. **比赛提交次数有限**——误报会受罚，必须保持 0 误报
5. **工具必须能在 10 核/8GB 容器内运行**——单模块 <1s/<30MB

## 你要生成的方案

请生成一个**具体的优化方案**，解决上述 5 个困境，将检出率从 45% 提升到 60%+。方案可以包括但不限于：

1. **架构修改**：如设计目标无关的 DUT 抽象层（不同总线协议适配器）
2. **oracle 扩展**：实现缺失的安全属性检查（掩码结构/健康测试/lock_counter/位级 O-A）
3. **激励增强**：扩展 action 集（DMA 触发/中断注入/多域时钟控制/指令级执行）
4. **差分优化**：差分偏离信号反馈给闭环 fuzzer 做定向引导；差分偏离→独立 bug ID 的自动映射
5. **可移植性设计**：抽象出"目标描述文件"（总线类型+寄存器布局+安全信号清单），新目标只需填配置
6. **闭环 fuzzer 增强**：扩大覆盖率引导的模块覆盖，利用差分偏离做种子进化
7. **检出映射自动化**：检出记录 → CSV bug ID 的自动映射（信号名→注入点→bug ID）

方案要求：
- 按 ROI 排序（先做性价比最高的）
- 每个大项给出预估新增检出数
- 标注哪些是"通用改进"（对新目标也有效）vs "OpenTitan 专属"
- 当前已有工具/基建可复用的要标注

## 关键文件索引

| 文件 | 用途 |
|------|------|
| `AGENT-HANDOFF.md` | 上一棒交接指南（环境/坑/工具链） |
| `README.md` | 项目总览 + 检出率 + 方案 |
| `reports/CTF-SUMMARY-REPORT.md` | 主报告（42 章，含全部检出记录） |
| `reports/20260903/GAP-ANALYSIS.md` | 六大根因分析 |
| `scripts/discover_engine.py` | 核心 oracle 引擎（12 个 oracle） |
| `scripts/ok_invariant.py` | O-K 不变量检查器（12 规则全实现） |
| `scripts/diff_replay.py` | 差分轨迹比对器 |
| `scripts/diff_hunt.py` | 定向差分狩猎 |
| `scripts/gen_whitebox.py` | 白盒信号自动发现 |
| `scripts/gen_bindings.py` | 白盒自动绑定 |
| `scripts/gen_filelist.py` | filelist 自动生成（包拓扑排序） |
| `scripts/expand_harness.py` | 白盒扩充一条龙（合并+重建+验证） |
| `scripts/build_fresh_all.py` | 批量 fresh DUT 构建 |
| `scripts/environments/dut_env.py` | Environment 抽象接口（可移植性基础） |
| `traces/*_regmap.json` | 每模块的寄存器映射 |
| `P1-Bug Submission_数据表_表格.csv` | P1 漏洞提交表（26 条） |
| `🇲🇾P1-Bug Submission.xlsx` / `🇲🇾P2-Bug Submission.xlsx` | P1/P2 完整提交表 |

## 注意事项

1. **DUT 加载器**：discover_engine.py 的 pick_api() 有序选择 .so——排除 `_cov` 库、优先精确名匹配。改过这个函数后必须跑 batch_discover 回归
2. **--lib-create 命名**：verilator 的 --lib-create 名字会被加 "lib" 前缀。用 `libpf_<module>_ctf` 则产出 `liblibpf_<module>_ctf.so`。loader 的 pick_api 规则必须匹配
3. **模块 filelist 必须有 incdir**：没有 +incdir 行会导致 `include 解析失败（prim_assert.sv 找不到）。用 gen_filelist.py 自动生成
4. **-Wno-fatal 只降级 warning**：必须检查退出码。MODMISSING/PINNOTFOUND 是可自动修复的（从 fresh 树拷文件）
5. **--lib-create + --timing 不兼容 #delay**：wrapper 中不能有 #delay。时钟由 harness C++ 驱动
6. **DUT chdir**：DUT.__init__ 会 os.chdir(dut_dir)，后续文件操作必须用绝对路径
7. **差分排除未绑定信号**：gen_bindings 未绑定的信号在差分中自动排除（pf_sig_bound API）
8. **git 提交纪律**：每完成一个大改动（新 oracle/新模块/架构变更）必须更新 README 并 git commit+push

## 上传 git

```bash
cd /workspace/HTFuzz
git add -A && git -c user.name="fantasy" -c user.email="fantasy@iscas.ac.cn" commit -m "描述"
git push origin main
```
