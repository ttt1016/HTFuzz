# HTFuzz 下一步优化计划

## 优先级 1：Agent 架构改进（借鉴 mini-swe-agent）

### 1.1 全量消息历史回传（★★★）
- 现状：history[-8:] 截断，LLM 遗忘早期观测（如标记值写入位置）
- 改进：全量 messages 回传（GLM 128K token 窗口足够）
- 预期：agent 收敛率提升（减少步数耗尽）

### 1.2 格式错误容忍（★★）
- 现状：解析失败直接终止
- 改进：解析失败 → 错误信息回传 LLM → 重新输出（3 次容忍）
- 参考：mini-swe-agent max_consecutive_format_errors = 3

### 1.3 环境抽象接口（★★★）
- 现状：DutHandle 耦合在 llm_agent.py 里
- 改进：拆成 environments/dut_env.py，execute(action) 唯一接口
- 目标：支持多 DUT 实例 → 跨模块联动验证（lc_esc → hmac_wipe → keymgr_invalid）

### 1.4 轨迹回放接口
- 现状：trace 已保存但无回放
- 改进：trajectory JSON → 直接重放验证（可复现性）

### 1.5 成本/时间追踪
- token 用量统计 + wall_time 限制

## 优先级 2：新模块 DUT

### 2.1 rv_dm（Debug Module）
- CSV Bug#0 位置（dmi_jtag），JTAG 调试接口安全边界
- 跨域攻击面最大（CPU ↔ 外部调试器）

### 2.2 keymgr 完整流程 fuzzing
- DUT 已建，用 agent 走完整 key derivation 流程（6 个操作状态）再触发
- Bug#21/64 StCtrlInvalid 可能只是冰山一角

## 优先级 3：跨模块联动验证

### 3.1 联动序列
- lc_ctrl escalation → hmac wipe → keymgr invalid
- 需要多 DUT 环境（依赖 1.3 环境抽象）

### 3.2 时序类注入
- 精确复位/时钟时序触发（当前 oracle 不覆盖）

## 优先级 4：O-K 规则扩展

- no_write_without_enable：未使能时敏感信号不得修改
- monotonic：计数器单调性
- fsm_sparse：FSM 编码稀疏性检查
- pairwise SEC_CM 组合不变量
