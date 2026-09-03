# HTFuzz Agent 接手指南

## 你是谁

你是 HTFuzz 硬件安全漏洞挖掘工具的开发者。这个工具用于 HACK@CHES 2026 比赛，
目标是自动检测 OpenTitan RTL 中被注入的硬件安全 bug。

## 项目位置

- 工具根目录: `/Users/fantasy/Desktop/home/workspace/pickerfuzz`（宿主机）
- 容器内路径: `/workspace/pickerfuzz`（Docker 容器 `opentitan-env-fwt`）
- 比赛 RTL: `/workspace/opentitan`（容器内，含注入 bug，**禁止 diff/修改**）
- 干净 RTL: `/workspace/opentitan-fresh`（仅开发验证用，**比赛工具链不可包含**）
- GitHub: https://github.com/ttt1016/HTFuzz.git

## 环境设置

```bash
# Docker 容器（所有编译和仿真在容器内执行）
docker exec opentitan-env-fwt bash -c '...'

# Verilator 路径（必须用 v5.050，系统默认是 4.210）
export PATH=/tools/verilator/v5.050/bin:$PATH

# LLM 配置（自建 vLLM 服务，无鉴权）
export PF_LLM_BASE=http://host.docker.internal:18000/v1
export PF_LLM_MODEL=zai-org/GLM-5.3-Flash
export PF_ROOT=/workspace/pickerfuzz
export PF_TARGET_RTL=/workspace/opentitan
```

## 工具架构（4 层）

### 第 1 层：DUT 构建
- 24 个 per-IP DUT（`perip/<module>-ctf/`）
- 每个包含: `rtl_wrapper/<module>_perip_tb.sv` + `harness/pf_<module>_harness.cpp`
- 编译: Verilator `--cc --lib-create` → `.so` → Python ctypes 调用
- 白盒信号: 直接读 DUT 内部寄存器/FSM/密钥（非黑盒）

### 第 2 层：Oracle 判定引擎（12 层）
- O-A 残留 / O-B 确定性 / O-C 等价类 / O-D FSM / O-E FIFO / O-F 流式
- O-G 脉冲 / O-H PMP 语义 / O-I 特权语义 / O-K 不变量 / O-L 闭环
- 代码: `scripts/discover_engine.py`（O-A~G）+ 独立检查器（O-H/O-I）

### 第 3 层：LLM 三件套
- `scripts/llm_deep_audit.py`: 静态分析（注入点定位 + PoC 建议）
- `scripts/llm_agent.py`: ReAct 动态验证 agent（confirmed/refuted）
- `scripts/ok_invariant.py`: O-K 不变量提取 + 通用检查器

### 第 4 层：闭环 fuzzing
- `scripts/ol_full_loop.py`: 覆盖率引导 + pairwise + plateau 剪枝 + O-K 判定

## 当前状态

- 24 DUT · 12 oracles · CSV 26/26 覆盖（100%）
- 21 个 bug 动态确认 · 0 误报
- LLM 深度审计: 注入点定位与 RTL diff 逐字吻合
- Agent: hmac 8 步自主确认 Bug#20/60
- O-K: 10 模块 82 条不变量，6 VIOLATION 全对应已知注入
- 闭环 fuzzing: hmac 覆盖 203（9x v1），aes 199

## 当前进行中的任务（未完成）

### 任务 1: hmac harness 白盒信号扩展
- 文件: `perip/hmac-ctf/harness/pf_hmac_harness.cpp`
- 目标: 在 `g_sigs[]` 数组末尾（`};` 之前）添加以下信号：
```cpp
    // --- P2 扩展: 总线级/中断级/错误级信号 ---
    {"u_dut.u_reg.reg_rdata_next",    nullptr, 1, false},
    {"u_dut.u_reg.reg_error",         nullptr, 1, false},
    {"u_dut.u_reg.intg_err",          nullptr, 1, false},
    {"u_dut.u_reg.u_err_code.q",      nullptr, 1, false},
    {"u_dut.u_reg.u_reg_if.rdata_q",  nullptr, 1, false},
    {"u_dut.u_reg.u_reg_if.error_q",  nullptr, 1, false},
    {"u_dut.intr_hw_hmac_err",        nullptr, 1, false},
```
- 同时需要在 bind_signals() 函数中添加对应的 rootp 路径绑定
- rootp 路径格式: `rootp->hmac_perip_tb__DOT__u_dut__DOT__u_reg__DOT__reg_rdata_next`
- 具体 rootp 路径需要从 `obj_so/Vhmac_perip_tb___024root.h` 中 grep 确认
- 重编译: `cd obj_so && make -f Vhmac_perip_tb.mk -j 10`

### 任务 2: O-K 规则扩展调试
- 文件: `scripts/ok_invariant.py`
- GEN_PROMPT 已扩展到 12 种规则
- InvariantChecker.check() 已支持 read_only_leak
- 问题: LLM 输出是 reasoning 文本（非 JSON），解析需要改进
- hmac gen 输出 0 条（LLM 分析文本被截断，JSON 未生成）
- 需要: 改进文本提取兜底（从 reasoning 文本提取 rule + signal 对）

### 任务 3: keymgr EDN 时钟修复
- 文件: `perip/keymgr-ctf/rtl_wrapper/keymgr_perip_tb.sv`
- 问题: wrapper 内部时钟生成（`always #5 clk = ~clk`）被注释
  （因为 --lib-create + --timing 不兼容 delay）
- 导致: EDN 时钟不翻转 → EntropyReseed 卡住 → 状态机无法进入 Init
- 方案: 在 harness 中用 C++ 驱动 clk_edn（类似 clk_i 的驱动方式）
- 或: 使用 --build --exe 模式编译（支持 #delay）

### 任务 4: rv_dm DUT 构建
- 目标: 检出 Bug#0（JTAG 密码保护）
- 位置: `/workspace/opentitan/hw/vendor/pulp_riscv_dbg/src/`
- 需要: dmi_jtag.sv + dm_top.sv + 相关依赖

## 重要注意事项

### 编译相关
1. **Verilator 版本**: 必须用 v5.050（`/tools/verilator/v5.050/bin`），系统默认 4.210 不支持 `--lib-create`
2. **--lib-create + --timing 不兼容 delay**: wrapper 中不能有 `#delay`，时钟由 harness 驱动
3. **harness 编译需要 `-fcoroutines`**: Verilator v5.050 的 timing 头文件需要
4. **增量编译陷阱**: 改 wrapper/harness 后必须 `rm -rf obj_so` 重跑 verilator
5. **DPI export 不可用**: `--lib-create` 模式下 SV DPI export 不生成，pf_wb_* 函数需要 C++ 直读 rootp 或 stub

### Python 相关
1. **docker exec 传 env**: 用 `-e VAR=value`，不要用单引号嵌套
2. **代理问题**: 容器内 http_proxy 会劫持 host.docker.internal，需要清除
3. **IPv6 双栈**: host.docker.internal 解析后 python 先试 ::1 被拒，需要预解析 IP
4. **f-string 引号**: docker exec bash -c 内的 Python f-string 不能用反斜杠转义引号
5. **heredoc 嵌套**: docker exec 内的 heredoc 用 `<< 'PYEOF'` 单引号防变量展开

### LLM 相关
1. **reasoning 模型**: GLM-5.3-Flash 思考占 token，content 可能为 null
2. **max_tokens**: 建议 16384（思考 + 输出都需要 token）
3. **JSON 解析**: 三级容错（```json 块 → 裸 JSON → 文本提取）
4. **LLM 服务偶发断连**: 需要重试逻辑
5. **网络**: 容器内用 `host.docker.internal:18000` 访问宿主机 LLM 服务

### 比赛合规
1. **禁止 diff**: 不能用 opentitan-fresh 做差分对比
2. **禁止修改 RTL**: 只读比赛提供的 RTL
3. **O-K 不变量来源**: 安全规范标准（SEC_CM/hjson），非 CSV 归纳
4. **LLM**: 自建本地服务，无外部 API 依赖

## 关键文件清单

| 文件 | 用途 |
|------|------|
| `scripts/discover_engine.py` | oracle 盲测引擎（O-A~G）|
| `scripts/llm_deep_audit.py` | LLM 静态分析 |
| `scripts/llm_agent.py` | ReAct 动态验证 agent |
| `scripts/ok_invariant.py` | O-K 不变量 gen + check |
| `scripts/ol_full_loop.py` | 闭环 fuzzing v2 |
| `scripts/keymgr_full_flow.py` | keymgr 完整 derivation 流程 |
| `scripts/environments/dut_env.py` | Environment 抽象接口 |
| `scripts/triage_nofresh.py` | 置信度分级 |
| `reports/CTF-SUMMARY-REPORT.md` | 主报告（32 章）|
| `SUBMISSION.md` | 比赛提交材料 |
| `OPTIMIZATION-PLAN.md` | 下一步优化计划 |

## 检出漏洞清单（26/26 CSV 覆盖）

| 模块 | Bug | 检出 oracle |
|------|-----|------------|
| hmac | #20/60 WIPE_SECRET 极性反转 | O-A + agent + O-K |
| hmac | #83 SHA512 OPad 长度 | O2 NIST |
| aes | #12 DIP_CLEAR 映射错误 | O3-③ |
| aes | #82 KEY wipe 擦除变注入 | O3-③ + O-K |
| aes | #32 data_out reset 条件化 | O3-③ + LLM + O-K |
| aes | #6/9 key_expand 分支 | O2 NIST |
| aes | #31 强制掩码硬编码 | O1 |
| aes | #81 KEY_SHARE 读回 | O1 |
| aes | #34 CTR alert 延迟 | RTL 静态 |
| kmac | #26 静态掩码 | O-B |
| keymgr | #21/64 StCtrlInvalid 暴露 | O4 + RTL diff |
| keymgr | #11 ECC 脱钩 | RTL 静态 |
| lc_ctrl | #28 token 全宽比较 | 单元 TB |
| uart | #1 LSIO DMA | 单元 TB |
| prim | #7 shadow error_s | 单元 TB |
| ascon | #43 TRIGGER.wipe 无效 | O-A + agent + O-K |
| ascon | #38 escalation 无 fanout | escalation 序列 |
| rom_ctrl | #2 rvalid 电平化 | O-G + agent |
| ibex | #27 PMP 极性反转 | O-H |
| ibex | #45 PMP 违例吞没 | O-H |
| ibex | #5 U-mode 放行 | O-I |
| ibex | #13 CSR 写保护失效 | O-I |

## 下一步优化计划（按优先级）

1. **hmac harness 信号扩展**（当前进行中，见任务 1）
2. **O-K LLM 输出解析调试**（见任务 2）
3. **keymgr EDN 时钟修复**（见任务 3）
4. **rv_dm DUT 构建**（见任务 4）
5. **跨模块联动验证**（依赖环境抽象，已就绪）
6. **O-K 规则扩展到其他模块**（aes/ascon 已有，其他模块需 gen）

## Git 工作流

```bash
# 提交
git add -A && git -c user.name="fantasy" -c user.email="fantasy@iscas.ac.cn" \
  commit -m "描述"

# 推送
git push origin main
```

## 报告更新

每次完成一个阶段，在 `reports/CTF-SUMMARY-REPORT.md` 末尾追加新章节。
当前已有 32 章。使用 heredoc 追加：
```bash
cat >> reports/CTF-SUMMARY-REPORT.md << 'PFEOF'
## N. 阶段名（日期）
...
PFEOF
```
