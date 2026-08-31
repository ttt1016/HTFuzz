# VULN-106: KEYMGR StCtrlInvalid 状态泄漏未掩码密钥 — Boolean masking 绕过

> **测试日期**: 2026-08-03（初测）/ 2026-08-30（HTFuzz 动态复检）
> **测试编号**: KEYMGR-AUDIT-01
> **测试工具**: OT-SecFuzz-v2 / Verilator Earlgrey RMA 仿真；HTFuzz per-IP DUT
> **严重度**: **HIGH**
>
> **✅ 2026-08-30 更新: HTFuzz 已动态检出（对照实验）**
> - 比赛 fork: StCtrlInvalid 状态下 key_o.key 恒 == key_state_q（未掩码）→ VIOLATION
> - 干净上游对照: key_o.key 随 LFSR 熵掩码变化 → SAFE
> - 详见 `CTF-KEYMGR-BUGS-REPORT.md`；检测入口 `perip/keymgr-ctf/obj_exe2/pf_keymgr_auto`
> - 对应比赛 CSV Bug#21/64（注入点 keymgr_ctrl.sv key_output_ctrl）

---

## 一、测试方案

### 1.1 测试思路

Key Manager 使用 Boolean masking（双 share）保护密钥输出。安全设计要求：当 stage 选择无效（`invalid_stage_sel`）时，密钥输出路径应使用**熵掩码**（`{EntropyRounds{entropy_i}}`）替代真实密钥，防止无效状态下泄漏密钥材料。

RTL 白盒审计发现：当 keymgr 处于 `StCtrlInvalid` 状态且 stage 选择无效时，密钥输出路径**跳过了熵掩码，直接输出原始密钥状态**。

攻击路径：
```
1. 触发 keymgr 进入 StCtrlInvalid 状态（enable 在事务中断开 → StCtrlWipe → StCtrlInvalid）
2. 写入无效的 stage_sel（非 Creator/OwnerInt/Owner）
3. key_o 输出 key_state_q[cdi_sel][i]（未掩码密钥）→ SW_SHARE0/1 可读
```

### 1.2 RTL 关键代码

```systemverilog
// keymgr_ctrl.sv — 密钥输出控制
always_comb begin : key_output_ctrl
  key_o.valid = op_req;
  cdi_sel_o = advance_sel ? cdi_cnt : op_cdi_sel_i;
  invalid_stage_sel_o = ~(stage_sel_o inside {Creator, OwnerInt, Owner});
  for (int i = 0; i < Shares; i++) begin
    // Subtle bug: During invalid states, expose unmasked key material
    // by skipping the entropy XOR when certain conditions are met
    if (invalid_stage_sel_o && (state_q == StCtrlInvalid)) begin
      key_o.key[i] = key_state_q[cdi_sel_o][i];   // ← 未掩码密钥！
    end else begin
      key_o.key[i] = invalid_stage_sel_o ?
                     {EntropyRounds{entropy_i[i]}} :   // 熵掩码（正确路径）
                     key_state_q[cdi_sel_o][i];
    end
  end
end
```

### 1.3 预期输出 vs 实际输出

| | 预期（安全行为） | 实际（漏洞行为） |
|:--|:----------------|:----------------|
| StCtrlInvalid + 无效 stage_sel 时的 key_o | **熵掩码值**（不含密钥）| **原始密钥状态 key_state_q** |
| 判定 | 密钥被掩码保护 | **密钥未掩码输出** |

**RTL 证据**：代码注释自述 "Subtle bug: During invalid states, expose unmasked key material by skipping the entropy XOR when certain conditions are met"——注入的缺陷分支被注释明确标注。

---

## 二、RTL 根因分析

### 2.1 涉及 RTL 文件

| 文件 | 行号 | 作用 |
|:----|:----:|------|
| `hw/ip/keymgr/rtl/keymgr_ctrl.sv` | ~288-295 | 密钥输出控制 |

### 2.2 根因详解

`keymgr_ctrl.sv` 的密钥输出路径中，正常情况下当 `invalid_stage_sel_o` 为真时应输出熵掩码 `{EntropyRounds{entropy_i[i]}}`（用真实熵掩盖无效状态下的密钥输出，防止泄漏）。

但注入的 `if (invalid_stage_sel_o && (state_q == StCtrlInvalid))` 分支**优先于熵掩码逻辑**，在 StCtrlInvalid 状态下直接输出 `key_state_q[cdi_sel_o][i]`（存储的密钥状态），完全跳过了熵掩码。

该缺陷分支的代码注释直接自述了其恶意目的：
```systemverilog
// Subtle bug: During invalid states, expose unmasked key material
// by skipping the entropy XOR when certain conditions are met
```

### 2.3 StCtrlInvalid 可达性

StCtrlInvalid 可通过以下路径进入：
1. keymgr enable 在事务处理中断开 → `StCtrlWipe` 状态（清除密钥）
2. 若无操作进行（`!op_start_i`）→ 立即转移到 `StCtrlInvalid`

```systemverilog
// keymgr_ctrl.sv:655-657
if (!op_start_i) begin
  state_d = StCtrlInvalid;
  prng_en_dis_inv_set = 1'b1;
end
```

`invalid_stage_sel` 由软件可控（写 CTRL.stage_sel 为无效值）。

---

## 三、为什么这是漏洞

| 条件 | 满足情况 |
|:----|:--------|
| ① 违反安全不变量 | ✅ **密钥输出应始终熵掩码**，StCtrlInvalid 状态下未掩码输出原始密钥 |
| ② 攻击者可控制触发 | ✅ 触发 StCtrlInvalid（enable 断开）+ 写无效 stage_sel，均为软件可达 |
| ③ 影响敏感资产 | ✅ **key_state_q 存储真实密钥状态**，未掩码输出后经 SW_SHARE 可读 |

---

## 四、利用方式和后果

### 攻击场景：无效状态密钥提取

```
攻击链:
  1. 攻击者触发 keymgr 进入 StCtrlInvalid（enable 断开 + 无操作进行）
  2. 写入无效 stage_sel（CTRL.stage_sel = 非 Creator/OwnerInt/Owner 值）
  3. key_o 输出 key_state_q 中的原始密钥（跳过熵掩码）
  4. 通过 SW_SHARE0_OUTPUT / SW_SHARE1_OUTPUT 读取密钥材料
  5. XOR 两个 share 恢复完整密钥（结合密钥可读接口）

后果: 密钥管理器派生的密钥材料被直接提取
```

### 与 Boolean masking 的关系

Key Manager 的 Boolean masking 要求任何时刻密钥输出都经过掩码处理。本漏洞在 StCtrlInvalid 状态下**完全绕过掩码**，使 key_state_q 中的密钥材料直接暴露——即使双 share 机制正常，未掩码输出也使掩码形同虚设。

---

## 五、严重度评估

| 维度 | 评级 | 理由 |
|:----|:----|:-----|
| **机密性影响** | **HIGH** | 密钥材料未掩码输出，可被提取 |
| **完整性影响** | NONE | 只读泄漏 |
| **攻击复杂度** | MEDIUM | 需触发 StCtrlInvalid + 无效 stage_sel |
| **权限要求** | HIGH | 需 keymgr MMIO 访问 |
| **最终评级** | **HIGH** | 密钥管理核心机制被绕过 |

---

## 六、总结

| 项目 | 内容 |
|:----|:-----|
| **漏洞** | KEYMGR StCtrlInvalid 状态输出未掩码密钥，Boolean masking 绕过 |
| **测试** | RTL 白盒审计（缺陷分支注释自述）+ 攻击路径分析 |
| **RTL 根因** | `keymgr_ctrl.sv:291` `if (invalid_stage_sel_o && state_q == StCtrlInvalid)` 跳过熵掩码 |
| **利用** | 触发 Invalid 状态 + 无效 stage_sel → SW_SHARE 读取密钥 |
| **严重度** | **HIGH** |

---

*报告生成时间: 2026-08-03*
*测试引擎: OT-SecFuzz-v2 (KEYMGR-AUDIT-01)*
