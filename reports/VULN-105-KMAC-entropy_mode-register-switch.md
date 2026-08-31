# VULN-105: KMAC entropy_mode 锁定绕过 — entropy_ready 后可切回 idle_mode

> **测试日期**: 2026-08-03
> **测试编号**: KMAC-AUDIT-01
> **测试工具**: OT-SecFuzz-v2 / Verilator Earlgrey RMA 仿真
> **严重度**: **MEDIUM**

---

## 一、测试方案

### 1.1 测试思路

KMAC 模块的 `CFG_SHADOWED.entropy_ready` 置位后，硬件规范明确要求模块**不能再被切回 `idle_mode`**：

> "Once the CFG_SHADOWED.entropy_ready bit is set after reset, the module cannot be made to return to idle_mode once any of the other modes have been used."
> （摘自 kmac.hjson 寄存器规范）

`idle_mode` 使用固定种子（不注入新鲜熵）的 PRNG，仅应在初始阶段使用；进入显式熵模式后不应回退，否则 SCA 掩码的随机性失去保障。

测试设计：正确配置 KMAC 的 CFG_SHADOWED（设置 entropy_mode=edn + entropy_ready=1），随后尝试将 entropy_mode 切回 idle，验证硬件是否拒绝。

```
1. 读取 CFG_SHADOWED (offset 0x14)
2. 设置 entropy_mode=edn(1) + entropy_ready=1（影子寄存器双写提交）
3. 读回确认配置生效
4. 尝试写 entropy_mode=0（idle）—— 规范要求应被拒绝
5. 读回检查 entropy_mode 是否被接受为 0
```

### 1.2 固件测试代码

```c
// KMAC_BASE = 0x41120000, CFG_SHADOWED offset 0x14
// 影子寄存器需双写提交
wr(kc + 0x14, new_cfg);   // 设置 entropy_mode=edn + entropy_ready
wr(kc + 0x14, new_cfg);   // 第二次写提交
uint32_t cfg2 = rd(kc + 0x14);

// 尝试切回 idle_mode(0)
wr(kc + 0x14, idle_cfg);
wr(kc + 0x14, idle_cfg);
uint32_t cfg3 = rd(kc + 0x14);
uint32_t mode_after = (cfg3 >> 16) & 0x3;
```

### 1.3 预期输出 vs 实际输出

| | 预期（安全行为） | 实际（漏洞行为） |
|:--|:----------------|:----------------|
| 设置 edn+ready 后读回 | mode=1（edn）| mode=1, ready=1 ✓ |
| 尝试切回 idle 后读回 | **mode=1（被拒绝）**| **mode=0（被接受）**|
| 判定 | entropy_mode 锁定 | **锁定绕过** |

**实测日志（Verilator 仿真）**：
```
===== [KMAC-DEEP-02-FIXED] entropy_mode Lock Invariant =====
CFG_SHADOWED=0x00000000
entropy_mode=0 entropy_ready=0
After set edn+ready: CFG=0x01010000 mode=1 ready=1
After mode=0 write:  CFG=0x01000000 mode=0
[KMAC-DEEP-02 CONFIRMED] entropy_mode switched back to idle after entropy_ready=1 (spec violation)
FAIL!
```

---

## 二、RTL 根因分析

### 2.1 涉及 RTL 文件

| 文件 | 行号 | 作用 |
|:----|:----:|------|
| `hw/ip/kmac/rtl/kmac_reg_top.sv` | CFG_SHADOWED 写路径 | entropy_mode 字段写保护 |
| `hw/ip/kmac/rtl/kmac.sv` | ~545-547 | entropy_mode/ready 信号 |
| `hw/ip/kmac/rtl/kmac_entropy.sv` | ~345-348 | 模式锁存 |

### 2.2 根因详解

`CFG_SHADOWED.entropy_mode` 字段（bits[17:16]）在寄存器写路径中**没有硬件锁定机制**。`entropy_ready` 置位后，硬件未阻止后续对该字段的写操作：

```systemverilog
// kmac.sv:547 — entropy_mode 直接来自寄存器值，无锁定
assign entropy_mode = entropy_mode_e'(reg2hw.cfg_shadowed.entropy_mode.q);
```

实测确认：设置 `entropy_ready=1` 后，写入 `entropy_mode=0` 被寄存器接受（读回 mode=0），违反规范"cannot be made to return to idle_mode"的锁定要求。

**注意**：`kmac_entropy.sv` 的 `mode_q`（实际驱动 PRNG 的模式）在 `entropy_ready` 脉冲时锁存一次，后续写寄存器只改变 `mode_i` 不影响已锁存的 `mode_q`。因此：
- **寄存器级**：entropy_mode 可被写回 idle（本漏洞）
- **功能级**：若先写 (mode=1, ready=1) 再写 mode=0，mode_q 已锁存为 edn，PRNG 仍用 edn

但存在**利用窗口**：若攻击者在 `entropy_ready` 脉冲前（或与 ready 同周期）把 mode 设为 0，`mode_q` 将锁存为 idle——PRNG 使用固定种子，而固件认为熵已配置。

---

## 三、为什么这是漏洞

| 条件 | 满足情况 |
|:----|:--------|
| ① 违反安全不变量 | ✅ **规范明确要求 entropy_ready 后不能回 idle**，寄存器层未实现锁定 |
| ② 攻击者可控制触发 | ✅ 固件写 CFG_SHADOWED 即可 |
| ③ 影响敏感资产 | ✅ KMAC 的 SCA 掩码依赖 PRNG 不可预测性，idle 模式用固定种子 |

---

## 四、利用方式和后果

### 攻击场景：SCA 掩码降级

```
攻击链:
  1. 攻击者（或恶意固件）在 KMAC 配置阶段将 entropy_mode 设为 0（idle）
  2. 固件设置 entropy_ready=1，认为熵已配置
  3. mode_q 锁存为 idle_mode → PRNG 使用固定种子
  4. SCA 掩码失去随机性 → 侧信道攻击更容易成功

后果: KMAC 掩码防护被削弱，密钥材料可能通过功率侧信道泄漏
```

---

## 五、严重度评估

| 维度 | 评级 | 理由 |
|:----|:----|:-----|
| **机密性影响** | MEDIUM | SCA 掩码降级可辅助密钥恢复 |
| **攻击复杂度** | LOW | 写 CFG_SHADOWED 即可（需正确时序）|
| **最终评级** | **MEDIUM** | 规范承诺的锁定机制未在寄存器层实现 |

---

## 六、总结

| 项目 | 内容 |
|:----|:-----|
| **漏洞** | KMAC entropy_mode 在 entropy_ready 后可被写回 idle，寄存器级锁定缺失 |
| **测试** | 设置 edn+ready → 写 mode=0 → 读回 |
| **实际输出** | mode 从 1 被写回 0（规范应拒绝）|
| **RTL 根因** | CFG_SHADOWED.entropy_mode 写路径无锁定机制 |
| **利用** | 配置阶段将 mode 设为 idle → SCA 掩码降级 |
| **严重度** | **MEDIUM** |

---

*报告生成时间: 2026-08-03*
*测试引擎: OT-SecFuzz-v2 (KMAC-AUDIT-01)*
