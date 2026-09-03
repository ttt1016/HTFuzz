# VULN-107: prim_subreg_shadow error_s 未赋值 — 影子寄存器故障注入检测失效（全局）

> **测试日期**: 2026-08-03
> **测试编号**: AES-AUDIT-03
> **测试工具**: OT-SecFuzz-v2 / Verilator Earlgrey RMA 仿真
> **严重度**: **HIGH**

---

## 一、测试方案

### 1.1 测试思路

OpenTitan 所有安全模块的影子寄存器（如 AES `CTRL_SHADOWED`、KMAC `CFG_SHADOWED`、OTP 配置、KEYMGR binding 等）都基于通用原语 `prim_subreg_shadow`。该原语的核心安全功能是**故障注入（FI）检测**：当主寄存器和影子寄存器不一致（或被写入不一致的双写）时，应触发 `err_update`/`err_storage` 错误并上报告警。

测试设计：向 AES `CTRL_SHADOWED` 写入两个**不同的值**（正常应为影子更新错误），检查错误是否被上报到 STATUS 寄存器。

```
1. 写 CTRL_SHADOWED = 0x4（第一阶段写）
2. 写 CTRL_SHADOWED = 0x8（第二阶段写，与第一写不同）
   → 规范要求触发 err_update（影子更新错误）
3. 读取 STATUS 寄存器
4. 若 STATUS.alert_recov_ctrl_update_err (bit5) 置位 → 检测正常
   若未置位 → 故障检测失效
```

### 1.2 固件测试代码

```c
// AES_BASE = 0x41100000
wr(ab + 0x74, (1u << 2));   // 写值 A（MODE=ECB）
wr(ab + 0x74, (2u << 2));   // 写值 B（MODE=CBC）— 与第一写不同
// 等待
uint32_t status = rd(ab + 0x84);   // STATUS
// 检查 bit5 (alert_recov_ctrl_update_err)
```

### 1.3 预期输出 vs 实际输出

| | 预期（安全行为） | 实际（漏洞行为） |
|:--|:----------------|:----------------|
| STATUS.alert_recov_ctrl_update_err (bit5) | **1**（检测到影子更新错误）| **0**（未检测到）|
| 判定 | 故障检测正常 | **故障检测失效** |

**实测日志（Verilator 仿真）**：
```
===== [AES-AUDIT] CTRL_SHADOWED fault detection =====
STATUS=0x00000011 (bit5=ctrl_update_err=0, bit4=input_ready=1)
INTR_STATE=0x00000000
[AES-SHADOWDET CONFIRMED] shadow update error NOT reported - fault detection broken!
FAIL!
```

---

## 二、RTL 根因分析

### 2.1 涉及 RTL 文件

| 文件 | 行号 | 作用 |
|:----|:----:|------|
| `hw/ip/prim/rtl/prim_subreg_shadow.sv` | ~72 | `error_s` 信号声明 |
| `hw/ip/prim/rtl/prim_subreg_shadow.sv` | ~188-189 | `err_update`/`err_storage` 逻辑 |

### 2.2 根因详解

通用影子寄存器原语 `prim_subreg_shadow` 中，信号 `error_s` **被声明但从未赋值**：

```systemverilog
// prim_subreg_shadow.sv:72
logic error_s;                     // ← 声明

// prim_subreg_shadow.sv:188-189
assign err_update  = (~staged_q != wr_data) ? error_s : 1'b0;
assign err_storage = (~shadow_q != committed_q) ? error_s : 1'b0;
```

`error_s` 在整个文件中只出现 3 次（声明 + 2 处使用），**没有任何赋值语句**。在 SystemVerilog 中，未赋值信号值为 **X**（未知）。

因此：
- 当影子不一致（`~staged_q != wr_data` 为真）时，`err_update = error_s = X`
- 在 Verilator 仿真中 X 解析为 0 → **`err_update` 永不置位**
- `err_storage` 同理永不置位
- **影子寄存器的故障注入检测完全失效**

### 2.3 影响范围（全局）

`prim_subreg_shadow` 是所有安全模块影子寄存器的公共实现。此缺陷影响：
- **AES**：`CTRL_SHADOWED`、`CTRL_AUX_SHADOWED`
- **KMAC**：`CFG_SHADOWED`、`ENTROPY_REFRESH_THRESHOLD_SHADOWED`
- **KEYMGR**：`MAX_*_KEY_VER`、`SW_BINDING`（shadowed）
- **OTP_CTRL**、**ALERT_HANDLER**（CLASS_CTRL_SHADOWED）等

这些影子寄存器是**FI 反措施的核心**——用于检测主/影子副本被故障注入篡改。检测失效意味着**针对安全配置寄存器的故障注入攻击无法被检测**。

---

## 三、为什么这是漏洞

| 条件 | 满足情况 |
|:----|:--------|
| ① 违反安全不变量 | ✅ **影子寄存器规范要求检测主/影子不一致**，实际检测逻辑因 `error_s` 未赋值而失效 |
| ② 攻击者可控制触发 | ✅ **固件写入不一致的双写即触发该路径**（MMIO 可验证）|
| ③ 影响敏感资产 | ✅ 影子寄存器保护安全配置（AES/KMAC 模式、密钥长度等），FI 检测失效使配置可被篡改 |

---

## 四、利用方式和后果

### 攻击场景：故障注入检测绕过

```
攻击链:
  1. 攻击者进行故障注入（电压/时钟毛刺）篡改 AES CTRL_SHADOWED 配置
  2. 主/影子寄存器不一致 → 本应触发 err_update 告警
  3. 由于 error_s=X，err_update 不置位 → 告警不触发
  4. 攻击者成功篡改安全配置（如降级密钥长度）而不被检测
  5. 结合物理探测，攻击者可在无告警的情况下破坏加密参数

后果: 影子寄存器的 FI 反措施形同虚设，安全配置可被静默篡改
```

### 附加影响：影子提交协议异常

`err_update` 的 X 值还会影响阶段跟踪寄存器（`phase_q`），可能导致影子寄存器双写提交异常（实测写 `0x4` 后读回 `0x1405`，非预期值）——软件无法可靠确认配置写入。

---

## 五、严重度评估

| 维度 | 评级 | 理由 |
|:----|:----|:-----|
| **完整性影响** | **HIGH** | 影子寄存器 FI 检测失效，安全配置可被静默篡改 |
| **攻击复杂度** | MEDIUM | 需 FI 篡改 + 固件写入路径 |
| **影响范围** | **全局** | 所有使用影子寄存器的模块 |
| **最终评级** | **HIGH** | 通用原语缺陷，影响所有安全模块的 FI 反措施 |

---

## 六、总结

| 项目 | 内容 |
|:----|:-----|
| **漏洞** | prim_subreg_shadow `error_s` 未赋值，影子寄存器故障注入检测失效 |
| **测试** | 写两个不同值到 AES CTRL_SHADOWED → 检查 STATUS 错误位 |
| **实际输出** | STATUS.alert_recov_ctrl_update_err=0（错误未报告）|
| **RTL 根因** | `prim_subreg_shadow.sv:72` 声明 `error_s` 但从未赋值（X）|
| **利用** | FI 篡改影子配置不被检测；影子提交异常 |
| **严重度** | **HIGH**（全局）|

---

*报告生成时间: 2026-08-03*
*测试引擎: OT-SecFuzz-v2 (AES-AUDIT-03)*
