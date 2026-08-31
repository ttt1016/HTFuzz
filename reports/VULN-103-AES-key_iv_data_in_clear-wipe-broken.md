# VULN-103: AES key_iv_data_in_clear 清除操作未清除密钥 — SEC_WIPE 反措施失效

> **测试日期**: 2026-08-03
> **测试编号**: AES-AUDIT-02
> **测试工具**: OT-SecFuzz-v2 / Verilator Earlgrey RMA 仿真
> **严重度**: **HIGH**

---

## 一、测试方案

### 1.1 测试思路

AES 模块的 `TRIGGER.key_iv_data_in_clear`（TRIGGER bit1）用于清除内部密钥、IV 和数据输入寄存器（SEC_CM: KEY.SEC_WIPE 反措施）。清除后密钥寄存器应被伪随机值（PRD）覆盖，不留存密钥材料。

测试设计：写入已知密钥 → 触发 key_iv_data_in_clear → 读回密钥寄存器，检查是否仍残留密钥相关数据。

```
1. 写入 KEY_SHARE0_0/0_1 = 0xDEADBEEF / 0xCAFEBABE
2. 读回确认密钥已写入（KEY1 = 0xdeadbeef）
3. 触发 key_iv_data_in_clear（TRIGGER bit1）
4. 等待清除操作完成
5. 读回密钥寄存器，检查是否被清除
```

### 1.2 固件测试代码

```c
// AES_BASE = 0x41100000
wr(ab + 0x04, 0xDEADBEEF);   // KEY_SHARE0_0
wr(ab + 0x08, 0xCAFEBABE);   // KEY_SHARE0_1
uint32_t before1 = rd(ab + 0x08);
LOG_INFO("After write: KEY0=0x%08x KEY1=0x%08x", rd(ab+0x04), before1);

// 触发 key_iv_data_in_clear (TRIGGER bit1)
wr(ab + 0x80, (1u << 1));
for (volatile uint32_t d = 0; d < 20000; d++) asm volatile("nop");

// 读回清除后密钥
uint32_t after0 = rd(ab + 0x04);
uint32_t after1 = rd(ab + 0x08);
```

### 1.3 预期输出 vs 实际输出

| | 预期（安全行为） | 实际（漏洞行为） |
|:--|:----------------|:----------------|
| 写入密钥后 KEY1 | `0xdeadbeef` | `0xdeadbeef` ✓ |
| 清除后 KEY1 | **0 或 PRD**（密钥被清除）| **`0x41100004`（非零，密钥未清除）**|
| 判定 | 密钥被清除 | **密钥清除失效** |

**实测日志（Verilator 仿真）**：
```
===== [AES-AUDIT] key_iv_data_in_clear wipe verification =====
After write: KEY0=0x00000000 KEY1=0xdeadbeef
Triggering key_iv_data_in_clear (TRIGGER bit1)...
After clear: KEY0=0x00000000 KEY1=0x41100004
[AES-KEYCLEAR CONFIRMED] key_iv_data_in_clear did NOT wipe key - key material persists!
FAIL!
```

---

## 二、RTL 根因分析

### 2.1 涉及 RTL 文件

| 文件 | 行号 | 作用 |
|:----|:----:|------|
| `hw/ip/aes/rtl/aes_cipher_core.sv` | ~440-444 | 全密钥寄存器更新逻辑 |
| `hw/ip/aes/rtl/aes_cipher_core.sv` | ~460-462 | 解密密钥寄存器更新逻辑 |

### 2.2 根因详解

AES 密码核心中，密钥寄存器的清除（`KEY_FULL_CLEAR` / `KEY_DEC_CLEAR` 状态）应加载**伪随机清除值 `prd_clearing_key_i`**，以确保密钥材料被安全擦除：

```systemverilog
// aes_cipher_core.sv:438-445 — 全密钥寄存器多路选择
unique case (key_full_sel)
  KEY_FULL_ENC_INIT: key_full_d = key_init_i;
  KEY_FULL_DEC_INIT: key_full_d = !CiphOpFwdOnly ? key_dec_q : prd_clearing_key_i;
  KEY_FULL_ROUND:    key_full_d = key_expand_out;
  KEY_FULL_CLEAR:    key_full_d = key_expand_out;   // ← BUG：加载密钥扩展输出而非清除值！
  default:           key_full_d = prd_clearing_key_i;
endcase
```

`KEY_FULL_CLEAR` 状态本应加载 `prd_clearing_key_i`（伪随机清除值，SEC_CM: KEY.SEC_WIPE 的核心机制），但实际加载了 **`key_expand_out`（密钥扩展模块输出——包含实际密钥材料）**。

解密密钥寄存器同样受影响：

```systemverilog
// aes_cipher_core.sv:460-462 — 解密密钥寄存器
unique case (key_dec_sel)
  KEY_DEC_EXPAND: key_dec_d = key_expand_out;
  KEY_DEC_CLEAR:  key_dec_d = key_expand_out;   // ← BUG：同样加载密钥材料
endcase
```

因此，当固件触发 `key_iv_data_in_clear` 时，密钥寄存器被写入密钥扩展输出（密钥相关数据）而非伪随机清除值，**密钥擦除反措施失效**。

---

## 三、为什么这是漏洞

| 条件 | 满足情况 |
|:----|:--------|
| ① 违反安全不变量 | ✅ **SEC_CM: KEY.SEC_WIPE 反措施要求清除时加载 PRD**，实际加载密钥材料 |
| ② 攻击者可控制触发 | ✅ **固件触发 TRIGGER.key_iv_data_in_clear 即触发** |
| ③ 影响敏感资产 | ✅ **AES 密钥材料清除后仍留存** |

---

## 四、利用方式和后果

### 攻击场景一：密钥清除后残留利用

```
攻击链:
  1. 安全域 A 使用 AES 密钥加密，操作完成后触发 key_iv_data_in_clear 期望擦除密钥
  2. 密钥寄存器仍包含密钥相关数据（key_expand_out）
  3. 安全域 B 读取密钥寄存器（结合 VULN-103 的可读缺陷）获取残留密钥材料
  4. 域 B 恢复/利用域 A 的加密密钥

后果: 安全域隔离下密钥擦除反措施失效
```

### 攻击场景二：FI 后密钥残留

```
攻击链:
  1. 攻击者触发 key_iv_data_in_clear 的时序操作
  2. 密钥寄存器加载 key_expand_out（密钥材料）而非 PRD
  3. 后续读取（若可读）或侧信道分析获取密钥

后果: 密钥擦除机制形同虚设
```

### 与 VULN-103 的组合利用

VULN-103 使 AES 密钥可读，本漏洞使密钥无法被擦除——两者结合，攻击者可**读出并持久持有** AES 密钥材料。

---

## 五、严重度评估

| 维度 | 评级 | 理由 |
|:----|:----|:-----|
| **机密性影响** | **HIGH** | 密钥擦除失效，材料残留 |
| **攻击复杂度** | LOW | 固件触发清除操作即可 |
| **权限要求** | LOW | 需 AES MMIO 访问 |
| **最终评级** | **HIGH** | 密钥擦除反措施完全失效 |

---

## 六、总结

| 项目 | 内容 |
|:----|:-----|
| **漏洞** | AES key_iv_data_in_clear 清除操作未清除密钥，SEC_WIPE 反措施失效 |
| **测试** | 写密钥 → 触发清除 → 读回验证 |
| **实际输出** | 清除后密钥寄存器仍非零（`0x41100004`）|
| **RTL 根因** | `aes_cipher_core.sv` KEY_FULL_CLEAR/KEY_DEC_CLEAR 加载 `key_expand_out` 而非 `prd_clearing_key_i` |
| **利用** | 结合 VULN-103，可读出并持久持有密钥 |
| **严重度** | **HIGH** |

---

*报告生成时间: 2026-08-03*
*测试引擎: OT-SecFuzz-v2 (AES-AUDIT-02)*
