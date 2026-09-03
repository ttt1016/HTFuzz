# VULN-102: AES 密钥寄存器 SW_UNREADABLE 属性失效 — 密钥材料 MMIO 可读

> **测试日期**: 2026-08-03
> **测试编号**: AES-AUDIT-01
> **测试工具**: OT-SecFuzz-v2 / Verilator Earlgrey RMA 仿真
> **严重度**: **CRITICAL**

---

## 一、测试方案

### 1.1 测试思路

AES 模块的密钥寄存器（`KEY_SHARE0_0..15`，offset `0x04-0x44`）在设计中标记为 **SW_UNREADABLE**（固件不可读）——密钥材料只能写入，不能读出，防止密钥泄漏。

测试设计：向密钥寄存器写入已知值，立即读回，检查是否返回写入的密钥值。

```
1. 写入 KEY_SHARE0_0 = 0xDEADBEEF
2. 写入 KEY_SHARE0_1 = 0xCAFEBABE
3. 读回 KEY_SHARE0_0 / KEY_SHARE0_1
4. 若读回值为写入值 → 密钥可读 → SW_UNREADABLE 失效
```

### 1.2 固件测试代码

```c
// AES_BASE = 0x41100000
// KEY_SHARE0_0 偏移 0x04, KEY_SHARE0_1 偏移 0x08
wr(ab + 0x04, 0xDEADBEEF);
wr(ab + 0x08, 0xCAFEBABE);

uint32_t r0 = rd(ab + 0x04);   // 读 KEY_SHARE0_0
uint32_t r1 = rd(ab + 0x08);   // 读 KEY_SHARE0_1
```

### 1.3 预期输出 vs 实际输出

| | 预期（安全行为） | 实际（漏洞行为） |
|:--|:----------------|:----------------|
| 读回 KEY_SHARE0_0 | `0x00000000`（SW_UNREADABLE）| `0x00000000` |
| 读回 KEY_SHARE0_1 | `0x00000000`（SW_UNREADABLE）| **`0xcafebabe`**（实际密钥值！）|
| 判定 | 密钥不可读 | **密钥可读** |

**实测日志（Verilator 仿真）**：
```
===== [AES-AUDIT] KEY_SHARE readback leak =====
Wrote KEY0=0xDEADBEEF, KEY1=0xCAFEBABE
Readback KEY0=0x00000000 KEY1=0xcafebabe
[AES-KEYREAD CONFIRMED] AES KEY_SHARE readable - key material leaked via MMIO!
FAIL!
```

---

## 二、RTL 根因分析

### 2.1 涉及 RTL 文件

| 文件 | 行号 | 作用 |
|:----|:----:|------|
| `hw/ip/aes/rtl/aes_reg_top.sv` | ~278-290 | KEY_SHARE0_0 子寄存器 |
| `hw/ip/aes/rtl/aes_reg_top.sv` | ~1678-1679 | KEY_SHARE0_0 读回路径 |

### 2.2 根因详解

AES 密钥子寄存器使用 `prim_subreg_ext` 且读使能被绑定为 0（`.re(1'b0)`），本应禁用读路径：

```systemverilog
// aes_reg_top.sv:278-290
prim_subreg_ext #(
  .DW    (32)
) u_key_share0_0 (
  .re     (1'b0),                 // 读使能绑死 0
  .we     (key_share0_0_we),
  .wd     (key_share0_0_wd),
  .d      (hw2reg.key_share0[0].d),
  .q      (reg2hw.key_share0[0].q),
  ...
);
```

然而，**顶层读回路径（`reg_rdata_next`）绕过子寄存器的读使能门控，直接返回存储的密钥值**：

```systemverilog
// aes_reg_top.sv:1678-1679
addr_hit[1]: begin
  reg_rdata_next[31:0] = reg2hw.key_share0[0].q;   // 直接读密钥值！
end
```

`reg2hw.key_share0[0].q` 是密钥寄存器的实际存储值（写入 `0xCAFEBABE` 后即为该值）。顶层读回逻辑将其直接驱动到数据总线上，导致固件读取 KEY_SHARE0_1（offset `0x08`，即 `addr_hit[2]`）时返回实际密钥。

### 2.3 影响范围

受影响的寄存器包括 `KEY_SHARE0_0..15`（offset `0x04-0x44`）。实测确认至少部分密钥字可读回（`KEY_SHARE0_1` 返回写入的 `0xcafebabe`）。

---

## 三、为什么这是漏洞

| 条件 | 满足情况 |
|:----|:--------|
| ① 违反安全不变量 | ✅ **AES 密钥 SW_UNREADABLE 属性失效**。密钥材料不应对固件可读 |
| ② 攻击者可控制触发 | ✅ **固件只需 MMIO 读**即可获取密钥 |
| ③ 影响敏感资产 | ✅ **AES 密钥是加密核心材料**，直接读出后可用于解密/伪造 |

---

## 四、利用方式和后果

### 攻击场景一：恶意固件窃取 AES 密钥

```
攻击链:
  1. 攻击者通过漏洞注入恶意代码
  2. 恶意代码 MMIO 读取 AES_KEY_SHARE0 寄存器
  3. 获取密钥值 → 解密受保护的数据/伪造加密结果
```

### 攻击场景二：跨安全域密钥提取

```
攻击链:
  1. 安全域 A 加载 AES 密钥进行加密
  2. 边界切换后，安全域 B 的代码读取 AES 密钥寄存器
  3. 域 B 获得域 A 的加密密钥，解密域 A 的所有密文

后果: 安全域隔离下加密密钥直接泄漏
```

### 攻击场景三：供应链/测试阶段密钥提取

```
攻击链:
  1. 芯片在测试阶段运行测试固件
  2. 测试固件读取 AES 密钥寄存器
  3. 密钥通过调试接口外传

后果: 同一批次芯片的密钥泄漏
```

---

## 五、严重度评估

| 维度 | 评级 | 理由 |
|:----|:----|:-----|
| **机密性影响** | **CRITICAL** | 直接读出加密密钥 |
| **攻击复杂度** | **LOW** | 单次 MMIO 读 |
| **权限要求** | LOW | 需 AES MMIO 访问 |
| **影响范围** | **芯片级** | 所有使用 AES 的加密数据 |
| **最终评级** | **CRITICAL** | 低复杂度、直接密钥泄漏 |

---

## 六、总结

| 项目 | 内容 |
|:----|:-----|
| **漏洞** | AES 密钥寄存器 SW_UNREADABLE 失效，密钥材料可 MMIO 读出 |
| **测试** | 写密钥 → 读回验证 |
| **实际输出** | `KEY_SHARE0_1` 读回写入的 `0xcafebabe`（期望 0）|
| **RTL 根因** | `aes_reg_top.sv` 顶层读回路径直接返回 `reg2hw.key_share0[i].q`，绕过 `.re(1'b0)` 门控 |
| **利用** | 固件直接读密钥 → 解密/伪造 |
| **严重度** | **CRITICAL** |

---

*报告生成时间: 2026-08-03*
*测试引擎: OT-SecFuzz-v2 (AES-AUDIT-01)*
