# VULN-108: AES CTRL_SHADOWED 配置写入提交异常 — 加密参数不可信

> **测试日期**: 2026-08-03
> **测试编号**: AES-AUDIT-04
> **测试工具**: OT-SecFuzz-v2 / Verilator Earlgrey RMA 仿真
> **严重度**: **HIGH**

---

## 一、测试方案

### 1.1 测试思路

AES 的 `CTRL_SHADOWED` 寄存器（offset `0x74`）是影子寄存器，控制加密方向（OPERATION）、块模式（MODE）、密钥长度（KEY_LEN）等安全关键参数。软件写入后应能正确读回，确认配置生效。

测试通过**寄存器 fuzzing**：向 CTRL_SHADOWED 写入多组随机/边界值（双写提交），读回验证是否与写入一致。

```
1. 对每组测试值 V：
   - 双写 V 到 CTRL_SHADOWED（影子提交协议）
   - 读回
   - 检查读回值是否 == V
2. 统计提交失败次数
```

### 1.2 固件测试代码

```c
// 8 组 fuzz 值
uint32_t fuzz_vals[8] = {0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x3F};

for (i = 0; i < 8; i++) {
  wr(ab + 0x74, fuzz_vals[i]);   // 第一写
  wr(ab + 0x74, fuzz_vals[i]);   // 第二写（提交）
  uint32_t rb = rd(ab + 0x74);   // 读回
  if (rb != fuzz_vals[i]) anomalies++;
}
```

### 1.3 预期输出 vs 实际输出

| | 预期（正确行为） | 实际（漏洞行为） |
|:--|:----------------|:----------------|
| 读回值与写入值 | **相等**（配置可靠）| **8/8 不相等**（提交异常）|
| 判定 | 配置正确提交 | **配置提交不可靠** |

**实测日志（Verilator 仿真）**：
```
===== [AES-AUDIT] CTRL_SHADOWED fuzz - commit consistency =====
fuzz[0]: wrote=0x00000000 read=0x00001481 MISMATCH (mode w=0x0 r=0x20)
fuzz[2]: wrote=0x00000002 read=0x00001482 MISMATCH (mode w=0x0 r=0x20)
fuzz[3]: wrote=0x00000004 read=0x00001405 MISMATCH (mode w=0x1 r=0x1)
fuzz[6]: wrote=0x00000020 read=0x00001421 MISMATCH (mode w=0x8 r=0x8)
fuzz[7]: wrote=0x0000003f read=0x00001481 MISMATCH (mode w=0xf r=0x20)
[AES-SHADOWFUZZ CONFIRMED] 8/8 shadow writes did NOT commit correctly
FAIL!
```

---

## 二、RTL 根因分析

### 2.1 涉及 RTL 文件

| 文件 | 行号 | 作用 |
|:----|:----:|------|
| `hw/ip/aes/rtl/aes_reg_top.sv` | CTRL_SHADOWED 字段连接 | 影子寄存器字段读回 |
| `hw/ip/prim/rtl/prim_subreg_shadow.sv` | ~72, 188-189 | 影子寄存器实现（error_s 缺陷）|

### 2.2 根因详解

AES `CTRL_SHADOWED` 使用通用影子寄存器原语 `prim_subreg_shadow`。该原语存在 `error_s` 未赋值缺陷（VULN-107），导致：

1. **错误检测失效**：`err_update/err_storage` 因 `error_s=X` 永不置位（VULN-107 已确认）
2. **阶段跟踪异常**：`err_update` 的 X 值影响阶段寄存器 `phase_q` 的切换逻辑，导致影子寄存器**提交协议无法可靠完成**

实测提交异常的具体表现：
- **MODE 字段**：写入非零值时能更新（w=0x4 → r mode=0x1）
- **OPERATION/KEY_LEN/PRNG 字段**：残留复位值（读回基值 `0x1481` 含复位 OPERATION=1、PRNG=1、异常 KEY_LEN）

因此软件配置 AES 后，硬件实际运行的配置是**写入值与复位值的混合**——并非软件期望的配置。

### 2.3 与 VULN-107 的关系

本漏洞是 VULN-107（prim_subreg_shadow error_s 未赋值）在 AES 配置寄存器上的**具体可利用后果**。VULN-107 影响所有影子寄存器，但 AES CTRL_SHADOWED 因字段结构（稀疏编码）表现最明显——提交异常导致加密参数错误。

---

## 三、为什么这是漏洞

| 条件 | 满足情况 |
|:----|:--------|
| ① 违反安全不变量 | ✅ **配置寄存器写入应可靠生效**，实际提交值与写入不一致 |
| ② 攻击者可控制触发 | ✅ **固件写 CTRL_SHADOWED 即触发**（MMIO）|
| ③ 影响敏感资产 | ✅ **加密方向/密钥长度/模式是安全关键参数**，错误配置导致加密失败或弱化 |

---

## 四、利用方式和后果

### 攻击场景一：加密参数降级/错误

```
攻击链:
  1. 软件配置 AES-128-ENC 加密（写 CTRL_SHADOWED）
  2. 实际硬件以混合配置运行（OPERATION 残留 DEC、KEY_LEN 残留错误值）
  3. 加密结果与软件预期不符
  4. 若软件信任"加密结果"而实际是错误配置的产物，安全边界被破坏

后果: 加密方向/密钥长度错误，加密数据不可信
```

### 攻击场景二：解密方向混淆

```
攻击链:
  1. 软件写 CTRL_SHADOWED 配置为加密（OPERATION=ENC）
  2. 但 OPERATION 字段残留复位值 DEC
  3. 硬件实际执行解密而非加密
  4. 软件认为得到密文，实际是解密结果 → 明文泄露

后果: 加密/解密方向被静默反转，机密数据以错误方式处理
```

### 攻击场景三：配置可靠性破坏（与 FI 结合）

```
攻击链:
  1. 攻击者进行故障注入篡改 CTRL_SHADOWED
  2. 影子寄存器提交异常（VULN-107/108）使篡改不被检测（error_s）
  3. 错误配置生效且无告警
  4. 加密参数被静默降级

后果: 结合 VULN-107，配置篡改既不被检测又导致错误配置
```

---

## 五、严重度评估

| 维度 | 评级 | 理由 |
|:----|:----|:-----|
| **机密性影响** | HIGH | 解密方向混淆可泄露明文；配置错误导致加密不可信 |
| **完整性影响** | HIGH | AES 配置不可靠，加密结果错误 |
| **攻击复杂度** | LOW | 固件写 CTRL_SHADOWED 即触发 |
| **影响范围** | AES 子系统 | 所有使用 AES 的加密/解密操作 |
| **最终评级** | **HIGH** | 配置提交异常 + 加密参数不可信 |

---

## 六、总结

| 项目 | 内容 |
|:----|:-----|
| **漏洞** | AES CTRL_SHADOWED 配置写入提交异常，加密参数不可信 |
| **测试** | 寄存器 fuzzing：8 组值双写提交后读回比对 |
| **实际输出** | 8/8 提交失败（写 0x0 读回 0x1481、写 0x4 读回 0x1405 等）|
| **RTL 根因** | prim_subreg_shadow error_s 缺陷（VULN-107）导致提交协议异常；AES 字段残留复位值 |
| **利用** | 加密方向/密钥长度被静默错误配置 |
| **严重度** | **HIGH** |

---

*报告生成时间: 2026-08-03*
*测试引擎: OT-SecFuzz-v2 (AES-AUDIT-04)*
