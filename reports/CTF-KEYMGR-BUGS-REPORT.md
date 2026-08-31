# HTFuzz CTF 检测报告: keymgr 模块

**日期**: 2026-08-30
**DUT**: `/workspace/pickerfuzz/perip/keymgr-ctf/`（比赛 fork keymgr RTL）
**对照**: `/workspace/pickerfuzz/perip/keymgr-clean/`（opentitan-fresh 干净上游）
**工具链**: Verilator 5.050（--timing --main 模式，全 SV 自包含检测）

---

## 检测结果总览

| Bug ID | 注入点 | Oracle | 结果 |
|--------|--------|--------|------|
| **Bug#21/64** | `keymgr_ctrl.sv` key_output_ctrl（StCtrlInvalid 密钥暴露） | O4 白盒观测（key_o.key vs key_state_q vs LFSR） | ✅ **检出（VIOLATION）** |
| **Bug#11** | `keymgr_ctrl.sv` ECC 编码脱钩（`{ecc_q} <= enc(...)` 丢 key_state_q 联合赋值） | RTL 静态 diff + O1 规格语义 | ✅ **RTL 确认**（动态触发需 ECC 故障注入，超出本轮范围） |

---

## Bug#21/64: StCtrlInvalid 状态密钥暴露（动态检出）

### 注入代码（fork `keymgr_ctrl.sv` 289-297 行）

```systemverilog
// Subtle bug: During invalid states, expose unmasked key material
if (invalid_stage_sel_o && (state_q == StCtrlInvalid)) begin
  key_o.key[i] = key_state_q[cdi_sel_o][i];   // 跳过 entropy XOR！
end else begin
  key_o.key[i] = invalid_stage_sel_o ?
                 {EntropyRounds{entropy_i[i]}} :   // clean: LFSR 掩码
                 key_state_q[cdi_sel_o][i];
end
```

干净版只有 else 分支（invalid 状态恒用 entropy 掩码）。

### 检测方法（O4 白盒观测）

1. 复位后 keymgr 状态机自然进入 `StCtrlInvalid`（fault 路径: Reset→Wipe→Invalid）
2. 白盒直接读 `u_dut.u_ctrl.key_o.key`（key_output_ctrl 组合输出）
3. 每 50 拍采样 5 次，同时记录 `key_state_q` 与 `lfsr[63:32]`

### 检测输出（比赛 fork）

```
state = StCtrlInvalid (0x2c7)
invalid_stage_sel = 1  stage_sel = 3 (Disable)

key_state_q[cdi=0][share=0] = 00000000 ... （全 0）
u_ctrl.key_o.key[share=0]   = 00000000 ... （恒全 0，5 次采样不变）
lfsr = 41cc1819 → 97130409 → 88306b1c ...（LFSR 在变）

VERDICT: VIOLATION — key_o.key == key_state_q（未掩码密钥直接输出）
```

### 对照实验（干净上游 RTL，同一 wrapper/激励）

```
state = StCtrlInvalid (invalid_stage_sel=1)
u_ctrl.key_o.key share0 = 00000001 00000000 00000000 00000001 ...（随 LFSR 变化）

VERDICT: SAFE — key_o.key follows LFSR entropy mask
```

**结论**: 同一测试平台下，fork 的 `key_o.key` 在 Invalid 状态恒等于内部密钥状态
（跳过熵掩码），干净版则被 LFSR 熵掩码覆盖且随时间变化。差异唯一来源是注入代码。
当 `key_state_q` 持有真实密钥时（正常 KDF 后掉入 Invalid），该 bug 将把未掩码密钥
暴露到 aes/kmac/otbn sideload 接口。

---

## Bug#11: ECC 编码与密钥状态脱钩（RTL 静态确认）

### 注入代码（fork `keymgr_ctrl.sv` 312-313 行）

```systemverilog
// fork（注入）:
{key_state_ecc_q[i][j][k]} <=
    prim_secded_pkg::prim_secded_inv_72_64_enc(key_state_ecc_words_d[i][j][k]);
// 72bit 编码输出截断为 8bit ECC，64bit 数据部分被丢弃

// clean:
{key_state_ecc_q[i][j][k], key_state_q[i][j][k]} <=
    prim_secded_pkg::prim_secded_inv_72_64_enc(key_state_ecc_words_d[i][j][k]);
// ECC 与数据由同一次编码联合更新（SEC_CM: CTRL.KEY.INTEGRITY）
```

**语义差异**: 干净版每次密钥状态更新时 ECC 与数据同步重编码；fork 版 ECC 寄存器
与 `key_state_q` 更新脱钩 → ECC 校验的是过期数据 → 完整性保护失效（攻击者翻转
key_state 位而不触发 ECC 错误，取决于更新路径时序）。

**动态触发条件**: 需要驱动 KDF 操作使 `key_state_ecc_words_d` 与 `key_state_q`
走不同更新路径，或直接故障注入翻转密钥位观察 ECC 是否报错。本轮以 RTL diff +
SEC_CM 语义比对确认注入事实。

**附注**: 该注入代码还触发 Verilator 5.050 V3Gate Internal Error（`-O0` 可绕过），
侧面说明该代码模式非常规。

---

## 工程记录

- keymgr 依赖闭包: 76 个 SV 文件（keymgr + prim + tlul + kmac_pkg/sha3_pkg +
  lc/otp/flash/rom/edn/entropy/csrng pkg + top_pkg）
- primgen 抽象模块（prim_flop/prim_buf/prim_flop_2sync）需手写 wrapper
- TL-UL host: 真实 ECC intg（`get_cmd_intg`/`get_data_intg`），instr_type=MuBi4False
- 编译模式: `--cc --build --main --timing`（SV 内部时钟 + 全 SV 检测任务）
- 检测入口: `obj_exe2/pf_keymgr_auto`（fork）/ `keymgr-clean/obj_exe2/pf_keymgr_clean`（对照）
