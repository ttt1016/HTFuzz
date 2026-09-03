# HTFuzz CTF 检测报告: AES 模块（第二轮批量检测）

**日期**: 2026-08-30
**DUT**: `/workspace/pickerfuzz/perip/aes-ctf/`（比赛 fork AES RTL）
**对照**: `/workspace/pickerfuzz/perip/aes/`（干净上游）
**新增白盒**: `key_full_q` / `key_dec_q`（cipher_core）、`data_out_q`、`sp_data_out_we`

---

## 本轮检测结果总览

| Bug ID | 注入点 | Oracle | 结果 |
|--------|--------|--------|------|
| **Bug#6/9** | `aes_key_expand.sv` rnd==0 分支被改 | O2 NIST SP800-38A | ✅ **动态检出** |
| **Bug#82** | `aes_cipher_core.sv` KEY_FULL/DEC_CLEAR 加载 key_expand_out | O3-③ 白盒残留 | ✅ **动态检出** |
| **Bug#32** | `aes_core.sv:873` data_out reset 条件化 | O3-③ 精确复位时序 | ✅ **动态检出** |
| **Bug#31** | `aes.sv` SecAllowForcingMasks=1（clean=0） | O1 配置面 | ✅ **动态检出** |
| **Bug#34** | `aes_ctr_fsm.sv` alert 延迟 100 拍 | O4 时序 | 📌 RTL 确认 |
| Bug#12/81 | （第一轮已检出） | O3-③ / O1 | ✅ |

**AES 模块战绩: 8 个 bug 中 7 个动态检出 + 1 个 RTL 确认**

---

## Bug#6/9: key_expand 注入（O2 NIST 比对）

**注入点**: `aes_key_expand.sv` — `rnd == 0` 分支逻辑被改写（clean: `regular[s] = {key_i[s][3:0], key_i[s][7:4]}` + irregular XOR 链；fork: 分支条件反转/结构破坏）

**检测流程**:
1. `prng_reseed` 触发（SecMasking=1 必需，否则 FSM 卡 INIT）
2. `CTRL_SHADOWED = FWD | ECB | AES_128 | manual_operation`（0x8085）
3. 写 NIST key `2b7e1516 28aed2a6 abf71588 09cf4f3c` + PT `6bc1bee2 2e409f96 e93d7e11 7393172a`
4. start → 等 `STATUS.output_valid`（bit3）

**结果**:
```
fork 密文        = c48d5784 f6bb1688 a1f6ac18 eedab413
NIST SP800-38A   = 3ad77bb4 0d7a3660 a89ecaf3 2466ef97
Python 参考      = 3ad77bb40d7a3660a89ecaf32466ef97（cryptography 库确认）
→ O2 VIOLATION: 密文不匹配（key schedule 注入生效）
```

---

## Bug#82: KEY_FULL/DEC_CLEAR 擦除变注入（O3-③）

**注入点**: `aes_cipher_core.sv`
```
fork:  KEY_FULL_CLEAR: key_full_d = key_expand_out;   ← 密钥材料！
       KEY_DEC_CLEAR:  key_dec_d  = key_expand_out;   ← 密钥材料！
clean: KEY_FULL_CLEAR: key_full_d = prd_clearing_key_i;
       KEY_DEC_CLEAR:  key_dec_d  = prd_clearing_key_i;
```

**决定性证据**（同一密钥材料填充两个独立寄存器）:
```
CLEAR 后 key_full_q = fe3a3417 3db27218 aca51718 d60dfc8f b75f99e1 c388460f 91176500 7aa8eb97
CLEAR 后 key_dec_q  = fe3a3417 3db27218 aca51718 d60dfc8f b75f99e1 c388460f 91176500 7aa8eb97
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                     完全相同！clean 版两者是独立 LFSR 随机值，不可能相同
→ VIOLATION: SEC_CM KEY.SEC_WIPE 失效（擦除操作反而写入密钥材料）
```

---

## Bug#32: data_out reset 条件化（O3-③ 精确复位时序）

**注入点**: `aes_core.sv:873`
```
fork:  if (!rst_ni && data_out_we != SP2V_HIGH) data_out_q <= '0;  ← we 高时复位失效
clean: if (!rst_ni) data_out_q <= '0;
```

**检测方法**: 新增 `pf_reset_at_we()` API —— 逐半拍轮询 `sp_data_out_we`（SP2V_HIGH=3'b011），在 we 高的组合态瞬间拉低 `rst_ni`。

**结果**:
```
复位前 data_out_q = 3b17821e b55579b8 49cae3f3 ccb22ffe
we=HIGH 时复位: True
复位后 data_out_q = 3b17821e b55579b8 49cae3f3 ccb22ffe   ← 完全残留！
→ VIOLATION: 复位期间输出更新瞬间可保留旧密文（CWE-1259）
```

---

## Bug#31: SecAllowForcingMasks=1（O1 配置面）

**注入点**: `aes.sv` 参数 `SecAllowForcingMasks = 1`（clean = 0）

**检测**: 写 `CTRL_AUX_SHADOWED(0x78).force_masks = 1`（shadow 两阶段）→ 读回
```
CTRL_AUX_SHADOWED readback = 0x2 (force_masks bit1 = 1)
→ force_masks 可写（clean 版该位应恒 0）
→ SCA 评估模式开启，掩码强制旁路配置面暴露
```

---

## Bug#34: CTR alert 延迟（RTL 确认）

**注入点**: `aes_ctr_fsm.sv` — 终态错误时 `alert_counter_q < 100` 期间 `alert_o = 0`（clean 无此延迟计数器）

**影响**: 致命错误告警延迟 100 拍 → 攻击窗口扩大。动态触发需 CTR 携带错误（incr_err），留待错误注入扩展。

---

## 工程记录

- **寄存器偏移（老版 aes_reg_pkg）**: CTRL_SHADOWED=0x74, CTRL_AUX=0x78, TRIGGER=0x80, STATUS=0x84, KEY_SHARE0=0x4, KEY_SHARE1=0x24, DATA_IN=0x54, DATA_OUT=0x64
- **STATUS 位**: idle[0], stall[1], output_lost[2], **output_valid[3]**, input_ready[4]
- **CTRL_SHADOWED 位**: operation[1:0], mode[7:2]（sparse: ECB=000001）, key_len[10:8]（128=001）, manual_operation[15]
- **SecMasking=1 必须先 `prng_reseed`**（TRIGGER bit3），否则 FSM 卡 INIT、STATUS 恒 0
- **白盒 CData 信号必须用 uint8 读**（uint32 指针会读越界拼接出 0x404 之类的错位值）
- SP2V 编码: HIGH=3'b011, LOW=3'b100

## 复现命令

```bash
cd /workspace/pickerfuzz/perip/aes-ctf
LD_LIBRARY_PATH=$PWD/obj_so python3 test_aes_nist.py   # Bug#6/9（O2 NIST）
LD_LIBRARY_PATH=$PWD/obj_so python3 test_bug82.py      # Bug#82（O3-③）
LD_LIBRARY_PATH=$PWD/obj_so python3 test_bug32.py      # Bug#32（精确复位）
LD_LIBRARY_PATH=$PWD/obj_so python3 test_aes_bugs2.py  # Bug#82/32 快速版
```
