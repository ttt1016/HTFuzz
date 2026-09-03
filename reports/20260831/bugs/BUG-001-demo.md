# BUG-1: [O3-3-key-residue] u_dut.secret_key: WIPE_SECRET 后 secret_key[31] 残留 0xDEADBEEF

## 1. 摘要

- **Oracle 层**: O3-3-key-residue
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Re-use)
- **签名**: demo1234
- **发现迭代**: 12345 (seed=31000)

## 2. 触发序列（最小化后）

```
  W off=0x024 data=0xdeadbeef mask=0xf
  W off=0x020 data=0x00000001 mask=0xf
```

## 3. 观测 vs 期望

| 项 | 值 |
|---|---|
| 观测 | wipe 后 secret_key[31]=0xDEADBEEF (期望 0x00000000) |
| 期望 | 按 hjson 规格/元变关系应无此行为 |
| Oracle 依据 | O3-3-key-residue oracle 检测规则 |

## 4. 复现步骤

1. 加载 per-IP DUT 共享库 `liblibpf_hmac.so`
2. `pf_init(seed=31000)`
3. 按上述序列执行 pf_write/pf_read
4. 触发条件: WIPE_SECRET 后 secret_key[31] 残留 0xDEADBEEF

## 5. 根因假设（LLM 辅助，人工确认）

- 相关 RTL: hmac.sv（待定位具体行）
- 假设: 待 LLM 根因分析（最小化序列 + 相关 RTL 片段输入）

## 6. 安全影响分析（CWE 映射）

**CWE-226 — Sensitive Information in Resource Not Removed Before Re-use**

密钥残留 → 下一个使用者可恢复前次密钥 → 跨会话密钥泄露（FIVE-9 类）

**利用链**: 攻击者（恶意固件/软件）→ 恶意固件写触发序列 → 观测违规行为 → 跨会话密钥泄露（FIVE-9 类）

## 7. PoC 复现

- per-IP DUT: 本报告序列直接复现
- 全芯片仿真: 将序列转成固件 mmio 调用，跑 chip_verilator_sim（报告可信度验证）
