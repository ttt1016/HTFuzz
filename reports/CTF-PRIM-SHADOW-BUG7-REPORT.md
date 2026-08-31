# HTFuzz CTF 检测报告: prim_subreg_shadow（Bug#7）

**日期**: 2026-08-30
**DUT**: 单元 TB（`perip/keymgr-ctf/rtl_wrapper/shadow_tb.sv` + fork 版 `prim_subreg_shadow.sv`）
**对照**: `perip/prim-clean/`（干净上游 prim_subreg_shadow）
**Oracle**: O1 规格语义（shadow 寄存器双写一致性检测）

---

## Bug#7: error_s 悬空 → shadow 错误检测完全失效

### 注入点（fork `prim_subreg_shadow.sv`）

```systemverilog
logic error_s;   // 声明但从未赋值（悬空）！

// Error detection - all bits must match.
assign err_update  = (~staged_q != wr_data) ? error_s : 1'b0;    // 恒 0
assign err_storage = (~shadow_q != committed_q) ? error_s : 1'b0; // 恒 0
```

干净版对照:
```systemverilog
assign err_update = (phase_q && wr_en) ? (~shadow_q != wd) : 1'b0;  // 正常检测
```

### 检测方法（单元 TB）

1. **T1** 正常两阶段写相同值（0x12/0x12）→ 期望 q=0x12、无错误
2. **T2** 两阶段写不同值（0x34/0x56）→ **期望 err_update=1**（双写不一致）
3. 判定用 `err_update_after_write`（we 时刻采样）

### 检测结果（对照实验）

| | fork（注入版） | clean（干净上游） |
|---|---|---|
| T1 正常写 | q=12, err=0 ✓ | q=12, err=0 ✓ |
| T2 不同值双写 | **err_update 未触发** | **err_update 正常触发** |
| 判定 | **VIOLATION** | SAFE |

```
fork:  [T2] 两阶段写不同值 0x34/0x56: err_update=0 (期望 1)
       → VIOLATION: 两阶段写不同值未触发 err_update
clean: → SAFE: err_update 正常触发
```

### 影响

- **SEC_CM: CONFIG.SHADOW 完全失效**：所有使用 shadow 寄存器的 IP（AES CTRL、
  KMAC CFG_SHADOWED、keymgr CTRL/CONTROL_SHADOWED 等）的双写一致性检测被禁用
- 攻击者对 shadow 寄存器两次写入不同值不会触发任何 alert → 控制寄存器可被
  单次写入篡改（绕过 phase 机制）
- err_storage 恒 0 → 存储完整性错误（位翻转）也无法检测
- 影响面: 全芯片所有 shadow 寄存器（跨 IP 的系统性削弱）

### 复现命令

```bash
cd /workspace/pickerfuzz/perip/keymgr-ctf
./obj_shadow/shadow_test          # fork → VIOLATION
cd /workspace/pickerfuzz/perip/prim-clean
./obj_shadow/shadow_test          # clean → SAFE
```
