# HTFuzz CTF 检测报告: lc_ctrl（Bug#28）

**日期**: 2026-08-30
**DUT**: 单元 TB（`perip/lc-ctf/rtl_wrapper/lc_fsm_tb.sv` + 比赛 fork `lc_ctrl_fsm.sv`）
**对照**: `perip/lc-clean/`（干净上游 lc_ctrl_fsm）
**Oracle**: O1 规格语义（token 全宽比较）+ FSM 状态转移观测

---

## Bug#28: Token 比较截断 128bit → 32bit

### 注入点（fork `lc_ctrl_fsm.sv` 456/497 两处）

```systemverilog
// fork（注入）:
if (hashed_token_i[31:0] == hashed_token_mux[31:0] && ...)   // 只比低 32bit！

// clean:
if (hashed_token_i == hashed_token_mux && ...)               // 全 128bit 比较
```

`lc_token_t` 为 128bit（KMAC hash 后的 token）。截断比较使有效碰撞空间从 2^128
缩小到 2^32。

### 检测方法（单元 TB + 对照实验）

1. 初始化 lc_ctrl_fsm 至 `IdleSt`（lc_state=LcStDev）
2. 设置 RMA token（OTP hash 后值）: `128'h11111111_22222222_33333333_DEADBEEF`
3. 设置 `hashed_token_i`（模拟 KMAC hash 输出）: `128'h99999999_88888888_77777777_DEADBEEF`
   —— **低 32bit 相同（0xDEADBEEF），高 96bit 完全不同**
4. 发起 `trans_cmd`（目标 RMA），推进状态机: ClkMuxSt → CntIncrSt → CntProgSt(ack)
   → TransCheckSt → TokenHashSt（模拟 token_hash_ack）
5. 观察 FSM 落点

### 检测结果（对照实验）

| | fork（注入版） | clean（干净上游） |
|---|---|---|
| token 低 32bit | 匹配（0xDEADBEEF） | 匹配（0xDEADBEEF） |
| token 高 96bit | **完全不同** | **完全不同** |
| FSM 落点 | **FlashRmaSt（转移被接受！）** | PostTransSt（token 被拒绝） |
| 判定 | **VIOLATION** | SAFE |

```
【fork】[T1] TokenHash 后 FSM=FlashRmaSt token_invalid_error=0
        hashed_token_i   = 999999998888888877777777deadbeef
        hashed_token_mux = 111111112222222233333333deadbeef
        低 32bit 相同: YES  高 96bit 不同: YES
        → VIOLATION: Bug#28 确认！

【clean】[T1] TokenHash 后 FSM=PostTransSt
        → SAFE: token 被拒绝（全宽比较正常）
```

### 影响

- **SEC_CM: TOKEN.DIGEST 失效**: 128bit token 只比较 32bit，碰撞概率 1/2^96
  （相对全宽比较），暴力破解从计算不可行变为 2^32 次尝试
- **任意 LC 状态转换绕过**: 攻击者只需构造低 32bit 碰撞的 token 即可通过
  RMA/TestUnlock/TestExit 等任意转换的 token 校验
- RMA 转换被绕过 → 攻击者可将生产设备转入 RMA 态，读取密钥材料、
  调试端口解锁（debug enable）
- 该比较在 TokenHashSt/TokenCheck0St/TokenCheck1St 三处生效（fork 修改了
  456/497 两处，第三处 TokenCheck1St 的比较同样被截断）

### 复现命令

```bash
cd /workspace/pickerfuzz/perip/lc-ctf
./obj_exe/lc_fsm_test          # fork → VIOLATION
cd /workspace/pickerfuzz/perip/lc-clean
./obj_exe/lc_fsm_test          # clean → SAFE
```

---

## 工程记录

- lc_ctrl_fsm 依赖闭包: lc_ctrl_pkg/state_pkg/reg_pkg/state_decode/state_transition
  + prim（lc_sync/lc_sender/sparse_fsm_flop/flop_2sync/sec_anchor）+ tlul/kmac pkg
- clean 版需额外 `lc_ctrl_token_pkg`（位于 `hw/top_earlgrey/rtl/autogen/testing/`）
- clean 版端口名差异: `nvm_rma_error_o`/`lc_nvm_rma_req_o`/`lc_nvm_rma_ack_i`
- clean 版 `rma_token_valid` 经 `prim_lc_sync` 同步（ResetValueIsOn=0），TB 需多等拍
- fsm_state_e 为 16bit sparse 编码（ResetSt=16'b1111011010111100 等）
- 状态机推进需模拟 `otp_prog_ack`（CntProgSt）和 `token_hash_ack`（TokenHashSt）
