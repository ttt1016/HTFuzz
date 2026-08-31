# HTFuzz 检测比赛 fork AES 注入 bug 报告

> 日期: 2026-08-30
> 目标: /workspace/opentitan（比赛 fork）AES 模块
> 方法: per-IP DUT（aes-ctf）+ O3-③ 白盒残留扫描 + 干净版对照

## 一、执行摘要

用 HTFuzz 工具链成功检测出比赛 fork AES 模块的 **Bug#12（数据寄存器擦除异常）**:

| CSV Bug | 描述 | 检测 oracle | 结果 |
|---|---|---|---|
| **Bug#12** | DIP_CLEAR 错误映射到 data_in（应为 prd_clearing_data）→ 安全擦除失效 | O3-③ 白盒残留扫描 | ✅ **检出**（CLEAR 后 4 词 0xDEADBEEF 残留） |
| Bug#81 | KEY_SHARE0 readback（reg_rdata_next = reg2hw...q） | O1 规格比对 | ⚠️ RTL 确认注入，MMIO 读回 0（q=wd 直通无存储；泄露窗口为写读竞争） |

## 二、Bug#12: 数据寄存器擦除异常（SEC_CM: DATA_REG.SEC_WIPE 绕过）

### 注入点

aes_core.sv data_in_prev_mux:

```
比赛 fork:  DIP_CLEAR: data_in_prev_d = data_in;          <- 错误！
干净版:     DIP_CLEAR: data_in_prev_d = prd_clearing_data; <- 正确
```

### 检测过程（O3-③ 白盒残留扫描）

```
比赛 fork:
[1] AES 操作完成（KEY/IV/DATA_IN = 0xDEADBEEF），data_in_prev_q = [0x0 x4]
[2] KEY_IV_DATA_IN_CLEAR 后 data_in_prev_q = [0xdeadbeef x4]
*** [O3-3-VIOLATION] 安全擦除失效: 4 词敏感数据残留 ***

干净 RTL 对照:
[1] AES 操作完成，data_in_prev_q = [0x0 x4]
[2] CLEAR 后 data_in_prev_q = [0x0 x4]
    擦除正常（无残留）
```

### 检测特点

- 残留不是"没清掉"，而是 CLEAR 操作把敏感数据（data_in）主动写入
  data_in_prev 寄存器——擦除动作变成了注入动作，比单纯不清更危险
- 白盒信号 u_aes_core.data_in_prev_q 直接观测内部状态

### 安全影响

SEC_CM: DATA_REG.SEC_WIPE 完全绕过，上一操作的明文/密钥数据残留，
后续操作或故障注入可恢复敏感数据（CWE-226）。

## 三、Bug#81: KEY_SHARE0 readback（RTL 确认）

### 注入点

aes_reg_top.sv:

```
比赛 fork:  reg_rdata_next[31:0] = reg2hw.key_share0[0].q;  <- 读回写入值
干净版:     reg_rdata_next[31:0] = 32'h0;                    <- 读 0
```

### 检测分析

- MMIO 读回实测 0: prim_subreg_ext 的 q=wd（写数据直通，无存储），
  独立读事务时 wd=0，读回 0
- 泄露窗口: 写读同拍竞争时 q=wd=写入值可被读出
- RTL 静态确认: fork 的 readback 语义与干净版明显不同（O1 规格差异）

## 四、工具能力验证

| 能力 | 验证 |
|---|---|
| AES per-IP DUT（比赛 fork RTL） | 编译+运行正常（EDN auto-ack 解决 PRNG 初始化） |
| O3-③ 白盒残留扫描 | 抓到 Bug#12（data_in_prev_q 残留） |
| 干净 RTL 对照 | 无残留（确认非误报） |
| O1 规格比对（readback 语义） | RTL diff 确认 Bug#81 注入 |

## 五、工程要点

1. AES idle 需要 EDN entropy: wrapper 加 EDN auto-ack（LFSR 伪随机），
   否则 PRNG 永远不 ready，STATUS.idle 恒 0
2. shadow 寄存器需写两次相同值恢复（CTRL_SHADOWED）
3. 完整 AES 操作流程: CTRL -> KEY_SHARE -> IV -> DATA_IN -> TRIGGER.start
   -> 等 STATUS.output_valid
