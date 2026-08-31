# HTFuzz 检测比赛 fork KMAC 注入 bug 报告

> 日期: 2026-08-30
> 目标: /workspace/opentitan（比赛 fork）KMAC 模块
> 方法: per-IP DUT（kmac-ctf）+ O4 白盒掩码静态性分析

## 一、执行摘要

用 HTFuzz 工具链成功检测出比赛 fork KMAC 模块的 **Bug#26（静态消息掩码）**:

| CSV Bug | 描述 | 检测 oracle | 结果 |
|---|---|---|---|
| **Bug#26** | 消息掩码用静态全 1 常量替代动态 LFSR 随机掩码 | O4 白盒掩码静态性分析 | ✅ **检出**（5 次采样掩码恒定 0xffffffff） |

## 二、Bug#26: 静态消息掩码（一阶掩码防护失效）

### 注入点

kmac.sv（g_msg_mask generate block）:

```
比赛 fork:
  assign static_mask = {MsgWidth{1'b1}};   // 静态全 1 常量
  msg_data_masked[i] = msg_data[i] ^
                       ({MsgWidth{cfg_msg_mask}} & static_mask);

干净版:
  动态 LFSR 掩码（entropy 驱动，每次不同）
```

### 检测过程（O4 白盒掩码静态性分析）

配置: CFG_SHADOWED = mode=SHA3 | msg_mask=1 | entropy_ready=1，
CMD.start 后写 MSG_FIFO，白盒观测 msg_data_masked:

```
采样1: masked[share0]=0xffffffff masked[share1]=0xffffffff
采样2: masked[share0]=0xffffffff masked[share1]=0xffffffff
采样3: masked[share0]=0xffffffff masked[share1]=0xffffffff
采样4: masked[share0]=0xffffffff masked[share1]=0xffffffff
采样5: masked[share0]=0xffffffff masked[share1]=0xffffffff

*** [O4-VIOLATION] 掩码静态恒定全 1（Bug#26 确认）***
```

### 检测逻辑

- 动态掩码（正确实现）: masked 值应随 PRNG/entropy 每次变化，
  且 share0/share1 独立
- 静态掩码（Bug#26）: masked = msg ^ 全1 恒定可预测，
  5 次采样（间隔 100 拍）值完全不变 → 掩码静态性直接可观测

### 安全影响

一阶掩码防护完全失效:
- masked 值 = msg ^ 0xFFFFFFFF，攻击者直接取反即得明文消息
- DPA（差分功耗分析）攻击面暴露: 掩码无随机性，功耗轨迹与数据直接相关
- 对比 FIVE-12 类（MuBi 硬编码）：同为"随机性被常量替代"注入手法

## 三、工具能力验证

| 能力 | 验证 |
|---|---|
| KMAC per-IP DUT（比赛 fork RTL） | ✅ 编译+运行（NumAppIntf=3 适配） |
| O4 白盒掩码静态性分析 | ✅ 5 次采样确认掩码恒定 |
| 多时间点采样判定动态/静态 | ✅ 间隔 100 拍 × 5 次 |

## 四、工程要点

1. 比赛 fork kmac.sv 是老版本: NumAppIntf=3（无 Otbn）、sw_msg_mask（新版为 strb）
2. KMAC 启动流程: CFG_REGWEN → CFG_SHADOWED（mode|msg_mask|entropy_ready，
   shadow 写两次）→ KEY_SHARE → CMD.start → MSG_FIFO
3. EnMasking=1 是默认参数（masked keccak），掩码逻辑在 g_msg_mask block
