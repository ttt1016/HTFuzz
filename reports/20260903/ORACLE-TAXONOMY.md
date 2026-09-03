# Oracle 属性分类学 —— 不依赖已知 bug 清单的检测基础（2026-09-03）

## 0. 对既有 7 大类总结的核验

之前的 7 分类（数据完整性/访问控制/随机性/状态机/总线完整性/信息泄露/时序安全）
**方向正确**，与我们 O-K 已实现的 12 规则同源。但对照三个权威来源，它**漏了 3 个
高频机制家族**（以比赛目标 RTL 实测的 278 个 SEC_CM 标注为证）：

| 漏掉的家族 | SEC_CM 实证频次 | 代表 bug |
|-----------|----------------|---------|
| **冗余一致性 REDUN**（多轨副本一致+不一致必须报错） | CTR.REDUN 33 + CTRL.REDUN 7 + FIFO.CTR.REDUN 5 + FSM.REDUN ≈ **50+** | 多轨状态不同步不报错 |
| **可用性/活性 availability**（检查必须周期运行、FSM 不得锁死） | BKGN_CHK 18 + 健康测试类 | P1 #21 adc_ctrl 永久锁死 |
| **MUBI 编码合法性**（多位编码信号值必须有效且跨域一致） | CONFIG.MUBI 17 + INTERSIG.MUBI 7 + LC_CTRL.INTERSIG.MUBI 7 | mubi 值损坏不被检测 |

## 1. 权威来源

1. **OpenTitan SEC_CM**（比赛方注入的原始依据，目标 RTL 实测 278 个类别）——第一手。
2. **Farzana, Rahman, Tehranipoor, Farahmandi, ITC 2019《SoC Security Verification using Property Checking》（DOI: 10.1109/ITC44170.2019.9000170）**——
   属性五分类：authentication / integrity / confidentiality / availability / isolation。
   **注意它含 availability**，7 大类缺失。
3. **Common Criteria (ISO 15408) FPT 类**——fail-secure、防旁路、TSF 保护。
4. **FIPS 140-3**——self-test 必须运行（↔BKGN_CHK）、密钥 zeroization（↔SEC_WIPE）、
   tamper 检测（↔GLITCH_DETECT）。
5. **MITRE CWE View-1194（硬件设计弱点）+ EMEA 对手画像**——攻击视角交叉验证。

## 2. 十大属性族（7 大类 + 3 补充）↔ Oracle 覆盖矩阵

| # | 属性族 | SEC_CM 家族（频次） | Oracle | 状态 |
|---|--------|--------------------|--------|------|
| 1 | 数据完整性-擦除 | DATA_REG.SEC_WIPE(4) | O-A 残留 + O-K wipe_clears + **O-K2 中途复位** | ✓ / O-K2 新 |
| 2 | 访问控制 | CONFIG.REGWEN(≈10) + LC_GATED(8) | O-K access_control/cfg_block_gating + O-J T3 | ✓ |
| 3 | 随机性 | KEY.MASKING(5) + DATA_REG_SW.SCA(26) | O-B 确定性 + **O-P 掩码活性** | ✓ / O-P 新 |
| 4 | 状态机编码+恢复 | FSM.SPARSE(9)+CTRL.SPARSE(8)+CONFIG.SPARSE(10) | O-K fsm_sparse + O-D FSM | ✓ |
| 5 | 总线完整性 | BUS.INTEGRITY(43) | O-K bus_intg + O-J T2 | ✓ |
| 6 | 信息泄露 | KEY.SW_UNREADABLE | O-K read_only_leak | ✓ |
| 7 | 时序安全 | （alert 延迟类，无独立 SEC_CM） | O-G 脉冲 + O-J 逐拍采样 | ✓ |
| 8 | **冗余一致性（新）** | CTR.REDUN(33)+CTRL.REDUN(7)+FSM.REDUN | **O-N 多轨一致**（差异必须报错） | **本节新增** |
| 9 | **可用性/活性（新）** | BKGN_CHK(18)+MAIN_SM | O-F 计数冻结 + **O-D 锁死**（已有）；背景检查活性 | ✓/部分 |
| 10 | **MUBI 合法性（新）** | MUBI 类(31+) | **O-M MUBI 编码合法+跨域一致** | **本节新增** |

升级链（FSM.LOCAL_ESC/GLOBAL_ESC 16 处）并入 O-N：轨间差异 → 必须触发 alert/err。

## 3. 本节实现

1. **O-N 多轨一致性**：自动发现共享同一尾名的多轨信号（如 aes 控制器 gen_fsm 0/1/2 的
   state_raw 三轨、ctr_fsm 三轨）；运行中采样，任意拍轨间不一致 → 检查 alert/err 是否置位；
   不置位 = "冗余比较失效"（CTRL.REDUN 类注入）。
2. **O-M MUBI 合法性**：名字含 mubi 的白盒信号，值必须 ∈ {True, False} 合法编码集
   （mubi4: 0x6/0x9；mubi8: 0x66/0x99；mubi12: 0x666/0x999）；出现非法编码 → 检查是否报错。
3. （O-K2 中途复位随 P1-2 补 DUT 时一并验证——需要 reset 期间操作能力，harness 已支持。）

## 4. 使用原则

写新 oracle 时**先查本表**：确认它属于哪个属性族、该族 SEC_CM 在目标 RTL 的频次，
不为单个 bug 写 oracle。比赛方换手法时，只要 bug 违反十大属性族之一即可检出。
