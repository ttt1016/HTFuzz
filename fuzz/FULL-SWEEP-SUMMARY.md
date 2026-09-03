# 全量检出扫描汇总（2026-09-03）

扫描范围: 18 个可运行 per-IP DUT（csrng/lc/uart 无 obj_so、prim 无 -ctf 跳过）× 4 类 oracle

## 1. O-A~G 盲测引擎（scripts/discover_engine.py, 18 DUT）
| 模块 | 唯一候选 |
|------|---------|
| aes | 2 (O-C data_out_q 等价类) |
| ascon | 2 (O-A key_share 残留) |
| hmac | 2 (O-A secret_key 残留) |
| kmac | 1 (O-B) |
| rom_ctrl | 1 (O-G) |
小计: 8 条

## 2. O-H ibex PMP（obj_pmp/obj_pmp_clean 单元 TB）
- Bug#27 PMP perm 极性反转: perm_mismatch=1, pmp_err_out=0（应违例但放行）
- Bug#45 PMP 违例吞没: clean 对照 violation=1
小计: 2

## 3. O-I ibex 特权（obj_priv/obj_csr_priv 单元 TB）
- Bug#5 U-mode MRET 放行: illegal_expected=1, illegal_fork=0
- Bug#13 CSR 特权写保护失效: U-mode 写 mstatus we_fork=1
小计: 2

## 4. O-K 不变量（12 模块, 107 条不变量）
- aes: data_out_q wipe_clears 残留 0x26122612... → Bug#32 (data_out reset 条件化)
- ascon: key_share0_in_q 残留 0xdeadbeef + 常量 → Bug#43 (TRIGGER.wipe 无效)
- hmac: secret_key wipe_clears 残留 0xdeadbeef → Bug#20/60 (WIPE_SECRET 极性反转)
- 其余 9 模块 (kmac/rom_ctrl/pattgen/rv_timer/sram_ctrl/aon_timer/clkmgr/rstmgr/alert_handler) 0 违反
小计: 6 条 VIOLATION

## 5. 单元 TB（lc/uart/prim）
- lc_fsm_test: Bug#28 token 128bit 只比 32bit → 任意状态转换绕过
- uart_test: Bug#1 LSIO DMA 握手触发失效
- prim shadow_test: T2/T3 实测 fork 特征（error_s 悬空 → err_update 恒 0）→ Bug#7
小计: 3

## 总计
**21 条检出记录 / 9 个模块**（aes, ascon, hmac, kmac, rom_ctrl, ibex, lc_ctrl, uart, prim）
对应 CSV 基线中的 bug: #20/60, #32, #43, #27, #45, #5, #13, #28, #1, #7 + 引擎候选若干

未在本轮覆盖（基线 26 中的其余路径）:
- RTL 静态: aes #34, keymgr #11（静态审计，非动态）
- escalation 序列: ascon #38
- LLM agent 确认流程: hmac/ascon（需 LLM 服务长跑）
- keymgr O4: 需 regmap（traces 缺 keymgr_regmap.json）
