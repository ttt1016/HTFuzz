# HTFuzz CTF 检测报告: uart（Bug#1）

**日期**: 2026-08-30
**DUT**: 单元 TB（perip/uart-ctf + fork uart_core.sv）
**对照**: perip/uart-clean（干净上游 uart_core.sv）
**Oracle**: O4 信号模式（stuck-at 检测）

---

## Bug#1: lsio_trigger_o stuck-at-1（LSIO DMA 握手触发失效）

### 注入点（fork uart_core.sv 356-364）

```systemverilog
// fork（注入）:
always_ff @(posedge clk_i or negedge rst_ni) begin
  if (!rst_ni) lsio_trigger_o <= 1'b0;
  else         lsio_trigger_o <= 1'b1;   // 恒 1！
end

// clean:
  else lsio_trigger_o <= event_tx_watermark | event_rx_watermark;
```

### 检测方法（两阶段）

- **T1** 空闲 100 拍: 两者都为 1（clean 的 tx_wm=1 属正常语义: FIFO 低于阈值可发送）
- **T2** 填满 TX FIFO（写 40 字节 WDATA）→ tx_depth >= thresh → tx_wm=0，rx 空 → rx_wm=0
  → clean 的 trigger 应变 0；fork 恒 1

### 检测结果（对照实验）

| | fork（注入版） | clean（干净上游） |
|---|---|---|
| T1 空闲 | trigger=1（与 clean 相同，无法区分） | trigger=1（tx_wm=1 正常） |
| T2 TX FIFO 满 | **trigger 仍恒 1（0/50 拍为 0）** | **trigger 变 0（50/50 拍为 0）** |
| 判定 | **VIOLATION** | SAFE |

### 影响

- LSIO DMA 握手触发信号完全失效: DMA 在无数据时被持续触发
- 可导致 DMA 错误传输、系统级数据流破坏、总线拥塞
- 注入手法属 O4 stuck-at 类（与 KMAC Bug#26 静态掩码同类）

### 复现命令

```bash
cd /workspace/pickerfuzz/perip/uart-ctf && ./obj_exe/uart_test    # VIOLATION
cd /workspace/pickerfuzz/perip/uart-clean && ./obj_exe/uart_test  # SAFE
```
