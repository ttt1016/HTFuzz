#!/bin/bash
# O-K 批量 gen: 全部有 DUT 的模块
cd /workspace/HTFuzz
MODULES="hmac aes kmac ascon rom_ctrl sram_ctrl aon_timer rv_timer pattgen clkmgr rstmgr alert_handler otp_ctrl flash_ctrl otbn"
for mod in $MODULES; do
  echo "=== $mod ==="
  python3 scripts/ok_invariant.py gen $mod 2>&1 | grep -E "不变量提取|VIOLATION" | head -2
done
