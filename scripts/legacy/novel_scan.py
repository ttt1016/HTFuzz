#!/usr/bin/env python3
"""表外漏洞指纹扫描: fork vs fresh 全 RTL diff 的语义模式分类"""
import subprocess, os, re
from collections import defaultdict

OT = "/workspace/opentitan"
FR = "/workspace/opentitan-fresh"

# 已知注入位置（CSV 表内）
KNOWN = {
    "hw/ip/hmac/rtl/hmac_reg_top.sv", "hw/ip/hmac/rtl/hmac_core.sv",
    "hw/ip/aes/rtl/aes_core.sv", "hw/ip/aes/rtl/aes_key_expand.sv",
    "hw/ip/aes/rtl/aes_cipher_core.sv", "hw/ip/aes/rtl/aes_ctr_fsm.sv",
    "hw/ip/aes/rtl/aes.sv", "hw/ip/aes/rtl/aes_reg_top.sv",
    "hw/ip/keymgr/rtl/keymgr_ctrl.sv",
    "hw/ip/kmac/rtl/kmac.sv",
    "hw/ip/lc_ctrl/rtl/lc_ctrl_fsm.sv",
    "hw/ip/prim/rtl/prim_subreg_shadow.sv",
    "hw/ip/uart/rtl/uart_core.sv",
    "hw/ip/rom_ctrl/rtl/rom_ctrl.sv",
    "hw/ip/ascon/rtl/ascon_core.sv",
}

results = []
for root, dirs, files in os.walk(os.path.join(OT, "hw/ip")):
    if "dv" in dirs: dirs.remove("dv")
    if "fpv" in dirs: dirs.remove("fpv")
    if "pre_syn" in dirs: dirs.remove("pre_syn")
    if "pre_sca" in dirs: dirs.remove("pre_sca")
    if "model" in dirs: dirs.remove("model")
    for fn in files:
        if not fn.endswith(".sv"): continue
        fork_path = os.path.join(root, fn)
        rel = os.path.relpath(fork_path, OT)
        cf = os.path.join(FR, rel)
        if not os.path.exists(cf):
            continue
        try:
            r = subprocess.run(["diff", cf, fork_path], capture_output=True, text=True, timeout=10)
        except Exception:
            continue
        lines = r.stdout.splitlines()
        removed = [l[2:] for l in lines if l.startswith("< ")]
        added = [l[2:] for l in lines if l.startswith("> ")]
        if not removed and not added:
            continue
        # 语义指纹
        # 1. fork 删掉了 clean 的条件判断（&&/|| 行被删）
        cond_removed = sum(1 for l in removed if re.search(r"&&|\|\||inside|==|!=", l))
        # 2. fork 把 clean 的表达式改成常量
        const_assign = sum(1 for l in added if re.search(r"<=\s*1.b0\s*;|=\s*1.b1\s*;|<=\s*1.b1\s*;", l))
        # 3. 位截断（[31:0] 或 [7:0] 出现在 fork 新增行）
        trunc = sum(1 for l in added if re.search(r"\[\d+:\d+\]\s*==|\[31:0\]", l))
        # 4. fork 删除了 clean 的赋值行（逻辑被掏空）
        assign_removed = sum(1 for l in removed if re.search(r"<=", l))
        score = cond_removed * 2 + const_assign * 3 + trunc * 2 + assign_removed
        if score >= 8:
            known = rel in KNOWN
            results.append((score, rel, cond_removed, const_assign, trunc, assign_removed, known))

results.sort(reverse=True)
print(f"{'score':>5} {'known':>5} {'cond-':>5} {'const':>5} {'trunc':>5} {'asgn-':>5}  file")
for score, rel, c, ca, t, a, known in results[:25]:
    mark = "KNOWN" if known else "**NEW?**"
    print(f"{score:>5} {mark:>7} {c:>5} {ca:>5} {t:>5} {a:>5}  {rel}")
