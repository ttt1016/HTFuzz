#!/usr/bin/env python3
"""适配比赛 fork 的信号名: 删除 harness 中不存在的信号绑定"""
import re
import subprocess

path = "/workspace/pickerfuzz/perip/hmac-ctf/harness/pf_hmac_harness.cpp"
hdr = "/workspace/pickerfuzz/perip/hmac-ctf/obj_so/Vhmac_perip_tb___024root.h"

r = subprocess.run(["grep", "-oE", r"hmac_perip_tb__DOT__u_dut__DOT__[a-zA-Z_0-9]+", hdr],
                   capture_output=True, text=True)
existing = set(x.split("DOT__")[-1] for x in r.stdout.split("\n") if x)
print("existing signals:", len(existing))

src = open(path).read()
lines = src.split("\n")
out = []
removed = 0
for l in lines:
    # 匹配绑定行: p = &rootp->hmac_perip_tb__DOT__u_dut__DOT__<sig>;
    m = re.search(r'rootp->hmac_perip_tb__DOT__u_dut__DOT__([a-z_0-9]+)\s*;', l)
    if m and m.group(1) not in existing:
        removed += 1
        continue
    out.append(l)
src = "\n".join(out)

# 删除 g_sigs 表中不存在的条目
sig_table = re.findall(r'\{"(u_dut\.[a-z_0-9]+)", nullptr, (\d+), (true|false)\}', src)
for name, words, wide in sig_table:
    short = name.replace("u_dut.", "")
    if short not in existing:
        src = re.sub(r'\s*\{"%s", nullptr, %s, %s\},' % (re.escape(name), words, wide), "", src)
        removed += 1

open(path, "w").write(src)
print("removed %d stale lines" % removed)
