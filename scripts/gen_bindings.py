#!/usr/bin/env python3
"""
通用白盒绑定生成器 —— 从 Verilator root 头自动推导 harness 绑定

用途: fresh(干净) RTL 的 flatten 名与 CTF 版可能不同, 手写 bind_signals 失配。
本脚本读取 obj_so/V<top>___024root.h, 对 harness g_sigs 表里的每个信号名:
  1) 试 全路径映射: <top>__DOT__ + name.replace(".", "__DOT__")
  2) 兜底: 末段成员唯一匹配
  3) 找不到 → 该信号不绑定(ptr=nullptr), 差分时自动排除
并注入 pf_sig_bound() API（未绑定信号在差分采样时跳过）。

用法: gen_bindings.py <dut_dir>   （就地改写 harness/*.cpp 的 bind_signals）
"""

import glob
import os
import re
import sys


def sig_names(harness_cpp):
    s = open(harness_cpp).read()
    m = re.search(r"static SigEntry g_sigs\[\] = \{(.*?)\};", s, re.DOTALL)
    if not m:
        return [], s
    names = re.findall(r'\{"([^"]+)"', m.group(1))
    return names, s


def main():
    dut_dir = sys.argv[1]
    os.chdir(dut_dir)
    headers = glob.glob("obj_so/V*_perip_tb___024root.h") or glob.glob("obj_so/V*___024root.h")
    if not headers:
        print("[gen_bindings] 无 root 头, 跳过")
        return
    hdr = open(headers[0]).read()
    top_m = re.search(r"(\w+)_perip_tb__DOT__", hdr)
    top = top_m.group(1) if top_m else ""
    members = set(re.findall(r"\b(\w+__DOT__\w+)\s*(?:;|\[)", hdr))
    members |= set(re.findall(r"\b(\w+__DOT__\w+)\s*(?:;|\[)", hdr))

    cpps = glob.glob("harness/*.cpp")
    if not cpps:
        print("[gen_bindings] 无 harness cpp, 跳过")
        return
    hpath = cpps[0]
    names, src = sig_names(harness_cpp := hpath)
    prefix = f"{top}_perip_tb__DOT__u_dut__DOT__"

    found, unbound = {}, []
    for nm in names:
        cand = prefix + nm.replace(".", "__DOT__")
        if cand in members:
            found[nm] = cand
            continue
        # 兜底1: 末段成员匹配（取最短路径=最内层）
        last = nm.split(".")[-1]
        cands = sorted(mm for mm in members if mm.endswith("__DOT__" + last))
        if cands:
            found[nm] = cands[0]
            continue
        # 兜底2: 词切分数组成员（key_share0_in_q__BRA__N__hex__KET__ 形态）→ 绑首词
        base_cand = prefix + nm.replace(".", "__DOT__")
        arr_cands = sorted(mm for mm in members if mm.startswith(base_cand + "__BRA__"))
        if arr_cands:
            found[nm] = arr_cands[0]
            continue
        unbound.append(nm)

    # 重写 bind_signals()
    body = [
        "static void bind_signals() {",
        "    for (int i = 0; i < g_nsig; i++) {",
        "        const char* n = g_sigs[i].name;",
        "        void* p = nullptr;",
        "        (void)p;",
    ]
    for k, nm in enumerate(sorted(found)):
        kw = "if" if k == 0 else "else if"
        body.append(f'        {kw} (strcmp(n, "{nm}") == 0) p = &rootp->{found[nm]};')
    body.append("        g_sigs[i].ptr = p;")
    body.append("    }")
    body.append("}")
    new = re.sub(r"static void bind_signals\(\) \{.*?\n\}", "\n".join(body), src, flags=re.DOTALL)

    # 注入 pf_sig_bound（差分采样跳过未绑定信号）
    if "pf_sig_bound" not in new:
        new = new.replace(
            "int pf_sig_count(void) { return g_nsig; }",
            "int pf_sig_bound(int i) { return (i >= 0 && i < g_nsig && g_sigs[i].ptr != nullptr) ? 1 : 0; }\n"
            "int pf_sig_count(void) { return g_nsig; }",
        )
    open(hpath, "w").write(new)

    print(f"[gen_bindings] {len(found)}/{len(names)} 绑定, 未绑定: {unbound[:5]}")


if __name__ == "__main__":
    main()
