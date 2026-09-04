#!/usr/bin/env python3
"""
Phase A 工具: 白盒信号表自动扩充生成器

从 Verilator root 头的全部扁平成员名反解 SV 层次名, 按安全关键词分级:
  P0 必收: key/secret/seed/digest/hash/mask/entropy/token/priv/wipe/scrambl/rand
  P1 状态机: fsm/state/ctr/count_q/addr_q/wdata_q/rdata_q
  P2 错误面: alert/err/intg/escalat/fatal
输出可直接粘贴进 harness 的 SigEntry 行（绑定用 gen_bindings.py 自动完成）。

用法: gen_whitebox.py <dut_dir> [--emit <out_cpp_lines>]
"""
import glob, os, re, sys


def collect(root_header, prefix):
    hdr = open(root_header).read()
    members = re.findall(
        r"\b(" + re.escape(prefix) + r"\w+)\s*(?:\[[^\]]*\])?\s*;", hdr)
    out = {}
    for m in members:
        sv = m[len(prefix):]
        sv = sv.replace("__DOT__", ".")
        if re.search(r"\.(tb|drv_q|div_cnt|tl_a|tl_h2d|tl_d2h)\b", sv):
            continue
        if re.search(r"__Vdly|__Vcellin|__Vcellout|__Vmatch|__Vtrig", sv):
            continue
        low = sv.lower()
        if re.search(r"\.(we|wr_en|strb|wr_data|wd|phase_q|committed_reg|re$|we_q)$", low):
            continue
        low = sv.lower()
        tier = None
        if re.search(r"key|secret|seed|digest|hash|mask|entropy|token|priv|wipe|scrambl|cred|rand", low):
            tier = "P0"
        elif re.search(r"fsm|state|ctr_|count.*q|addr_q|wdata_q|rdata_q|_cnt_q", low):
            tier = "P1"
        elif re.search(r"alert|err|intg|escalat|fatal", low):
            tier = "P2"
        if not tier:
            continue
        mm = re.search(re.escape(m) + r"\s*\[(\d+)\]", hdr)
        words = int(mm.group(1)) if mm else 1
        out.setdefault(sv, (tier, words))
    return out


def main():
    dut_dir = sys.argv[1]
    emit = "--emit" in sys.argv
    os.chdir(dut_dir)
    hdrs = sorted(set(glob.glob("obj_so/V*___024root.h")))
    if not hdrs:
        print("无 root 头")
        sys.exit(1)
    top = re.search(r"V(\w+?)___024root", hdrs[0]).group(1)
    prefix = f"{top}__DOT__u_dut__DOT__"
    sigs = collect(hdrs[0], prefix)
    tiers = {"P0": [], "P1": [], "P2": []}
    for sv, (tier, words) in sorted(sigs.items()):
        tiers[tier].append((sv, words))
    lines = []
    for t in ("P0", "P1", "P2"):
        print(f"== {t} ({len(tiers[t])}) ==", file=sys.stderr)
        for sv, w in tiers[t]:
            # 位切片 → 基名（如 key_share0_in_q[127:96] → key_share0_in_q 4 words）
            base = re.sub(r"__BRA__\d+__[0-9a-f]+__KET__", "", sv)
            if base != sv:
                sv = base
            if re.search(r"\.(we|strb|wr_en)$", sv.lower()):
                continue
            if any(sv == l.strip().lstrip('{').split(',')[0].strip('"') for l in lines if l.strip()):
                continue
            entry = f'    {{"{sv}", nullptr, 1, true }},'
            lines.append(entry)
    if emit:
        out = sys.argv[sys.argv.index("--emit") + 1]
        open(out, "w").write("\n".join(lines) + "\n")
        print(f"共 {len(lines)} 行 → {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
