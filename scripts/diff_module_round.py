#!/usr/bin/env python3
"""
逐模块差分改造驱动（目标节奏）:
  对每个模块: fresh 构建(如未建) → diff_replay 模块测试 → triage 差分叠加 →
  台账追加 → git commit+push → 下一模块

用法（宿主机）: diff_module_round.py <module> [<module> ...]
"""

import json
import os
import subprocess
import sys

PF = os.environ.get("PF_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORT = os.path.join(PF, "reports", "CTF-SUMMARY-REPORT.md")
GIT = ["git", "-c", "user.name=fantasy", "-c", "user.email=fantasy@iscas.ac.cn"]

# 模块名别名（引擎 module 名 → perip 目录名）
DIR_ALIAS = {"lc_ctrl": "lc"}


def sh(cmd, timeout=1800, cwd=PF):
    return subprocess.run(
        cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout, cwd=cwd
    )


def fresh_ready(module):
    dname = DIR_ALIAS.get(module, module)
    obj = f"{PF}/perip/{dname}-fresh/obj_so"
    return os.path.isdir(obj) and any(f.endswith(".so") for f in os.listdir(obj))


def one_module(module):
    print(f"\n########## 模块 {module} ##########", flush=True)
    dname = DIR_ALIAS.get(module, module)
    # 1) fresh 构建（已建则跳过）
    if fresh_ready(module):
        print(f"[{module}] fresh 已建成, 跳过构建", flush=True)
        build = "已建"
    else:
        p = sh([sys.executable, f"{PF}/scripts/build_fresh_all.py", dname], timeout=2400)
        out = (p.stdout or "") + (p.stderr or "")
        build = "OK" if "BUILD OK" in out else "FAIL"
        print(out[-400:], flush=True)
        if build == "FAIL":
            return False
    # 2) 模块测试: 差分重放
    p = sh(
        [
            "docker",
            "exec",
            "opentitan-env-fwt",
            "bash",
            "-c",
            f"cd /workspace/HTFuzz && python3 scripts/diff_replay.py {dname} 0",
        ],
        timeout=900,
    )
    out = (p.stdout or "") + (p.stderr or "")
    verdict = "DIVERGENT" if "DIVERGENT" in out else ("IDENTICAL" if "IDENTICAL" in out else "?")
    print(out[-500:], flush=True)
    # 3) triage 差分叠加（有引擎检出时）
    jf = f"{PF}/fuzz/discover_{module}.json"
    if os.path.exists(jf):
        p2 = sh(
            [
                "docker",
                "exec",
                "opentitan-env-fwt",
                "bash",
                "-c",
                f"cd /workspace/HTFuzz && python3 scripts/triage_nofresh.py "
                f"fuzz/discover_{module}.json {module}",
            ],
            timeout=900,
        )
        print((p2.stdout or "")[-700:], flush=True)
    # 4) 台账 + git
    first = None
    jf = f"{PF}/fuzz/diff_{dname}.json"
    if os.path.exists(jf):
        j = json.load(open(jf))
        first = j.get("first_divergence")
    tgt = "—"
    if first:
        tgt = first.get("signal") or f"addr={first.get('addr')}"
    row = (
        f"| {module} | {build}（自动化） | "
        f"{'✅ ' if verdict == 'DIVERGENT' else '⚪ '}{verdict} 首偏离 "
        f"{first['idx'] if first else '—'} {tgt if verdict == 'DIVERGENT' else ''} | |"
    )
    rep = open(REPORT).read()
    marker = "| aes |"
    idx = rep.find(marker)
    if idx != -1:
        eol = rep.find("\n", idx)
        rep = rep[: eol + 1] + row + "\n" + rep[eol + 1 :]
        open(REPORT, "w").write(rep)
    subprocess.run(GIT + ["add", "-A"], cwd=PF)
    subprocess.run(
        GIT + ["commit", "-m", f"差分层模块: {module} fresh 建成 + 差分 {verdict} + 台账"],
        cwd=PF,
        capture_output=True,
    )
    subprocess.run(GIT + ["push", "origin", "main"], cwd=PF, capture_output=True)
    print(f"[{module}] 报告+git 完成", flush=True)
    return True


if __name__ == "__main__":
    mods = sys.argv[1:]
    for m in mods:
        ok = one_module(m)
        if not ok:
            print(f"[{m}] 失败, 停止本轮（人工处理后重跑）")
            sys.exit(1)
    print("=== 本轮模块差分改造完成 ===")
