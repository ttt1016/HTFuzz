#!/usr/bin/env python3
"""
Phase A 执行器: 白盒表合并 + 重建 + 引擎测试 一条龙

用法（宿主机）: expand_harness.py <module> [cap]
  1. gen_whitebox 生成候选表
  2. 合并进 harness（去重, 上限 cap=150）
  3. 容器内重建 CTF .so
  4. 跑引擎对比前后检出数
"""

import json
import os
import re
import subprocess
import sys

PF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKER = "opentitan-env-fwt"


def dx(cmd, timeout=1800):
    return subprocess.run(
        ["docker", "exec", DOCKER, "bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def main():
    module = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    ctf = f"{PF}/perip/{module}-ctf"
    harness = f"{ctf}/harness"
    cpps = [f for f in os.listdir(harness) if f.endswith(".cpp")]
    pref = [f for f in cpps if module in f]
    hpath = os.path.join(harness, (pref or cpps)[0])

    # 1) 候选表
    subprocess.run(
        [sys.executable, f"{PF}/scripts/gen_whitebox.py", ctf, "--emit", f"/tmp/{module}_sigs.txt"],
        capture_output=True,
        text=True,
    )
    cand_file = f"/tmp/{module}_sigs.txt"
    if not os.path.exists("/tmp/" + f"{module}_sigs.txt"):
        print(f"[{module}] gen_whitebox 失败")
        sys.exit(1)

    # 2) 合并进 harness（去重, 上限）
    s = open(hpath).read()
    m = re.search(r"(static SigEntry g_sigs\[\] = \{\n)(.*?)(\n\};)", s, re.DOTALL)
    existing = set(re.findall(r'\{"([^"]+)"', m.group(2)))
    add = []
    for l in cand_file and open(f"/tmp/{module}_sigs.txt").read().splitlines():
        l = l.strip()
        if not l:
            continue
        nm = l.lstrip("{").split(",")[0].strip().strip('"')
        if nm not in existing:
            add.append(l)
            existing.add(nm)
        if len(add) >= cap:
            break
    newtable = (
        m.group(1) + m.group(2).rstrip("\n") + (",\n" if add else "") + "\n".join(add) + m.group(3)
    )
    newtable = re.sub(r",,(\s*)\};", r"\n};", newtable)
    newtable = re.sub(r",\s*,", ",", newtable)
    newtable = re.sub(r",+(\s*)};", r"\1};", newtable)
    s = s[: m.start()] + newtable + s[m.end() :]
    open(hpath, "w").write(s)
    print(f"[{module}] 追加 {len(add)} 条白盒信号（cap={cap}）")

    # 3) 容器内重建
    if not os.path.exists(f"{PF}/perip/{module}-ctf/filelist.f"):
        subprocess.run(
            [sys.executable, f"{PF}/scripts/gen_filelist.py", ctf],
            capture_output=True,
            text=True,
            timeout=120,
        )
        print(f"[{module}] filelist 由 gen_filelist 生成")
    r = dx(f"""
export PATH=/tools/verilator/v5.050/bin:$PATH
cd /workspace/HTFuzz/perip/{module}-ctf
verilator --cc --lib-create libpf_{module}_ctf --top-module {module}_perip_tb \
  -f filelist.f --Mdir obj_so -CFLAGS -fPIC -LDFLAGS -fPIC -Wno-fatal -j 10 \
  2>&1 | grep -E "%Error" | head -3
cd obj_so
python3 /workspace/HTFuzz/scripts/gen_bindings.py .. 2>&1 | head -2
H=pf_{module}_harness.cpp
g++ -c -fPIC -fcoroutines -O2 -I/tools/verilator/v5.050/share/verilator/include \
  -I/tools/verilator/v5.050/share/verilator/include/vltstd -I. ../harness/$H \
  -o pf_h.o 2>&1 | grep -E "error" | head -4
make -f V{module}_perip_tb.mk libpf_{module}_ctf.a libpf_{module}_ctf.so \
  VK_USER_OBJS=pf_harness.o -j 10 2>&1 | grep -E "%Error|undefined" | head -3
ls libpf_{module}_ctf.so >/dev/null 2>&1 && echo REBUILD_OK
""")
    ok = "REBUILD_OK" in (r.stdout + r.stderr)
    if not ok:
        print((r.stdout + r.stderr)[-600:])
        sys.exit(1)
    print(f"[{module}] 重建 OK")

    # 4) 引擎对比
    before = f"{PF}/fuzz/discover_{module}.json"
    prev = json.load(open(before)).get("findings", []) if os.path.exists(before) else []
    prev_keys = {(f.get("oracle"), f.get("signal")) for f in prev}
    p = dx(
        f"cd /workspace/HTFuzz && python3 scripts/discover_engine.py "
        f"perip/{module}-ctf {module} /workspace/HTFuzz/traces/{module}_regmap.json "
        f"2>&1 | tail -3",
        timeout=600,
    )
    print((p.stdout or "")[-500:])
    new = json.load(open(before)).get("findings", []) if os.path.exists(before) else []
    new_keys = {(f.get("oracle"), f.get("signal")) for f in new}
    added = new_keys - prev_keys
    print(f"[{module}] 检出 {len(prev)} → {len(new)} (新增 {len(added)})")
    for o, s2 in list(added)[:10]:
        print(f"  + [{o}] {o.split() and s2}")


if __name__ == "__main__":
    main()
