#!/usr/bin/env python3
"""
变异测试闭环 —— 分类学"样本外有效性"验证（报告 39.3 待办兑现）

原理: 向 fresh(干净) RTL 注入按已知 bug 族合成的变异体 → 重建 DUT →
      跑 oracle 引擎 + 差分重放（mut vs fresh）→ 统计检出/差分杀伤率。
      哪类变异体全部逃逸 = 性质缺口（直接倒推新 oracle）。

用法（宿主机运行, 需 docker）: mutate_fresh.py <module> [mutant ...]
变异体注册表: MUTANTS[module]（按 P1/P2 已知注入"族"合成, 不参考具体已知 diff 语义）
"""

import json
import os
import shutil
import subprocess
import sys

# 宿主机脚本根 = scripts 的上级; 容器内路径由 dx() 用 relpath 换算
PF = os.environ.get("PF_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCKER = "opentitan-env-fwt"


def dx(cmd, timeout=900):
    """容器内执行"""
    p = subprocess.run(
        ["docker", "exec", DOCKER, "bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p


# ---- 变异体注册表 ----
# 每项: (mid, 注入函数名) —— 注入在 build_mutant 后对 mut 目录的 fresh RTL 执行
MUTANTS = {
    "hmac": ["wipe_noop"],
}


def build_mutant(module, mid):
    """fresh 副本（排除 obj_so）→ perip/<module>-mut-<mid>/"""
    src = f"{PF}/perip/{module}-fresh"
    dst = f"{PF}/perip/{module}-mut-{mid}"
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("obj_so", "obj_*"))
    return dst


def inject(module, mid, dut_dir):
    """按注册表对 mut 目录的 RTL 做文本级变异。返回注入描述或 None。"""
    if module == "hmac" and mid == "wipe_noop":
        # 族: 擦除失效。wipe 分支写原值（key 保持）→ 擦除后密钥残留
        p = os.path.join(dut_dir, "hw/ip/hmac/rtl/hmac.sv")
        s = open(p).read()
        old = """    if (wipe_secret) begin
      secret_key_d = {32{wipe_v}};"""
        new = """    if (wipe_secret) begin
      secret_key_d = secret_key; // MUTANT wipe_noop: wipe 写回原值"""
        if old in s:
            open(p, "w").write(s.replace(old, new, 1))
            return "wipe 分支写回原值（擦除失效族）"
        return f"注入点未匹配: {p}"
    return None


def rebuild(dut_dir, module, mid):
    """容器内重建 .so（复用 filelist/wrapper/harness）"""
    rel = os.path.relpath(dut_dir, PF)
    cmd = f"""
export PATH=/tools/verilator/v5.050/bin:$PATH
cd /workspace/HTFuzz/{rel}
rm -rf obj_so
verilator --cc --lib-create pf_{module}_mut --top-module hmac_perip_tb \
  -f filelist.f --Mdir obj_so -CFLAGS -fPIC -LDFLAGS -fPIC -Wno-fatal -j 10 \
  2>&1 | grep -E "%Error" | head -3
cd obj_so
g++ -c -fPIC -fcoroutines -O2 -I/tools/verilator/v5.050/share/verilator/include \
  -I/tools/verilator/v5.050/share/verilator/include/vltstd -I. \
  ../harness/pf_hmac_harness.cpp -o pf_hmac_harness.o 2>&1 | head -3
make -f Vhmac_perip_tb.mk libpf_hmac_mut.a libpf_hmac_mut.so \
  VK_USER_OBJS=pf_hmac_harness.o -j 10 2>&1 | grep -E "%Error" | head -3
ls libpf_hmac_mut.so >/dev/null 2>&1 && echo BUILD_OK
"""
    p = dx(cmd)
    ok = "BUILD_OK" in (p.stdout + p.stderr)
    if not ok:
        print(f"  [build] 失败:\n{(p.stdout + p.stderr)[-500:]}")
    return ok


def _trace_container(dut_dir, seed, tag):
    out = f"/tmp/trace_{tag}.json"
    p = dx(
        f"python3 /workspace/HTFuzz/scripts/dut_trace.py "
        f"{os.path.relpath(dut_dir, PF)} hmac "
        f"/workspace/HTFuzz/traces/hmac_regmap.json {out} {seed}",
        timeout=600,
    )
    if p.returncode != 0:
        raise RuntimeError(f"dut_trace[{tag}] rc={p.returncode}: {p.stderr[-300:]}")
    # /tmp 在容器与宿主机不共享 → 容器内 cat 回来
    p2 = dx(f"cat {out}")
    return json.loads(p2.stdout)


def main():
    if len(sys.argv) < 2:
        print("用法: mutate_fresh.py <module> [mutant ...]  （宿主机运行, 需 docker）")
        sys.exit(1)
    module = sys.argv[1]
    only = set(sys.argv[2:])
    results = []
    for mid in MUTANTS.get(module, []):
        if only and mid not in only:
            continue
        print(f"=== 变异体 {mid} ===")
        dut_dir = build_mutant(module, mid)
        desc = inject(module, mid, dut_dir)
        print(f"  [inject] {desc}")
        if not rebuild(dut_dir, module, mid):
            results.append({"module": module, "mutant": mid, "error": "build"})
            continue
        # 差分基线: fresh 两遍（缓存复用）
        t_f1 = _trace_container(f"{PF}/perip/{module}-fresh", 0, "f1")
        t_f2 = _trace_container(f"{PF}/perip/{module}-fresh", 0, "f2")
        t_mut = _trace_container(dut_dir, 0, "mut")
        sys.path.insert(0, os.path.join(PF, "scripts"))
        import diff_replay as dr

        diff = dr.compare(t_mut, t_f1, t_f2)
        # 引擎检出（容器内; 侧车输出避免覆盖 CTF findings）
        bak = f"{PF}/fuzz/discover_{module}.json"
        saved = open(bak).read() if os.path.exists(bak) else None
        dx(
            f"python3 /workspace/HTFuzz/scripts/discover_engine.py "
            f"{os.path.relpath(dut_dir, PF)} {module} "
            f"/workspace/HTFuzz/traces/{module}_regmap.json",
            timeout=600,
        )
        mut_findings = []
        if os.path.exists(bak):
            mut_findings = json.load(open(bak)).get("findings", [])
            if saved is not None:
                open(bak, "w").write(saved)  # 还原 CTF 侧
        res = {
            "module": module,
            "mutant": mid,
            "inject": desc,
            "oracle_findings": len(mut_findings),
            "oracle_killed": len(mut_findings) > 0,
            "diff_verdict": diff["verdict"],
            "diff_killed": diff["verdict"] == "DIVERGENT",
            "first_divergence": diff["first_divergence"],
            "signals": sorted({f.get("signal", "?") for f in mut_findings})[:8],
        }
        json.dump(
            res, open(f"{PF}/fuzz/mut_{module}_{mid}.json", "w"), indent=1, ensure_ascii=False
        )
        results.append(res)
        fd = res["first_divergence"]
        fd_str = f"idx={fd['idx']} {fd.get('signal', fd.get('channel'))}" if fd else "无"
        print(
            f"  oracle: {res['oracle_findings']} 条 (killed={res['oracle_killed']})"
            f"  diff: {res['diff_verdict']} (killed={res['diff_killed']}) 首偏离: {fd_str}"
        )
    json.dump(
        results,
        open(f"{PF}/fuzz/mutation_{module}_summary.json", "w"),
        indent=1,
        ensure_ascii=False,
    )
    ko = sum(1 for r in results if r.get("oracle_killed"))
    kd = sum(1 for r in results if r.get("diff_killed"))
    print(f"\n=== 杀伤率: oracle {ko}/{len(results)}  diff {kd}/{len(results)} ===")


if __name__ == "__main__":
    main()
