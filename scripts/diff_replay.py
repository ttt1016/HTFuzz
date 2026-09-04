#!/usr/bin/env python3
"""
差分重放比对器 —— CTF(注入版) vs fresh(干净版) 行为轨迹比对

三遍跑法:
  1. CTF  DUT 跑 dut_trace        → trace_ctf
  2. fresh DUT 跑同 seed           → trace_fresh1
  3. fresh 再跑一遍（同 seed）      → trace_fresh2   ← 非确定性基线

比对规则:
  稳定集 = fresh 两遍逐位一致的 (信号,字) / 回读项 —— 只在稳定集内做差分
  （RNG/熵/掩码类合法非确定性输出自动过滤）
  首偏离点 = 稳定集内 CTF 与 fresh 第一个不同的动作序号
  判定: 有稳定偏离 → DIVERGENT（候选为真），全一致 → IDENTICAL（候选存疑/误报）

用法: diff_replay.py <module> [seed]
输出: fuzz/diff_<module>.json
"""
import json, os, subprocess, sys

PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")
sys.path.insert(0, os.path.join(PF, "scripts"))


def run_trace(dut_dir, module, seed, tag):
    out = f"/tmp/trace_{module}_{tag}.json"
    regmap = f"{PF}/traces/{module}_regmap.json"
    args = [sys.executable, f"{PF}/scripts/dut_trace.py", dut_dir, module, regmap, out, str(seed)]
    p = subprocess.run(args, capture_output=True, text=True, timeout=300, cwd=PF)
    if p.returncode != 0:
        raise RuntimeError(f"[{tag}] dut_trace 失败 rc={p.returncode}: {p.stderr[-400:]}")
    return json.load(open(out))


def cmp_rows(a, b):
    """比对两条动作记录的稳定字段（readback/特殊），供回读通道用"""
    return (a.get("readback") == b.get("readback")
            and a.get("error") == b.get("error"))


def compare(trace_ctf, trace_f1, trace_f2):
    # 1) 非确定性过滤: fresh 两遍
    f1 = {r["idx"]: r for r in trace_f1["trace"]}
    f2 = {r["idx"]: r for r in trace_f2["trace"]}
    n_act = min(trace_f1["n_actions"], trace_f2["n_actions"])

    stable_sigs = {}   # sig -> {word: True}（逐字级稳定性）
    for i in range(n_act):
        r1, r2 = f1.get(i), f2.get(i)
        if not r1 or not r2:
            continue
        for sig, words in r1["sigs"].items():
            w2 = r2["sigs"].get(sig)
            if w2 is None:
                continue
            st = stable_sigs.setdefault(sig, {})
            for w, v in enumerate(words):
                v2 = w2[w] if w < len(w2) else None
                if v == v2:
                    st[w] = True
                else:
                    st[w] = False

    stable_rb = {}     # idx -> True（该动作的回读在 fresh 两遍一致）
    for i in range(n_act):
        r1, r2 = f1.get(i), f2.get(i)
        if r1 and r2 and cmp_rows(r1, r2):
            stable_rb[i] = True

    # 2) CTF vs fresh 差分（仅稳定集）
    ctf = {r["idx"]: r for r in trace_ctf["trace"]}
    n_cmp = min(trace_ctf["n_actions"], n_act)
    divergences = []
    divergent_sigs = {}
    first = None
    for i in range(n_cmp):
        rc, rf = ctf.get(i), f1.get(i)
        if not rc or not rf:
            continue
        # 回读通道
        if stable_rb.get(i):
            if rc.get("readback") != rf.get("readback") or rc.get("error") != rf.get("error"):
                d = {"idx": i, "channel": "readback", "kind": rc["kind"],
                     "addr": rc.get("addr"), "ctf": rc.get("readback"),
                     "fresh": rf.get("readback")}
                divergences.append(d)
                if first is None:
                    first = d
        # 白盒信号通道
        for sig, st in stable_sigs.items():
            wc = rc["sigs"].get(sig, [])
            wf = rf["sigs"].get(sig, [])
            for w, ok in st.items():
                if not ok or w >= len(wc) or w >= len(wf):
                    continue
                if wc[w] != wf[w]:
                    divergent_sigs.setdefault(sig, set()).add(i)
                    if len(divergences) < 400:  # 证据截断保护
                        d = {"idx": i, "channel": "sig", "signal": sig, "word": w,
                             "kind": rc["kind"], "addr": rc.get("addr"),
                             "ctf": wc[w], "fresh": wf[w]}
                        divergences.append(d)
                    if first is None:
                        first = d

    div_sig_summary = {s: len(v) for s, v in sorted(divergent_sigs.items(),
                                                    key=lambda kv: -len(kv[1]))}
    return {
        "verdict": "DIVERGENT" if divergences else "IDENTICAL",
        "first_divergence": first,
        "n_actions_compared": n_cmp,
        "n_divergences": len(divergences),
        "divergent_signals": div_sig_summary,
        "evidence": divergences[:200],
        "n_stable_signals": sum(1 for st in stable_sigs.values() if st),
        "n_signals_total": len(stable_sigs),
        "n_stable_readbacks": len(stable_rb),
    }


def main():
    if len(sys.argv) < 2:
        print("用法: diff_replay.py <module> [seed]")
        sys.exit(1)
    module = sys.argv[1]
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    regmap = f"{PF}/traces/{module}_regmap.json"

    try:
        t_ctf = run_trace(f"{PF}/perip/{module}-ctf", module, seed, "ctf", regmap)
        t_f1 = run_trace(f"{PF}/perip/{module}-fresh", module, seed, "fresh1", regmap)
        t_f2 = run_trace(f"{PF}/perip/{module}-fresh", module, seed, "fresh2", regmap)
    except Exception as e:
        print(f"[diff] 轨迹采集失败: {e}")
        sys.exit(2)

    result = compare(t_ctf, t_f1, t_f2)
    result.update({"module": module, "seed": seed})
    out = f"{PF}/fuzz/diff_{module}.json"
    json.dump(result, open(out, "w"), indent=1, ensure_ascii=False)

    print(f"=== 差分判定: {module} → {result['verdict']} ===")
    fd = result.get("first_divergence")
    if fd:
        if fd["channel"] == "readback":
            print(f"  首偏离: idx={fd['idx']} {fd['kind']} addr={fd['addr']:#x} "
                  f"ctf={fd['ctf']:#x} fresh={fd['fresh']:#x}")
        else:
            print(f"  首偏离: idx={fd['idx']} {fd['signal']}[{fd['word']}] "
                  f"ctf={fd['ctf']:#x} fresh={fd['fresh']:#x}")
    print(f"  偏离信号: {result['divergent_signals'] or '无'}")
    print(f"  稳定信号: {result['n_stable_signals']}/{result['n_signals_total']}"
          f"  比对动作: {result['n_actions_compared']}  → {out}")


def run_trace(dut_dir, module, seed, tag, regmap):
    out = f"/tmp/trace_{module}_{tag}.json"
    args = [sys.executable, f"{PF}/scripts/dut_trace.py", dut_dir, module,
            regmap, out, str(seed)]
    p = subprocess.run(args, capture_output=True, text=True, timeout=600, cwd=PF)
    if p.returncode != 0:
        raise RuntimeError(f"[{tag}] dut_trace rc={p.returncode}: {(p.stderr or '')[-400:]}")
    return json.load(open(out))


if __name__ == "__main__":
    main()
