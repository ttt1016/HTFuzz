#!/usr/bin/env python3
"""
O-L 闭环 fuzzing v2 —— 覆盖率引导 + O-K 不变量判定 + pairwise 组合 + plateau 剪枝

完整闭环：
  种子变异 → 执行 → coverage 增量 → 语料库保留
    → 新覆盖区域跑 O-K 不变量 → VIOLATION = 新漏洞候选
  plateau（无新覆盖 N 迭代）→ 语料库剪枝 → 强制重探索
  pairwise：安全信号两两组合状态计入覆盖（交互盲区）

用法:
  python3 ol_full_loop.py perip/hmac-ctf hmac traces/hmac_regmap.json \
      [--iterations 80] [--plateau 15]
"""

import glob
import itertools
import json
import os
import random
import sys

PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")
OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")


def load_dut(dut_dir, module):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from llm_agent import DutHandle

    return DutHandle(dut_dir, module)


def load_regmap(path):
    raw = json.load(open(path))
    regmap = {}
    if isinstance(raw, list):
        for r in raw:
            if not isinstance(r, dict):
                continue
            if r.get("kind") == "reg" and "name" in r and "offset" in r:
                try:
                    regmap[r["name"].lower()] = (
                        int(r["offset"], 0) if isinstance(r["offset"], str) else r["offset"]
                    )
                except Exception:
                    pass
            elif r.get("kind") == "multireg" and "name" in r and "offset" in r:
                cnt = int(r.get("count", 1))
                stride = int(r.get("stride", 4))
                off0 = int(r["offset"], 0) if isinstance(r["offset"], str) else r["offset"]
                nm = r["name"].lower()
                for i in range(cnt):
                    regmap[f"{nm}_{i}"] = off0 + i * stride
    elif isinstance(raw, dict):
        for k, v in raw.items():
            try:
                regmap[k] = int(v, 0) if isinstance(v, str) else v
            except Exception:
                pass
    return regmap


def build_seeds(module):
    seeds = []
    for f in glob.glob(os.path.join(PF, "fuzz", f"discover_{module}_deep_agent.json")):
        d = json.load(open(f))
        for r in d.get("agent_results", []):
            ops = []
            for t in r.get("trace", []):
                a = t.get("action", {})
                if isinstance(a, dict) and a.get("action") == "write":
                    try:
                        ops.append(
                            (
                                "write",
                                int(str(a.get("addr", "0")), 0),
                                int(str(a.get("data", "0")), 0),
                            )
                        )
                    except Exception:
                        pass
                elif isinstance(a, dict) and a.get("action") == "step":
                    ops.append(("step", int(a.get("n", 10)), 0))
            if ops:
                seeds.append({"name": f"agent_{r.get('signal', 'x')[:30]}", "ops": ops})
    for f in glob.glob(os.path.join(PF, "fuzz", f"discover_{module}.json")):
        d = json.load(open(f))
        for x in d.get("findings", [])[:3]:
            seeds.append(
                {
                    "name": f"fuzz_{x.get('oracle', '')[:12]}",
                    "ops": [("write", 0x20, 0xDEADBEEF), ("step", 50)],
                }
            )
    seeds.append(
        {
            "name": "generic_explore",
            "ops": [
                ("write", 0x10, 0x1),
                ("step", 20),
                ("write", 0x14, 0x1),
                ("step", 100),
                ("write", 0x20, 0xDEADBEEF),
                ("step", 50),
            ],
        }
    )
    return seeds


class Coverage:
    """值状态覆盖 + pairwise 组合覆盖"""

    def __init__(self, dut):
        self.dut = dut
        self.sigs = dict(dut.sigs)
        self.values = {}  # sig -> set of value tuples
        self.pairwise = set()  # (sigA, valA_bin, sigB, valB_bin) 组合
        self.prev = {}

    def _bin(self, v):
        return 1 if any(x != 0 for x in v) else 0

    def sample(self):
        cur = {}
        for name, words in self.sigs.items():
            vals = tuple(self.dut.api.pf_sig_read(name.encode(), w) for w in range(words))
            cur[name] = vals
            old = self.prev.get(name)
            if old is not None and vals != old:
                self.values.setdefault(name, set()).add(vals)
            self.prev[name] = vals
        # pairwise：非零信号两两组合
        active = [(n, self._bin(v)) for n, v in cur.items() if self._bin(v)]
        for (na, va), (nb, vb) in itertools.combinations(active, 2):
            self.pairwise.add((na, va, nb, vb))

    def size(self):
        return sum(len(v) for v in self.values.values()) + len(self.pairwise)

    def merge_max(self, other):
        new = False
        for name, vals in other.values.items():
            mine = self.values.setdefault(name, set())
            for v in vals:
                if v not in mine:
                    mine.add(v)
                    new = True
        for p in other.pairwise:
            if p not in self.pairwise:
                self.pairwise.add(p)
                new = True
        return new


def execute_ops(dut, cov, ops):
    dut.reset()
    dut.step(5)
    cov.sample()
    for op in ops:
        if op[0] == "write":
            try:
                dut.write(op[1], op[2])
            except Exception:
                pass
        elif op[0] == "step":
            dut.step(min(op[1], 2000))
        cov.sample()


def mutate(seed_ops, regmap, rng):
    ops = list(seed_ops) if seed_ops else [("write", 0x20, 0xDEADBEEF), ("step", 50)]
    mut_type = rng.choice(["data", "addr", "step", "insert", "delete", "dup", "burst"])
    new_ops = list(ops)
    if mut_type == "data":
        wi = [i for i, o in enumerate(ops) if o[0] == "write"]
        if wi:
            i = rng.choice(wi)
            new_ops[i] = (
                "write",
                ops[i][1],
                rng.choice(
                    [
                        0xDEADBEEF,
                        0x0,
                        0xFFFFFFFF,
                        rng.randint(0, 0xFFFFFFFF),
                        ops[i][2] ^ rng.randint(1, 0xFFFF),
                    ]
                ),
            )
    elif mut_type == "addr":
        wi = [i for i, o in enumerate(ops) if o[0] == "write"]
        if wi and regmap:
            i = rng.choice(wi)
            new_ops[i] = ("write", rng.choice(list(regmap.values())), ops[i][2])
    elif mut_type == "step":
        si = [i for i, o in enumerate(ops) if o[0] == "step"]
        if si:
            i = rng.choice(si)
            new_ops[i] = ("step", rng.choice([5, 20, 50, 100, 500]))
        else:
            new_ops.append(("step", 100))
    elif mut_type == "insert" and regmap:
        new_ops.insert(
            rng.randint(0, len(new_ops)),
            ("write", rng.choice(list(regmap.values())), rng.randint(0, 0xFFFFFFFF)),
        )
    elif mut_type == "delete" and len(new_ops) > 2:
        new_ops.pop(rng.randint(0, len(new_ops) - 1))
    elif mut_type == "dup" and ops:
        new_ops.extend(ops)
    elif mut_type == "burst" and regmap:
        # 连续突发写（FIFO 压力类）
        base = rng.choice(list(regmap.values()))
        for _ in range(rng.randint(4, 16)):
            new_ops.append(("write", base, rng.randint(0, 0xFFFFFFFF)))
        new_ops.append(("step", rng.choice([50, 100])))
    return new_ops, mut_type


def run_invariant_checks(dut, regmap, module):
    """对当前 DUT 跑 O-K 不变量检查，返回 VIOLATION 列表"""
    inv_path = os.path.join(PF, "invariants", f"{module}.json")
    if not os.path.exists(inv_path):
        return []
    inv = json.load(open(inv_path))
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from ok_invariant import InvariantChecker

    checker = InvariantChecker(dut, regmap)
    violations = []
    for item in inv.get("invariants", []):
        r = checker.check(item)
        if r:
            violations.append(r)
    return violations


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("dut_dir")
    ap.add_argument("module")
    ap.add_argument("regmap_path")
    ap.add_argument("--iterations", type=int, default=80)
    ap.add_argument("--plateau", type=int, default=15, help="无新覆盖 N 迭代触发剪枝")
    args = ap.parse_args()

    regmap = load_regmap(args.regmap_path)
    dut = load_dut(args.dut_dir, args.module)
    seeds = build_seeds(args.module)

    print(f"=== O-L 闭环 fuzzing v2: {args.module} ===")
    print(
        f"种子: {len(seeds)}, 白盒信号: {len(dut.sigs)}, "
        f"迭代: {args.iterations}, plateau: {args.plateau}"
    )

    rng = random.Random(0xC0FFEE)
    corpus = []
    global_cov = Coverage(dut)
    new_findings = []
    plateau_count = 0
    exec_count = 0

    # 基线
    for seed in seeds:
        cov = Coverage(dut)
        execute_ops(dut, cov, seed["ops"])
        exec_count += 1
        if global_cov.merge_max(cov):
            corpus.append({"name": seed["name"], "ops": seed["ops"]})
    print(f"基线: {len(seeds)} 种子 → coverage={global_cov.size()} corpus={len(corpus)}")

    # 变异循环
    for it in range(args.iterations):
        if not corpus:
            break
        entry = rng.choice(corpus)
        new_ops, mut_type = mutate(entry["ops"], regmap, rng)
        cov = Coverage(dut)
        execute_ops(dut, cov, new_ops)
        exec_count += 1

        if global_cov.merge_max(cov):
            corpus.append({"name": f"mut_{it}_{mut_type}", "ops": new_ops})
            plateau_count = 0
            # 新覆盖区域 → O-K 不变量判定（每 5 个新覆盖跑一次，控制耗时）
            if len(corpus) % 5 == 0:
                viols = run_invariant_checks(dut, regmap, args.module)
                for v in viols:
                    dup = any(
                        x["signal"] == v["signal"] and x["rule"] == v["rule"] for x in new_findings
                    )
                    if not dup:
                        new_findings.append(v)
                        print(
                            f"  [iter {it}] *** NEW VIOLATION: {v['signal']} "
                            f"({v['rule']}): {str(v['desc'])[:80]}"
                        )
            print(
                f"  [iter {it}] +cov (mut={mut_type}) "
                f"global={global_cov.size()} corpus={len(corpus)}"
            )
        else:
            plateau_count += 1
            # plateau 剪枝
            if plateau_count >= args.plateau and len(corpus) > 8:
                prune_n = max(1, int(len(corpus) * rng.uniform(0.3, 0.7)))
                rng.shuffle(corpus)
                pruned = corpus[:prune_n]
                corpus = corpus[prune_n:]
                plateau_count = 0
                print(f"  [iter {it}] PLATEAU: pruned {len(pruned)} entries, corpus={len(corpus)}")
        if it % 20 == 19:
            print(
                f"  [iter {it}] cov={global_cov.size()} corpus={len(corpus)} "
                f"findings={len(new_findings)}"
            )

    # 最终跑一遍全部不变量
    print("\n--- 最终不变量检查 ---")
    final_viols = run_invariant_checks(dut, regmap, args.module)
    for v in final_viols:
        dup = any(x["signal"] == v["signal"] and x["rule"] == v["rule"] for x in new_findings)
        if not dup:
            new_findings.append(v)
        print(f"  [{'VIOLATION' if not dup else 'dup'}] {v['signal']} ({v['rule']})")

    out = os.path.join(PF, "fuzz", f"closed_loop_v2_{args.module}.json")
    json.dump(
        {
            "module": args.module,
            "iterations": args.iterations,
            "exec_count": exec_count,
            "final_coverage": global_cov.size(),
            "pairwise_count": len(global_cov.pairwise),
            "corpus_size": len(corpus),
            "violations": new_findings,
        },
        open(out, "w"),
        indent=1,
        ensure_ascii=False,
    )
    print("\n=== 汇总 ===")
    print(
        f"执行: {exec_count}, 覆盖: {global_cov.size()} "
        f"(含 pairwise {len(global_cov.pairwise)}), 语料库: {len(corpus)}"
    )
    print(f"不变量违反: {len(new_findings)} 条")
    for v in new_findings:
        print(f"  [{v['rule']}] {v['signal']}: {str(v['desc'])[:80]}")
    print(f"输出: {out}")


if __name__ == "__main__":
    main()
