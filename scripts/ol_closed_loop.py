#!/usr/bin/env python3
"""
O-L 闭环 fuzzing —— 覆盖率引导的寄存器序列变异（HitFuzz 思想移植）

覆盖率：白盒信号翻转统计（每个信号在序列执行中的值变化次数 = 等效 toggle）
种子库：26 个 bug 的 agent trace + fuzzing findings 序列
循环：种子变异 → 执行 → coverage 增量 → 保留/丢弃（MaxMap）→ 新候选

用法:
  python3 ol_closed_loop.py perip/hmac-ctf hmac traces/hmac_regmap.json \
      [--iterations 50] [--seed-dir fuzz/seeds]
"""
import json, os, re, sys, random, ctypes, glob

PF = os.environ.get("PF_ROOT", "/workspace/pickerfuzz")
OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")


# ---------------------------------------------------------------------------
# DUT 句柄（复用 llm_agent 的 DutHandle）
# ---------------------------------------------------------------------------
def load_dut(dut_dir, module):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from llm_agent import DutHandle
    return DutHandle(dut_dir, module)


# ---------------------------------------------------------------------------
# 种子库构建：从 agent trace + findings 提取寄存器序列
# ---------------------------------------------------------------------------
def build_seeds(module):
    """从 agent trace 和 fuzzing findings 构建种子库"""
    seeds = []
    # 1) agent trace 里的 write 序列
    for f in glob.glob(os.path.join(PF, "fuzz", f"discover_{module}_deep_agent.json")):
        d = json.load(open(f))
        for r in d.get("agent_results", []):
            ops = []
            for t in r.get("trace", []):
                a = t.get("action", {})
                if isinstance(a, dict) and a.get("action") == "write":
                    try:
                        ops.append(("write", int(str(a.get("addr", "0")), 0),
                                    int(str(a.get("data", "0")), 0)))
                    except Exception:
                        pass
                elif isinstance(a, dict) and a.get("action") == "step":
                    ops.append(("step", int(a.get("n", 10)), 0))
            if ops:
                seeds.append({"name": f"agent_{r.get('signal', 'x')[:30]}",
                              "ops": ops,
                              "source": "agent_trace",
                              "verdict": r.get("agent_verdict", {}).get("verdict", "")})
    # 2) fuzzing findings 的触发序列（从 oracle 描述推断的通用序列）
    for f in glob.glob(os.path.join(PF, "fuzz", f"discover_{module}.json")):
        d = json.load(open(f))
        for x in d.get("findings", [])[:3]:
            # 通用擦除序列种子
            seeds.append({"name": f"fuzz_{x.get('oracle', '')}_{x.get('signal', '')[:20]}",
                          "ops": [("write", 0x20, 0xDEADBEEF),   # wipe_secret
                                  ("step", 50)],
                          "source": "fuzz_finding",
                          "verdict": "candidate"})
    # 3) 通用探索种子
    seeds.append({"name": "generic_explore",
                  "ops": [("write", 0x10, 0x1), ("step", 20),
                          ("write", 0x14, 0x1), ("step", 100),
                          ("write", 0x20, 0xDEADBEEF), ("step", 50)],
                  "source": "generic", "verdict": ""})
    return seeds


# ---------------------------------------------------------------------------
# 覆盖率：白盒信号翻转统计
# ---------------------------------------------------------------------------
class ToggleCoverage:
    def __init__(self, dut):
        self.dut = dut
        self.sigs = dict(dut.sigs)
        self.bitmap = {}  # sig_name -> set of observed values（值多样性）
        self.prev = {}    # 上一拍值（翻转检测）

    def sample(self):
        """采样全部白盒信号，统计翻转和新值"""
        for name, words in self.sigs.items():
            vals = tuple(self.dut.api.pf_sig_read(name.encode(), w)
                         for w in range(words))
            old = self.prev.get(name)
            if old is not None and vals != old:
                # 翻转发生
                self.bitmap.setdefault(name, set()).add(vals)
            self.prev[name] = vals

    def bitmap_size(self):
        return sum(len(v) for v in self.bitmap.values())

    def merge_max(self, other):
        """MaxMap 语义：合并另一个 coverage，返回是否有增量"""
        new = False
        for name, vals in other.bitmap.items():
            mine = self.bitmap.setdefault(name, set())
            for v in vals:
                if v not in mine:
                    mine.add(v)
                    new = True
        return new


# ---------------------------------------------------------------------------
# 序列执行 + 覆盖率采集
# ---------------------------------------------------------------------------
def execute_ops(dut, cov, ops):
    """执行操作序列，边执行边采样覆盖率"""
    dut.reset()
    dut.step(5)
    cov.sample()
    for op in ops:
        kind = op[0]
        if kind == "write":
            try:
                dut.write(op[1], op[2])
            except Exception:
                pass
        elif kind == "step":
            dut.step(min(op[1], 2000))
        # 每步采样
        cov.sample()


# ---------------------------------------------------------------------------
# 变异器
# ---------------------------------------------------------------------------
def mutate(seed, regmap, rng):
    """对种子序列做变异：寄存器替换/数据变异/步数变异/插入删除"""
    ops = list(seed["ops"])
    if not ops:
        ops = [("write", 0x20, 0xDEADBEEF), ("step", 50)]
    mut_type = rng.choice(["data", "addr", "step", "insert", "delete", "dup"])
    new_ops = list(ops)
    if mut_type == "data" and ops:
        # 变异某个 write 的 data
        wi = [i for i, o in enumerate(ops) if o[0] == "write"]
        if wi:
            i = rng.choice(wi)
            new_ops[i] = ("write", ops[i][1],
                          rng.choice([0xDEADBEEF, 0x0, 0xFFFFFFFF,
                                      rng.randint(0, 0xFFFFFFFF),
                                      ops[i][2] ^ rng.randint(1, 0xFFFF)]))
    elif mut_type == "addr" and ops:
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
        new_ops.insert(rng.randint(0, len(new_ops)),
                       ("write", rng.choice(list(regmap.values())),
                        rng.randint(0, 0xFFFFFFFF)))
    elif mut_type == "delete" and len(new_ops) > 2:
        new_ops.pop(rng.randint(0, len(new_ops) - 1))
    elif mut_type == "dup" and ops:
        new_ops.extend(ops)
    return new_ops, mut_type


# ---------------------------------------------------------------------------
# 主循环
# ---------------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("dut_dir")
    ap.add_argument("module")
    ap.add_argument("regmap_path")
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--seed-dir", default=None)
    args = ap.parse_args()

    regmap_raw = json.load(open(args.regmap_path))
    regmap = {}
    if isinstance(regmap_raw, list):
        for r in regmap_raw:
            if isinstance(r, dict) and r.get("kind") == "reg":
                try:
                    regmap[r["name"].lower()] = int(r["offset"], 0) if isinstance(
                        r["offset"], str) else r["offset"]
                except Exception:
                    pass
            elif isinstance(r, dict) and r.get("kind") == "multireg":
                cnt = int(r.get("count", 1))
                stride = int(r.get("stride", 4))
                off0 = int(r["offset"], 0) if isinstance(r["offset"], str) else r["offset"]
                nm = r["name"].lower()
                for i in range(cnt):
                    regmap[f"{nm}_{i}"] = off0 + i * stride
    elif isinstance(regmap_raw, dict):
        for k, v in regmap_raw.items():
            try:
                regmap[k] = int(v, 0) if isinstance(v, str) else v
            except Exception:
                pass

    dut = load_dut(args.dut_dir, args.module)
    seeds = build_seeds(args.module)
    print(f"=== O-L 闭环 fuzzing: {args.module} ===")
    print(f"种子: {len(seeds)} 个, 白盒信号: {len(dut.sigs)} 个, 迭代: {args.iterations}")

    rng = random.Random(0xC0FFEE)
    corpus = []       # 保留的输入（coverage 有增量）
    global_cov = ToggleCoverage(dut)  # 全局覆盖率图
    findings = []
    exec_count = 0

    # 初始种子先跑一遍建立基线
    for seed in seeds:
        cov = ToggleCoverage(dut)
        execute_ops(dut, cov, seed["ops"])
        exec_count += 1
        if global_cov.merge_max(cov):
            corpus.append({"seed": seed, "ops": seed["ops"]})
        print(f"  [seed] {seed['name']}: bitmap={cov.bitmap_size()} "
              f"global={global_cov.bitmap_size()}")

    print(f"\n--- 变异循环（{args.iterations} 迭代）---")
    for it in range(args.iterations):
        if not corpus:
            break
        # 能量分配：随机选语料库条目（可加 COE power schedule）
        entry = rng.choice(corpus)
        new_ops, mut_type = mutate(entry, regmap, rng)
        cov = ToggleCoverage(dut)
        execute_ops(dut, cov, new_ops)
        exec_count += 1
        if global_cov.merge_max(cov):
            corpus.append({"seed": entry["seed"], "ops": new_ops,
                           "mut_type": mut_type, "iter": it})
            print(f"  [iter {it}] NEW COVERAGE +{cov.bitmap_size()} "
                  f"(mut={mut_type}) global={global_cov.bitmap_size()} "
                  f"corpus={len(corpus)}")
            # 新覆盖区域可能藏新候选——记录
            findings.append({"iter": it, "mut_type": mut_type,
                             "ops": [(o[0], hex(o[1]) if len(o) > 1 else 0,
                                      hex(o[2]) if len(o) > 2 else 0)
                                     for o in new_ops],
                             "new_cov": cov.bitmap_size()})
        if it % 10 == 9:
            print(f"  [iter {it}] global_cov={global_cov.bitmap_size()} "
                  f"corpus={len(corpus)}")

    # 保存结果
    out = os.path.join(PF, "fuzz", f"closed_loop_{args.module}.json")
    json.dump({"module": args.module, "iterations": args.iterations,
               "exec_count": exec_count,
               "final_coverage": global_cov.bitmap_size(),
               "corpus_size": len(corpus),
               "new_coverage_events": findings},
              open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\n=== 汇总 ===")
    print(f"执行: {exec_count} 次, 最终覆盖: {global_cov.bitmap_size()} 值状态, "
          f"语料库: {len(corpus)}, 新覆盖事件: {len(findings)}")
    print(f"输出: {out}")


if __name__ == "__main__":
    main()
