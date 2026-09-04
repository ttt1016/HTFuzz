#!/usr/bin/env python3
"""
确定性激励重放 + 全量观测轨迹落盘（差分比对用）

用法: dut_trace.py <dut_dir> <module> <regmap> <out.json> [seed]

对给定 DUT 执行一段完全由 seed 决定的确定性激励（写/读/步进/复位/擦除探测），
每个动作后快照全部白盒信号，落盘 JSON。同一 seed 在 CTF/fresh 两侧
产生逐字节相同的动作序列 —— 差分比对的输入。

激励四相（覆盖六步流水线中 oracle 扫描的典型行为）:
  A 遍历寄存器: 逐个写(伪随机值)+回读
  B 随机游走:   write/read/step 混合
  C 擦除探测:   敏感寄存器写标记 → 混合操作 → 快照（O-A 差分版）
  D 复位后态:   复位 + 寄存器回读
"""
import ctypes, json, os, random, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from discover_engine import DUT  # noqa: E402

PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")

# 触发类寄存器名片段 → 探测写入值（相位 C 用，generic 剧本）
TRIGGER_HINTS = [
    ("cmd", 0x1), ("cmd", 0x2), ("control", 0x1), ("control", 0x2),
    ("wipe", 0x1), ("trigger", 0x1), ("start", 0x1), ("execute", 0x1),
    ("operation", 0x1), ("refresh", 0x1), ("sha_en", 0x0),
]


def run(dut_dir, module, regmap_path, out_path, seed=0):
    rng = random.Random(seed)
    regs = []
    if regmap_path and os.path.exists(regmap_path):
        d = json.load(open(regmap_path))
        if isinstance(d, dict):            # dict: name -> offset
            regs = [(k, v) for k, v in d.items()]
        else:                              # list of {name, offset}
            for e in d:
                regs.append((e["name"], e["offset"]))
    regs.sort(key=lambda x: x[1])

    os.chdir(PF)
    dut = DUT(dut_dir, module)
    # 差分可比性: 只采样两侧都绑定的白盒信号（fresh 侧未绑定 → pf_sig_bound=0）
    bound = None
    try:
        a = dut.api
        a.pf_sig_bound.restype = ctypes.c_int
        a.pf_sig_bound.argtypes = [ctypes.c_int]
        bound = set()
        for i, nm in enumerate(dut.sigs):
            if a.pf_sig_bound(i):
                bound.add(nm)
    except Exception:
        bound = None  # 无 pf_sig_bound 的旧 harness: 全采样
    trace = []
    idx = 0

    def snap(phase, kind, addr=None, data=None, readback=None, error=None):
        nonlocal idx
        trace.append({
            "idx": idx, "phase": phase, "kind": kind,
            "addr": addr, "data": data,
            "readback": readback, "error": error,
            "cycle": int(dut.api.pf_get_cycle()) if hasattr(dut.api, "pf_get_cycle") else 0,
            "sigs": {k: v for k, v in dut.snapshot().items()
                     if bound is None or k in bound},
        })
        idx += 1

    print(f"[trace] phase A start", flush=True)
    # 相位 A: 遍历寄存器
    for name, off in regs:
        v = rng.getrandbits(32)
        dut.write(off, v)
        rb = dut.read(off)
        snap("A", "write_read", addr=off, data=v, readback=rb)
    print(f"[trace] phase A done, phase B start", flush=True)
    # 相位 B: 随机游走
    for _ in range(60):
        r = rng.random()
        if r < 0.45 and regs:
            off = rng.choice(regs)[1]
            v = rng.getrandbits(32)
            dut.write(off, v)
            rb = dut.read(off)
            snap("B", "write_read", addr=off, data=v, readback=rb)
        elif r < 0.8 and regs:
            off = rng.choice(regs)[1]
            rb = dut.read(off)
            snap("B", "read", addr=off, readback=rb)
        else:
            n = rng.randint(1, 16)
            dut.step(n)
            snap("B", "step", data=n)
    print("[trace] phase B done, phase C start", flush=True)
    # 相位 C: 擦除/触发探测 —— 敏感寄存器写标记 → 触发类操作 → 快照
    sens = [(n, o) for n, o in regs
            if any(k in n.lower() for k in ("key", "secret", "seed", "digest", "wdata", "msg"))]
    for name, off in sens[:8]:
        marker = 0xA5A5A5A5
        dut.write(off, marker)
        for th, tv in TRIGGER_HINTS:
            hit = [(n, o) for n, o in regs if th in n.lower()]
            for hn, ho in hit[:2]:
                dut.write(ho, tv)
                dut.step(20)
        rb = dut.read(off)
        snap("C", "marker_probe", addr=off, data=marker, readback=rb)
        # 混合扰动后再看
        for _ in range(3):
            off2 = rng.choice(regs)[1] if regs else off
            v2 = rng.getrandbits(32)
            dut.write(off2, v2)
        dut.step(30)
        rb2 = dut.read(off)
        snap("C", "marker_after", addr=off, readback=rb2)
    print("[trace] phase C done, phase D start", flush=True)
    # 相位 D: 复位后态
    dut.reset()
    snap("D", "reset")
    for name, off in regs[:16]:
        rb = dut.read(off)
        snap("D", "read", addr=off, readback=rb)

    json.dump({"module": module, "seed": seed, "n_actions": len(trace),
               "trace": trace}, open(out_path, "w"))
    print(f"[trace] {module} seed={seed}: {len(trace)} actions -> {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("用法: dut_trace.py <dut_dir> <module> <regmap> <out.json> [seed]")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4],
        int(sys.argv[5]) if len(sys.argv) > 5 else 0)
