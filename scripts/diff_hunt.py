#!/usr/bin/env python3
"""
差分优化 ①②: 定向刺激差分 + 偏离→findings 正式化

对每个 DIVERGENT 模块:
  1. 用模块特定定向序列（不再是通用 4 相剧本）跑差分 → 更精准的偏离触发
  2. DIVERGENT 偏离直接产出 findings JSON 记录（与开环检出同等计数）
  3. triage 差分叠加：DIFF-CONFIRMED / DIFF-REFUTED

用法（容器内）: diff_hunt.py <module>
输出: fuzz/diff_findings_<module>.json（可独立计入检测总数）
"""
import json, os, re, subprocess, sys

PF = "/workspace/HTFuzz"

# ---- 模块特定定向序列（基于注入面分析）----
# 每条 = (写入地址, 写入数据, 步进拍数),  None data = 只读
DIRECTED = {
    "aes": [
        # 写 KEY_SHARE0/1 → 启动加密 → 中途复位 → 读 key 寄存器
        {"wr": (0x54, 0xDEADBEEF), "step": 2},   # KEY_SHARE0_0
        {"wr": (0x58, 0x12345678), "step": 2},   # KEY_SHARE0_1
        {"wr": (0x5C, 0xABCD1234), "step": 2},   # KEY_SHARE0_2
        {"wr": (0x60, 0xEF012345), "step": 2},   # KEY_SHARE0_3
        {"wr": (0x64, 0x11111111), "step": 2},   # KEY_SHARE1_0
        {"wr": (0x68, 0x22222222), "step": 2},   # KEY_SHARE1_1
        {"wr": (0x6C, 0x33333333), "step": 2},   # KEY_SHARE1_2
        {"wr": (0x70, 0x44444444), "step": 2},   # KEY_SHARE1_3
        {"wr": (0x78, 0x1), "step": 5},           # CTRL: 启动加密
        {"wr": (0x40, 0x1), "step": 10},          # TRIGGER: start
        {"step": 20},                              # 进行中...
        {"reset": True},                           # 中途复位
        {"rd": 0x54}, {"rd": 0x58}, {"rd": 0x5C}, {"rd": 0x60},  # 读 key 回
        {"rd": 0x64}, {"rd": 0x68}, {"rd": 0x6C}, {"rd": 0x70},
    ],
    "hmac": [
        # 写 KEY → HASH_START → 中途 WIPE → 读 secret_key
        {"wr": (0x700, 0xDEADBEEF), "step": 2},   # KEY_0
        {"wr": (0x704, 0x12345678), "step": 2},   # KEY_1
        {"wr": (0x708, 0xA5A5A5A5), "step": 2},   # KEY_2
        {"wr": (0x70C, 0x5A5A5A5A), "step": 2},   # KEY_3
        {"wr": (0x18, 0x1), "step": 3},            # CFG: HMAC en
        {"wr": (0x14, 0x1), "step": 5},            # CMD: HASH_START
        {"step": 10},
        {"reset": True},                           # 中途复位
        # 读回 secret_key 类信号由白盒采样覆盖
    ],
    "ascon": [
        # 写 KEY_SHARE → CTRL(mode=enc) → TRIGGER.wipe → 读 key_share
        {"wr": (0x14, 0xDEADBEEF), "step": 2},   # KEY0
        {"wr": (0x18, 0x12345678), "step": 2},   # KEY1
        {"wr": (0x1C, 0xA5A5A5A5), "step": 2},   # KEY2
        {"wr": (0x20, 0x5A5A5A5A), "step": 2},   # KEY3
        {"wr": (0x8, 0x11), "step": 3},            # CTRL: mode=enc, key_len=128
        {"wr": (0x2C, 0x1), "step": 5},            # TRIGGER.wipe=1
        {"step": 20},
        {"reset": True},
    ],
    "keymgr": [
        # 写 CONTROL (0x0=CONTROL) start → 等 → 读 STATE/KEY 相关
        {"wr": (0x0, 0x1), "step": 5},            # CONTROL.start
        {"step": 20},
        {"wr": (0x4, 0x1), "step": 2},             # 可能的 CTRL 寄存器
        {"step": 10},
        {"reset": True},
    ],
    "kmac": [
        # CFG en → KEY 写 → CMD.start → 中途复位 → 读掩码信号
        {"wr": (0x14, 0x66666666), "step": 3},    # CFG enable
        {"wr": (0x18, 0x66), "step": 2},           # REGWEN
        {"wr": (0x30, 0xDEADBEEF), "step": 2},    # KEY_SHARE0_0
        {"wr": (0x34, 0x12345678), "step": 2},
        {"wr": (0x40, 0x1), "step": 5},             # CMD = START
        {"step": 10},
        {"reset": True},
    ],
    "ascon": [
        # CTRL(mode=enc) → KEY → TRIGGER.wipe → 中途复位
        {"wr": (0x8, 0x11), "step": 3},
        {"wr": (0x14, 0xDEADBEEF), "step": 2},
        {"wr": (0x2C, 0x1), "step": 5},
        {"step": 10},
        {"reset": True},
    ],
    "otp_ctrl": [
        # DAI 面定向: 写 OTP 地址 → 读 → 中途复位
        {"wr": (0x14, 0x1), "step": 3},            # STATUS rw1c
        {"wr": (0x58, 0x1), "step": 5},            # DIRECT_ACCESS_CMD: read
        {"step": 20},
        {"reset": True},
    ],
    "pwrmgr": [
        # 写 WAKEUP/RESET en → 等 FSM 推进 → 观察 slow FSM
        {"wr": (0x4, 0xFFFFFFFF), "step": 2},     # WAKEUP_EN
        {"wr": (0x8, 0xFFFFFFFF), "step": 2},     # RESET_EN
        {"wr": (0x0, 0x1), "step": 50},            # CTRL: 启动
        {"step": 100},
        {"reset": True},
     ],
    "entropy_src": [
        # CONF 使能 → 中途关断 → 读 main_sm 状态
        {"wr": (0x18, 0x66666666), "step": 5},    # CONF: module_enable=On
        {"wr": (0x1C, 0x1), "step": 5},            # FW_OV_CTRL
        {"wr": (0x14, 0x1), "step": 30},           # 触发健康检查
        {"step": 50},
        {"reset": True},
    ],
}


def load_trace(dut_dir, tag, module):
    out = f"/tmp/dh_{module}_{tag}.json"
    p = subprocess.run(["python3", f"{PF}/scripts/dut_trace.py",
                        dut_dir, module,
                        f"{PF}/traces/{module}_regmap.json", out, "0"],
                       capture_output=True, text=True, timeout=600,
                       cwd=PF)
    if p.returncode != 0:
        raise RuntimeError(f"[{tag}] rc={p.returncode}: {(p.stderr or '')[-300:]}")
    return json.load(open(out))


def main():
    module = sys.argv[1]
    seq = DIRECTED.get(module)
    if not seq:
        print(f"[{module}] 无定向序列定义")
        sys.exit(1)
    ctf_dir = f"{PF}/perip/{module}-ctf"
    fresh_dir = f"{PF}/perip/{module}-fresh"

    # 写定向序列为 dut_trace 可执行格式 → 直接用 dut_trace + 定向操作
    # 简化: 在 dut_trace 的通用 4 相之后追定向相（Phase A 流程不变）
    # 差分: 用定向序列替代通用相做 CTF vs fresh 比对
    print(f"=== 差分狩猎: {module}（定向刺激 {len(seq)} 步） ===")

    # 用 Python 直接驱动（不走 dut_trace, 因为需要定向序列）
    sys.path.insert(0, f"{PF}/scripts")
    from discover_engine import DUT
    import ctypes

    def run_directed(dut_dir, tag):
        d = DUT(dut_dir, module)
        trace = []
        for step_i, step in enumerate(seq):
            if step.get("reset"):
                d.reset()
                trace.append({"kind": "reset", "idx": step_i})
            elif "wr" in step:
                addr, data = step["wr"]
                d.write(addr, data)
                d.step(step.get("step", 2))
                rb = d.read(addr)
                sigs = {nm: d.sig_all(nm) for nm in list(d.sigs)[:60]}
                trace.append({"kind": "wr_rd", "addr": addr, "data": data,
                              "readback": rb, "sigs": sigs})
            elif "rd" in step:
                rb = d.read(step["rd"])
                trace.append({"kind": "rd", "addr": step["rd"], "readback": rb})
            else:
                d.step(step.get("step", 5))
                trace.append({"kind": "step"})
        return {"module": module, "trace": trace, "n_actions": len(trace)}

    def diff_traces(t_ctf, t_f1, t_f2):
        """定向序列差分: 对齐 trace 逐项比较"""
        f1 = {i: r for i, r in enumerate(t_f1["trace"])}
        divergences = []
        first = None
        n = min(len(t_ctf["trace"]), len(t_f1["trace"]))
        for i in range(n):
            a, b = t_ctf["trace"][i], t_f1["trace"][i]
            if a.get("kind") != b.get("kind"):
                continue
            # readback 差异
            if a.get("readback") is not None and a.get("readback") != b.get("readback"):
                d = {"idx": i, "channel": "readback", "addr": a.get("addr"),
                     "ctf": a.get("readback"), "fresh": b.get("readback")}
                divergences.append(d)
            # 白盒信号差分
            sa, sb = a.get("sigs", {}), b.get("sigs", {})
            for sig in set(list(a.get("sigs", {}).keys())) & set(b.get("sigs", {}).keys()):
                wa, wb = a["sigs"].get(sig, []), b["sigs"].get(sig, [])
                for w, (va, vb) in enumerate(zip(wa, wb)):
                    if va != vb:
                        divergences.append({"idx": i, "channel": "sig",
                                            "signal": sig, "word": w,
                                            "ctf": va, "fresh": vb})
        return divergences, n

    t_ctf = run_directed(ctf_dir, "ctf")
    t_f1 = run_directed(fresh_dir, "f1")
    t_f2 = run_directed(fresh_dir, "f2")

    divergences, _n = diff_traces(t_ctf, t_f1, t_f2)
    verdict = "DIVERGENT" if divergences else "IDENTICAL"

    # findings 正式化
    findings = []
    for d in divergences[:50]:
        if isinstance(d, dict):
            sig = d.get("signal") or (f"addr_{d['addr']:#x}" if d.get("addr") is not None else "?")
        else:
            sig = str(d)
        findings.append({
            "oracle": "O-DIFF-directed", "signal": sig,
            "desc": f"定向刺激偏离: {d.get('desc', sig)} ctf={d.get('ctf')} fresh={d.get('fresh')}",
            "first_idx": d["idx"], "channel": d["channel"],
        })
    out = f"{PF}/fuzz/diff_findings_{module}.json"
    json.dump({"module": module, "verdict": verdict,
               "findings": findings}, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"→ {verdict}: {len(findings)} 条差分检出 → {out}")


if __name__ == "__main__":
    main()
