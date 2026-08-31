#!/usr/bin/env python3
"""
发现引擎 v2.5 —— 变异序列驱动的深度盲测

= discover_engine（O-A/B/C oracle）+ opseq_fuzzer（7 算子序列变异）

工作流:
  1. 加载 DUT + regmap
  2. 生成 N 个变异操作序列（7 算子）
  3. 每个序列跑三类 oracle 检查:
     - O-A 残留: 序列中含写敏感寄存器 → 结束后扫敏感信号
     - O-B 确定性: 同序列跑两遍 → 掩码/熵信号应不同
     - O-C 等价类: 序列与其重排版 → 控制终态应一致
  4. 命中 → 记录（序列 + oracle + 证据）
"""
import ctypes, os, sys, json, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from opseq_fuzzer import OpSeqFuzzer

# 复用 discover_engine 的 DUT 类和分类
import importlib.util
spec = importlib.util.spec_from_file_location("de", os.path.join(os.path.dirname(os.path.abspath(__file__)), "discover_engine.py"))
de = importlib.util.module_from_spec(spec)
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "discover_engine.py")).read()
src = src.replace("if __name__ == \"__main__\":\n    main()", "")
exec(compile(src, "discover_engine.py", "exec"), de.__dict__)

def run_seq(dut, seq, base):
    for e in seq:
        op, addr, data, mask, wait = e
        if op == "W":
            dut.write(base + addr, data, mask)
        elif op == "R":
            dut.read(base + addr)
        if wait:
            dut.step(wait)

def main():
    if len(sys.argv) < 3:
        print("用法: discover_fuzz.py <dut_dir> <module> [n_seqs] [seed]")
        sys.exit(1)
    dut_dir, module = sys.argv[1], sys.argv[2]
    n_seqs = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 0xC0FFEE

    # regmap 先读（DUT 会 chdir）
    regmap = None
    for cand in [f"/workspace/pickerfuzz/traces/{module}_regmap.json"]:
        if os.path.exists(cand):
            regmap = json.load(open(cand))
            break
    norm = {}
    if isinstance(regmap, list):
        for e in regmap:
            if isinstance(e, dict) and e.get("name") is not None and e.get("offset") is not None:
                off = e["offset"]
                norm[e["name"]] = int(off, 0) if isinstance(off, str) else off
    # base 地址: 从 DUT 名推断（hmac=0x41110000 aes=0x41100000）
    base_map = {"hmac": 0x41110000, "aes": 0x41100000, "kmac": 0x41110000,
                "keymgr": 0x41130000, "lc_ctrl": 0x41140000, "uart": 0x40000000}
    base = base_map.get(module, 0x41110000)

    print(f"=== 发现引擎 v2.5（变异序列深度盲测）: {module} ===")
    print(f"寄存器 {len(norm)} 个, 变异序列 {n_seqs} 条, seed={hex(seed)}")

    dut = de.DUT(dut_dir, module)
    sens, ctrl, other = de.classify(dut.sigs)
    mask_sigs = [nm for nm in dut.sigs
                 if any(k in nm.lower() for k in ["mask", "entropy", "rnd", "lfsr", "prng", "rand"])]
    print(f"敏感 {len(sens)}  控制 {len(ctrl)}  掩码/熵 {len(mask_sigs)}")

    fz = OpSeqFuzzer(norm, base, seed)
    seqs = fz.fuzz(n_seqs=n_seqs, base_len=12)

    findings = []
    for si, (mut_name, seq) in enumerate(seqs):
        # --- O-A: 跑序列后扫残留 ---
        dut.reset()
        dut.step(5)
        run_seq(dut, seq, base)
        dut.step(30)
        snap = dut.snapshot(sens)
        # 收集序列写入过的非平凡数据值
        written_vals = set()
        for e in seq:
            if e[0] == "W" and e[2] not in (0, 0xFFFFFFFF):
                written_vals.add(e[2])
                written_vals.add(e[2] & 0xFFFF0000)
        for snm in sens:
            words = snap.get(snm, [])
            nwords = len(words)
            for w, v in enumerate(words):
                if v in (0, 0xFFFFFFFF):
                    continue
                # 1bit 信号: 0x1 与任意写 0x1 巧合概率高 → 要求写入值集合里有"特征值"
                # 多字信号: 精确或高 16 位匹配
                if nwords <= 1:
                    # 1bit/小信号: 只匹配精确值且写入值非平凡（非 0x1）
                    hit = any(v == x and x not in (0x1, 0x2, 0x4, 0x8) for x in written_vals)
                else:
                    hit = (v in written_vals) or any((v & 0xFFFF0000) == (x & 0xFFFF0000) for x in written_vals)
                if hit:
                    findings.append({
                        "oracle": "O-A-residual", "mut": mut_name, "seq_id": si,
                        "signal": snm, "word": w, "value": hex(v),
                        "desc": "序列[%s]后 %s[%d] 残留写入标记" % (mut_name, snm, w),
                    })
                    break
        # --- O-B: 同序列两遍，掩码信号应不同 ---
        if mask_sigs:
            runs = []
            for _ in range(2):
                dut.reset()
                dut.step(5)
                run_seq(dut, seq, base)
                dut.step(50)
                runs.append({nm: dut.sig_all(nm) for nm in mask_sigs})
            for nm in mask_sigs:
                if runs[0][nm] and runs[0][nm] == runs[1][nm] and any(v != 0 for v in runs[0][nm]):
                    findings.append({
                        "oracle": "O-B-determinism", "mut": mut_name, "seq_id": si,
                        "signal": nm, "value": " ".join(hex(x) for x in runs[0][nm][:4]),
                        "desc": f"序列[{mut_name}]两次执行 {nm} 逐位相同（无随机性）",
                    })
        # --- O-C: 序列 vs 其重排版，控制终态应一致 ---
        if ctrl:
            reordered = OpSeqFuzzer.mut_reorder(fz, seq)
            finals = []
            for s2 in (seq, reordered):
                dut.reset()
                dut.step(5)
                run_seq(dut, s2, base)
                dut.step(30)
                finals.append(dut.snapshot(ctrl[:4]))
            for cnm in ctrl[:4]:
                if finals[0].get(cnm) != finals[1].get(cnm):
                    findings.append({
                        "oracle": "O-C-equivclass", "mut": mut_name, "seq_id": si,
                        "signal": cnm,
                        "desc": f"序列[{mut_name}] vs 重排版: {cnm} 终态不同",
                    })

    # 去重（同 oracle+signal+desc）
    seen = set()
    uniq = []
    for f in findings:
        k = (f["oracle"], f["signal"], f["desc"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    out = f"/workspace/pickerfuzz/fuzz/discoverfuzz_{module}.json"
    json.dump({"module": module, "n_seqs": n_seqs, "findings": uniq}, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\n=== 结果: {len(findings)} 命中 → 去重 {len(uniq)} 条 → {out} ===")
    from collections import Counter
    c = Counter(f["oracle"] for f in uniq)
    print("按 oracle:", dict(c))
    for f in uniq[:12]:
        print("  [%s][%s] %s %s" % (f["oracle"], f.get("mut", ""), f.get("signal", ""), f.get("desc", "")[:60]))

if __name__ == "__main__":
    main()
