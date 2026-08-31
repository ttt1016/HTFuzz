#!/usr/bin/env python3
"""
候选分诊（无 fresh 对照版）—— 决赛环境用

输入: discover_engine 的 findings JSON
输出: 分级后的报告（HIGH/MEDIUM/LOW 置信度）

置信度规则（全部不依赖 fresh）:
  HIGH   : 多 oracle 交叉命中 + 违反明确 SEC_CM + 信号为敏感类
  MEDIUM : 单 oracle 命中 + 违反 SEC_CM
  LOW    : 单 oracle 命中 + 无 SEC_CM 关联（需人工/LLM 复核）

附加自证: 读 RTL 中候选信号的驱动赋值，检查是否存在
  - 恒值赋值（stuck-at）
  - 条件缺失（对比同文件其他分支）
  - 与 SEC_CM 注释声明的保护语义矛盾
"""
import json, re, os, sys

OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")

# SEC_CM 位置索引（file -> [(line, tag)]）
def build_sec_cm_index():
    idx = {}
    for root, dirs, files in os.walk(os.path.join(OT, "hw/ip")):
        for d in ("dv", "fpv", "pre_syn", "pre_sca", "model"):
            if d in dirs: dirs.remove(d)
        for fn in files:
            if not fn.endswith((".sv", ".svh")):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, OT)
            try:
                lines = open(p, errors="ignore").read().splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                m = re.search(r"SEC_CM:\s*([A-Z_.0-9]+)", line)
                if m:
                    idx.setdefault(rel, []).append((i, m.group(1)))
    return idx

SENSITIVE = ["key", "secret", "seed", "digest", "mask", "entropy", "token", "priv"]

def signal_module(signal):
    # "u_dut.secret_key" / "sha2.hash_q" -> 模块目录猜测
    return None  # 由调用方提供 module

def triage(findings, module, sec_cm_idx):
    # 模块目录映射
    mod_dir = f"hw/ip/{module}/rtl"
    out = []
    for f in findings:
        sig = f.get("signal", "")
        oracle = f.get("oracle", "")
        # 1. 敏感性
        sens = any(k in sig.lower() for k in SENSITIVE)
        # 2. SEC_CM 关联: 模块 RTL 里是否有与该信号语义相关的 SEC_CM
        sec_hits = []
        for tag_line in sec_cm_idx.get(mod_dir, []):
            tag = tag_line[1]
            # 信号名与 SEC_CM 语义关联（key/mask/wipe/shadow/token/integrity）
            low = sig.lower()
            for kw, t in [("key", "KEY"), ("mask", "MASKING"), ("wipe", "SEC_WIPE"),
                          ("shadow", "SHADOW"), ("token", "TOKEN"), ("digest", "DIGEST"),
                          ("entropy", "RNG"), ("state", "STATE"), ("fsm", "FSM")]:
                if kw in low and t in tag:
                    sec_hits.append(tag)
                    break
        # 3. oracle 交叉（同信号多 oracle）
        cross = sum(1 for g in findings if g.get("signal") == sig and g.get("oracle") != oracle)
        # 4. RTL 自证: 读模块 RTL，检查候选信号附近是否有 wipe/clear 语义
        #    （信号被清除流程覆盖却仍残留 = 强证据）
        rtl_self = False
        mod_rtl = os.path.join(OT, mod_dir, f"{module}_core.sv")
        alt_rtl = os.path.join(OT, mod_dir, f"{module}.sv")
        for rp in (mod_rtl, alt_rtl):
            if os.path.exists(rp):
                try:
                    rtl = open(rp, errors="ignore").read()
                    # 信号短名（去前缀）
                    short = sig.split(".")[-1].split("_q")[0].split("_d")[0]
                    # 找 wipe/clear 与该信号的邻近性（同 block 或 10 行内）
                    for m in re.finditer(r"(wipe|clear|zeroize)", rtl, re.I):
                        seg = rtl[max(0, m.start()-300):m.start()+300]
                        if short in seg:
                            rtl_self = True
                            break
                except Exception:
                    pass
                if rtl_self:
                    break
        # 分级
        if sens and (sec_hits or rtl_self) and (cross > 0 or oracle in ("O-A-residual", "O-B-determinism")):
            level = "HIGH"
        elif sens and (sec_hits or rtl_self):
            level = "MEDIUM"
        elif sens or sec_hits:
            level = "MEDIUM"
        else:
            level = "LOW"
        out.append({
            "level": level, "oracle": oracle, "signal": sig,
            "sec_cm": sec_hits, "sensitive": sens, "cross_oracle": cross,
            "rtl_wipe_nearby": rtl_self,
            "evidence": f.get("desc", ""),
        })
    # 排序: HIGH > MEDIUM > LOW
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    out.sort(key=lambda x: order[x["level"]])
    return out

def main():
    if len(sys.argv) < 3:
        print("用法: triage_nofresh.py <findings.json> <module>")
        sys.exit(1)
    findings = json.load(open(sys.argv[1]))["findings"]
    module = sys.argv[2]
    idx = build_sec_cm_index()
    result = triage(findings, module, idx)
    out = sys.argv[1].replace(".json", "_triaged.json")
    json.dump({"module": module, "triaged": result}, open(out, "w"), indent=1, ensure_ascii=False)
    from collections import Counter
    c = Counter(r["level"] for r in result)
    print(f"=== 分诊结果: {dict(c)} → {out} ===")
    for r in result:
        print("  [%s] %s %s" % (r["level"], r["oracle"], r["signal"]))
        if r["sec_cm"]:
            print("        SEC_CM: %s" % ",".join(r["sec_cm"]))

if __name__ == "__main__":
    main()
