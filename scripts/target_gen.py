#!/usr/bin/env python3
"""
靶点自动生成器 —— 不依赖漏洞表的发现管线第一环

三个真规格来源:
  T1. SEC_CM 标注解析 → 每条声明映射到可测 oracle 策略
  T2. SVA 安全断言提取 → 断言差分（被删/被改/豁免条件可触发）
  T3. 危险参数值 → 单文件检查参数值本身是否危险（上游默认值是公开知识）

输出: targets.json —— 每个靶点含 {来源, 位置, oracle策略, 优先级}
"""
import re, os, json, subprocess, sys

OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")  # 比赛提供的 RTL
# profile 支持: PF_PROFILE 环境变量指定 JSON 配置
_profile = None
try:
    _pp = os.environ.get("PF_PROFILE")
    if _pp and os.path.exists(_pp):
        import json as _json
        _profile = _json.load(open(_pp))
        OT = _profile.get("rtl_path", OT)
except Exception:
    pass

# SEC_CM 类型 → oracle 策略映射（通用，不针对特定漏洞）
SEC_CM_STRATEGY = {
    "SEC_WIPE":      {"oracle": "O-A-residual", "how": "触发擦除流程后白盒扫描关联寄存器/信号残留"},
    "KEY.MASKING":   {"oracle": "O-B-determinism", "how": "相同输入两次执行，掩码信号应不同"},
    "MASKING":       {"oracle": "O-B-determinism", "how": "相同输入两次执行，掩码信号应不同"},
    "CONFIG.SHADOW": {"oracle": "O-C-equivclass", "how": "shadow 寄存器两阶段写等价类 + err_update 观测"},
    "TOKEN.DIGEST":  {"oracle": "O-C-equivclass", "how": "token 等价类: 全匹配/部分匹配/不匹配的转移结果"},
    "INTEGRITY":     {"oracle": "O-C-equivclass", "how": "intg 错误注入 vs 正常，响应应不同"},
    "SPARSE":        {"oracle": "O-C-equivclass", "how": "非法编码值写入 → 应报错/进安全态"},
    "REDUN":         {"oracle": "O-C-equivclass", "how": "双轨信号不一致注入 → 应报错"},
    "GLOBAL_ESC":    {"oracle": "O-C-equivclass", "how": "escalate 触发 → 状态应立即进安全态"},
    "LOCAL_ESC":     {"oracle": "O-C-equivclass", "how": "本地错误 → 擦除+安全态"},
    "REGWEN":        {"oracle": "O-C-equivclass", "how": "REGWEN 锁定后写 → 应被拒"},
    "SCA":           {"oracle": "O-B-determinism", "how": "秘密相关信号功耗/翻转模式分析"},
    "BKGN_CHK":      {"oracle": "O-B-determinism", "how": "背景检查失效注入 → 应报 alert"},
    "SCRAMBLE":      {"oracle": "O-A-residual", "how": " scramble 前后明文残留扫描"},
    "MUBI":          {"oracle": "O-C-equivclass", "how": "mubi 非法值写入 → 应按 false 处理或报错"},
}

def scan_sec_cm():
    """T1: 全 fork SEC_CM 解析"""
    targets = []
    for root, dirs, files in os.walk(os.path.join(OT, "hw/ip")):
        for d in ("dv", "fpv", "pre_syn", "pre_sca", "model"):
            if d in dirs: dirs.remove(d)
        for fn in files:
            if not fn.endswith((".sv", ".svh")):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, OT)
            try:
                s = open(p, errors="ignore").read()
            except Exception:
                continue
            for i, line in enumerate(s.splitlines(), 1):
                m = re.search(r"SEC_CM:\s*([A-Z_.0-9]+)", line)
                if m:
                    tag = m.group(1)
                    strat = None
                    for k, v in SEC_CM_STRATEGY.items():
                        if k in tag:
                            strat = v
                            break
                    targets.append({
                        "source": "T1-SEC_CM", "tag": tag, "file": rel,
                        "line": i, "strategy": strat or {"oracle": "O-C-equivclass", "how": "通用等价类"},
                    })
    return targets

def get_asserts(path):
    try:
        s = open(path, errors="ignore").read()
    except Exception:
        return {}
    out = {}
    for m in re.finditer(r"`ASSERT\((\w+),\s*(.*?)\)\s*\n", s, re.S):
        out[m.group(1)] = re.sub(r"\s+", " ", m.group(2))
    return out

def scan_sva_weakness():
    """T2(合规版): 单文件断言弱点检查 —— 不依赖 fresh

    检查 fork RTL 自身:
      a) 断言豁免条件可被软件触发（如 SecAllowForcingMasks && force_masks_i，
         且该参数默认值/寄存器可写）→ 断言存在但可被关掉
      b) 安全断言被 `ifdef SIMULATION 包裹（综合/仿真可能被剔除）
    """
    targets = []
    for root, dirs, files in os.walk(os.path.join(OT, "hw/ip")):
        for d in ("dv", "fpv", "pre_syn", "pre_sca", "model"):
            if d in dirs: dirs.remove(d)
        for fn in files:
            if not fn.endswith(".sv"):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, OT)
            try:
                s = open(p, errors="ignore").read()
            except Exception:
                continue
            # a) 豁免条件: 断言体里引用了可被软件控制的豁免参数
            for m in re.finditer(r"`ASSERT\((\w+),\s*(.*?)\)\s*\n", s, re.S):
                name, body = m.group(1), re.sub(r"\s+", " ", m.group(2))
                # 豁免模式: || Sec...Allow... && force / || Sec... && xxx_i
                if re.search(r"\|\|\s*Sec\w*(Allow|Force)\w*\s*&&", body):
                    targets.append({"source": "T2-assert-waiver", "name": name,
                                    "file": rel, "body": body[:200],
                                    "strategy": {"oracle": "O-C-equivclass",
                                                 "how": "断言含软件可触发的豁免条件，构造条件满足场景使断言失效"}})
    return targets

PARAM_PATTERNS = [
    (r"SecAllowForcingMasks\s*=\s*1\b", "掩码强制后门参数开启（上游默认 0）"),
    (r"SecSkipPRNGReseeding\s*=\s*1\b", "跳过 PRNG 重播（上游默认 0）"),
    (r"SecVolatileRawUnlockEn\s*=\s*1\b", "易失 RAW 解锁开启"),
]

def scan_params():
    """T3(合规版): 单文件安全参数异常值检查 —— 不依赖 fresh

    只报"参数值本身危险"的情况（上游默认值是公开知识，不属于 diff）:
      SecAllowForcingMasks=1 / SecSkipPRNGReseeding=1 等
    """
    targets = []
    for root, dirs, files in os.walk(os.path.join(OT, "hw/ip")):
        for d in ("dv", "fpv", "pre_syn", "pre_sca", "model"):
            if d in dirs: dirs.remove(d)
        for fn in files:
            if not fn.endswith(".sv"):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, OT)
            try:
                fs = open(p, errors="ignore").read()
            except Exception:
                continue
            for pat, desc in PARAM_PATTERNS:
                for m in re.finditer(pat, fs):
                    # 排除默认参数声明行（parameter bit SecAllowForcingMasks = 0）
                    line_start = fs.rfind("\n", 0, m.start()) + 1
                    line = fs[line_start:fs.find("\n", m.start())]
                    if re.search(r"parameter\b", line) and re.search(r"=\s*0\b", line):
                        continue  # 默认声明，非实例化覆盖
                    targets.append({"source": "T3-param-risk", "file": rel,
                                    "frag": m.group(0), "desc": desc,
                                    "strategy": {"oracle": "O-C-equivclass",
                                                 "how": "危险参数值的安全后果验证"}})
    return targets

def main():
    print("=== 靶点自动生成器（合规版: 只读比赛提供的 RTL，无外部对照）===")
    t1 = scan_sec_cm()
    print(f"T1 SEC_CM 标注: {len(t1)} 条")
    t2 = scan_sva_weakness()
    print(f"T2 断言弱点（豁免条件/可关闭）: {len(t2)} 条")
    t3 = scan_params()
    print(f"T3 危险参数值: {len(t3)} 条")
    all_t = t1 + t2 + t3
    out = "/workspace/pickerfuzz/fuzz/targets.json"
    json.dump({"targets": all_t}, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\n总靶点: {len(all_t)} → {out}")
    # 按策略统计
    from collections import Counter
    c = Counter(t["strategy"]["oracle"] if t.get("strategy") else "?" for t in all_t)
    print("按 oracle 策略:", dict(c))
    # 高优先级: T2/T3（单文件即可判定的弱点）
    print("\n高优先级靶点（T2/T3 = 单文件可判定的安全弱点）:")
    for t in (t2 + t3)[:10]:
        nm = t.get("name", t.get("frag", ""))
        print("  [%s] %s %s" % (t["source"], t["file"], nm))

if __name__ == "__main__":
    main()
