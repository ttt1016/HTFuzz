#!/usr/bin/env python3
"""
LLM 分诊器 —— 把 fuzzing 候选喂给 LLM 做 RTL 语义确认

模式:
  mock : 无 API key 时的规则打分（信号名语义 + SEC_CM 关联 + oracle 类型加权）
  api  : 调用 OpenAI 兼容 API（PF_LLM_BASE/PF_LLM_KEY/PF_LLM_MODEL 环境变量）

输入: findings JSON（discover_engine / discover_fuzz 输出）
输出: 每条候选附加 llm_verdict 字段:
  {
    "verdict": "likely-bug" | "needs-review" | "likely-safe",
    "reason": "...",
    "score": 0-100
  }

用法:
  python3 llm_triage.py fuzz/discover_hmac.json hmac           # mock 模式
  PF_LLM_BASE=... PF_LLM_KEY=... python3 llm_triage.py ...     # api 模式
"""
import json, os, re, sys, hashlib

OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")
CACHE_FILE = "/workspace/pickerfuzz/fuzz/llm_cache.json"

# ---------------------------------------------------------------------------
# RTL 上下文提取: 找到候选信号在 RTL 里的驱动赋值
# ---------------------------------------------------------------------------
def find_signal_rtl(signal_name, module):
    """在比赛 RTL 里找信号定义/赋值，返回 (file, snippet)"""
    # 信号名: u_dut.secret_key / u_core.main_sm_state_raw / sha2.hash_q
    # 提取最内层信号名
    parts = signal_name.replace("u_dut.", "").replace("u_core.", "").split(".")
    sig = parts[-1]
    # 去掉 _raw/_d 后缀变体
    candidates = {sig, sig.replace("_raw", ""), sig.replace("_d", "")}
    hits = []
    ip_dir = os.path.join(OT, "hw/ip", module)
    if not os.path.isdir(ip_dir):
        return None
    for root, dirs, files in os.walk(ip_dir):
        for d in ("dv", "fpv", "pre_syn", "pre_sca", "model"):
            if d in dirs:
                dirs.remove(d)
        for fn in files:
            if not fn.endswith((".sv", ".svh")):
                continue
            path = os.path.join(root, fn)
            try:
                lines = open(path, errors="ignore").read().split("\n")
            except Exception:
                continue
            for i, ln in enumerate(lines):
                for c in candidates:
                    if re.search(r"\b%s\b" % re.escape(c), ln):
                        hits.append((path, i + 1, ln.strip()))
                        break
                if len(hits) >= 6:
                    break
            if len(hits) >= 6:
                break
    if not hits:
        return None
    # 取第一个赋值行上下文
    path, lineno, line = hits[0]
    try:
        all_lines = open(path, errors="ignore").read().split("\n")
        ctx = "\n".join(all_lines[max(0, lineno - 4):lineno + 4])
        return {"file": path.replace(OT + "/", ""), "line": lineno, "context": ctx}
    except Exception:
        return None

def find_sec_cm(signal_name, module):
    """找信号所在文件附近的 SEC_CM 注释"""
    parts = signal_name.replace("u_dut.", "").replace("u_core.", "").split(".")
    sig = parts[-1].replace("_raw", "").replace("_d", "")
    ip_dir = os.path.join(OT, "hw/ip", module)
    if not os.path.isdir(ip_dir):
        return []
    tags = []
    for root, dirs, files in os.walk(ip_dir):
        for d in ("dv", "fpv"):
            if d in dirs:
                dirs.remove(d)
        for fn in files:
            if not fn.endswith(".sv"):
                continue
            path = os.path.join(root, fn)
            try:
                content = open(path, errors="ignore").read()
            except Exception:
                continue
            if sig not in content:
                continue
            for m in re.finditer(r"SEC_CM:\s*([A-Z_.0-9]+)", content):
                tags.append(m.group(1))
    return list(set(tags))[:5]

# ---------------------------------------------------------------------------
# Mock 打分（无 API 时的规则引擎）
# ---------------------------------------------------------------------------
SENSITIVE_WORDS = ["key", "secret", "seed", "mask", "entropy", "digest", "token", "priv"]
ORACLE_WEIGHT = {
    "O-A-residual": 40,     # 残留是强信号
    "O-B-determinism": 35,  # 掩码静态是强信号
    "O-C-equivclass": 30,
    "O-D-fsm": 15,          # FSM 卡死弱信号（易误报）
    "O-E-fifo": 25,
}

def mock_verdict(finding, module):
    score = 0
    reasons = []
    sig = finding.get("signal", "")
    oracle = finding.get("oracle", "")
    # 1) oracle 类型基础分
    score += ORACLE_WEIGHT.get(oracle, 10)
    reasons.append(f"oracle {oracle} 基础分 {ORACLE_WEIGHT.get(oracle, 10)}")
    # 2) 敏感信号名
    low = sig.lower()
    if any(w in low for w in SENSITIVE_WORDS):
        score += 25
        reasons.append("信号名含敏感关键词 +25")
    # 3) SEC_CM 关联
    tags = find_sec_cm(sig, module)
    if tags:
        score += 20
        reasons.append(f"SEC_CM 关联 {tags[:2]} +20")
    # 4) RTL 上下文自证: 恒值赋值/可疑模式
    rtl = find_signal_rtl(sig, module)
    if rtl:
        ctx = rtl["context"]
        if re.search(r"%s\s*(<=|=)\s*['{]?[01b'hxXZ]+[,}]" % re.escape(sig.split(".")[-1].replace("_raw", "")), ctx):
            score += 15
            reasons.append("RTL 中存在常量赋值模式 +15")
        if "static_mask" in ctx or "'1" in ctx:
            score += 10
            reasons.append("RTL 中存在静态常量替代随机 +10")
    # 5) 多 trial 重复命中
    if finding.get("trial", 0) > 0:
        score += 5
    verdict = "likely-bug" if score >= 60 else ("needs-review" if score >= 35 else "likely-safe")
    return {"verdict": verdict, "score": min(score, 100), "reason": "; ".join(reasons), "mode": "mock"}

# ---------------------------------------------------------------------------
# API 模式（OpenAI 兼容）
# ---------------------------------------------------------------------------
def api_verdict(finding, module):
    try:
        import urllib.request
    except ImportError:
        return mock_verdict(finding, module)
    base = os.environ.get("PF_LLM_BASE", "https://api.openai.com/v1")
    key = os.environ.get("PF_LLM_KEY", "")
    model = os.environ.get("PF_LLM_MODEL", "gpt-4o-mini")
    if not key:
        return mock_verdict(finding, module)
    rtl = find_signal_rtl(finding.get("signal", ""), module)
    tags = find_sec_cm(finding.get("signal", ""), module)
    prompt = f"""你是硬件安全专家。分析以下 fuzzing 发现是否为真实安全漏洞。

模块: {module}
Oracle: {finding.get('oracle')}
信号: {finding.get('signal')}
描述: {finding.get('desc')}
SEC_CM 关联: {tags}
RTL 上下文:
{rtl['context'] if rtl else '(未找到)'}

回答 JSON: {{"verdict": "likely-bug|needs-review|likely-safe", "reason": "一句话", "score": 0-100}}"""
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    try:
        resp = json.load(urllib.request.urlopen(req, timeout=30))
        content = resp["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", content, re.S)
        v = json.loads(m.group(0)) if m else {"verdict": "needs-review", "reason": content[:100], "score": 50}
        v["mode"] = "api"
        return v
    except Exception as e:
        v = mock_verdict(finding, module)
        v["reason"] = f"API 失败({e}) 回退 mock: {v['reason']}"
        return v

# ---------------------------------------------------------------------------
# 主流程（带缓存）
# ---------------------------------------------------------------------------
def cache_key(finding, module):
    raw = json.dumps({"m": module, "o": finding.get("oracle"), "s": finding.get("signal"),
                      "d": finding.get("desc", "")[:80]}, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    path, module = sys.argv[1], sys.argv[2]
    data = json.load(open(path))
    findings = data.get("findings", [])
    cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            cache = json.load(open(CACHE_FILE))
        except Exception:
            cache = {}
    use_api = bool(os.environ.get("PF_LLM_KEY"))
    print(f"=== LLM 分诊: {module} ({len(findings)} 条, {'API' if use_api else 'mock'} 模式) ===")
    for f in findings:
        k = cache_key(f, module)
        if k in cache:
            f["llm_verdict"] = cache[k]
            continue
        v = api_verdict(f, module) if use_api else mock_verdict(f, module)
        f["llm_verdict"] = v
        cache[k] = v
    json.dump(cache, open(CACHE_FILE, "w"), indent=1, ensure_ascii=False)
    out = path.replace(".json", "_llm.json")
    json.dump(data, open(out, "w"), indent=1, ensure_ascii=False)
    # 汇总
    from collections import Counter
    cnt = Counter(f["llm_verdict"]["verdict"] for f in findings)
    print(f"结果: {dict(cnt)}")
    print(f"输出: {out}")
    for f in findings:
        v = f["llm_verdict"]
        if v["verdict"] == "likely-bug":
            print(f"  [BUG?] {f.get('signal')} score={v['score']} — {v['reason'][:70]}")

if __name__ == "__main__":
    main()
