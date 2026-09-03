#!/usr/bin/env python3
"""
LLM 主动安全审计 —— 不依赖 fuzzing 候选，直接对模块的安全关键信号做 LLM 审计
目标：发现 CSV 之外的新注入（比赛加分项）

策略：
1. 提取模块全部 SEC_CM 声明（安全机制清单）
2. 对每个 SEC_CM 定位其实现信号（计数器/FSM/冗余逻辑）
3. 构造审计 prompt（机制意图 + RTL 上下文）让 LLM 判断是否被篡改
4. 输出可疑点清单（按置信度排序）

用法:
  python3 llm_proactive_audit.py alert_handler
  python3 llm_proactive_audit.py --all-high-value   # 全部高价值模块
"""
import json, os, re, sys, glob, hashlib

OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")
PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")
CACHE_FILE = os.path.join(PF, "fuzz", "llm_proactive_cache.json")

# 高价值模块（安全机制密集）
HIGH_VALUE = [
    "alert_handler", "otp_ctrl", "flash_ctrl", "otbn", "keymgr",
    "sram_ctrl", "aes", "hmac", "kmac", "ascon", "lc_ctrl", "rv_dm",
]

# SEC_CM 类型 → 审计重点
SEC_CM_FOCUS = {
    "CTR.REDUN": "计数器冗余编码——检查冗余计数器是否真的独立递增、比较逻辑是否被绕过",
    "FSM.SPARSE": "稀疏 FSM 编码——检查状态编码是否仍稀疏、非法状态检测是否有效",
    "FSM.LOCAL_ESC": "本地 escalation——检查异常状态是否正确触发本地安全响应",
    "FSM.GLOBAL_ESC": "全局 escalation——检查全局 escalation 输入是否被正确消费",
    "LFSR.REDUN": "LFSR 冗余——检查 LFSR 复制是否独立、比较是否有效",
    "KEY.SEC_WIPE": "密钥安全擦除——检查擦除使能极性/条件/覆盖范围",
    "DATA_REG.SEC_WIPE": "数据寄存器擦除——同上",
    "BUS.INTEGRITY": "总线完整性——检查 intg 检查是否被旁路",
    "ACCESS.MUBI": "mubi 访问控制——检查 mubi 判定是否严格（== True 而非 !False）",
    "CTRL.FLOW.GLOBAL_ESC": "控制流全局 escalation",
    "CTRL.FLOW.LOCAL_ESC": "控制流本地 escalation",
}


def find_sec_cm_signals(module):
    """提取模块全部 SEC_CM 声明及其所在文件/行"""
    out = []
    for base in [os.path.join(OT, "hw/ip", module),
                 os.path.join(OT, "hw/top_earlgrey/ip_autogen", module),
                 os.path.join(OT, "hw/vendor/pulp_riscv_dbg/src"),
                 os.path.join(OT, "hw/vendor/lowrisc_ibex/rtl")]:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for d in ("dv", "fpv", "pre_dv", "pre_syn", "pre_sca", "model", "tb", "vendor"):
                if d in dirs:
                    dirs.remove(d)
            for fn in files:
                if not fn.endswith(".sv"):
                    continue
                path = os.path.join(root, fn)
                try:
                    lines = open(path, errors="ignore").read().split("\n")
                except Exception:
                    continue
                for i, ln in enumerate(lines):
                    m = re.search(r"SEC_CM:\s*([A-Z_.0-9,\s]+)", ln)
                    if m:
                        rel = os.path.relpath(path, base)
                        out.append({"sec_cm": m.group(1).strip(),
                                    "file": rel, "line": i + 1,
                                    "abs_path": path})
    return out


def context_around(path, line, pad=35):
    try:
        lines = open(path, errors="ignore").read().split("\n")
    except Exception:
        return ""
    lo = max(0, line - 1 - pad)
    hi = min(len(lines), line - 1 + pad + 1)
    return "\n".join(f"{n+1:5d}: {lines[n]}" for n in range(lo, hi))


def build_audit_prompt(module, sec):
    focus = ""
    for k, v in SEC_CM_FOCUS.items():
        if k in sec["sec_cm"]:
            focus = v
            break
    ctx = context_around(sec["abs_path"], sec["line"])
    return f"""你是硬件安全 CTF 专家（HACK@CHES），审计 OpenTitan fork 中被注入的硬件木马。

## 审计对象
- 模块: {module}
- 安全机制声明: SEC_CM: {sec['sec_cm']}
- 位置: {sec['file']}:{sec['line']}
- 该类机制的审计重点: {focus or '检查实现是否符合机制声明的安全意图'}

## RTL 上下文（声明处 ±35 行）
```systemverilog
{ctx}
```

## 审计要求
1. 该 SEC_CM 机制的实现是否完整（冗余计数器真的独立？FSM 编码真的稀疏？擦除真的无条件？）
2. 检查：极性反转、条件篡改、常量替换、检查逻辑被旁路、escalation 被吞没
3. 特别注意与上游 OpenTitan 标准实现的语义偏差

## 输出 JSON（严格格式）
{{"verdict": "suspicious|needs-review|clean",
  "confidence": 0-100,
  "injection_type": "常量替换|极性反转|条件篡改|检查旁路|escalation吞没|无",
  "evidence": "具体证据（引用行号）",
  "impact": "安全影响一句话"}}"""


def _llm_chat(prompt, timeout=180):
    import urllib.request
    base = os.environ.get("PF_LLM_BASE", "http://127.0.0.1:18000/v1")
    key = os.environ.get("PF_LLM_KEY", "")
    model = os.environ.get("PF_LLM_MODEL", "zai-org/GLM-5.3-Flash")
    maxtok = int(os.environ.get("PF_LLM_MAXTOK", "16384"))
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "temperature": 0, "max_tokens": maxtok}).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions",
                                 data=body, headers=headers)
    resp = json.load(urllib.request.urlopen(req, timeout=timeout))
    msg = resp["choices"][0]["message"]
    content = msg.get("content") or ""
    if not content.strip():
        content = msg.get("reasoning") or ""
    return content


def _parse_json(content):
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", content, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    m = re.search(r"\{.*\}", content, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def audit_module(module, cache, use_api):
    secs = find_sec_cm_signals(module)
    print(f"\n[{module}] {len(secs)} 个 SEC_CM 声明")
    results = []
    for sec in secs:
        key_raw = json.dumps({"m": module, "s": sec["sec_cm"],
                              "f": sec["file"], "l": sec["line"]}, sort_keys=True)
        k = "pro_" + hashlib.md5(key_raw.encode()).hexdigest()
        if k in cache:
            v = cache[k]
        else:
            if not use_api:
                v = {"verdict": "needs-review", "confidence": 0,
                     "note": "无 API，跳过主动审计"}
            else:
                try:
                    content = _llm_chat(build_audit_prompt(module, sec))
                    v = _parse_json(content) or {"verdict": "needs-review",
                                                  "confidence": 0,
                                                  "evidence": content[:1500]}
                    v["mode"] = "api-proactive"
                except Exception as e:
                    v = {"verdict": "error", "confidence": 0, "evidence": str(e)[:200]}
            cache[k] = v
        v["sec_cm"] = sec["sec_cm"]
        v["file"] = sec["file"]
        v["line"] = sec["line"]
        results.append(v)
        mark = {"suspicious": "[SUSPECT!]", "needs-review": "[review]"}.get(
            v.get("verdict"), "[clean]")
        print(f"  {mark} {sec['sec_cm']:40s} {sec['file']}:{sec['line']}"
              f" conf={v.get('confidence', 0)}")
        if v.get("verdict") == "suspicious":
            print(f"      注入类型: {v.get('injection_type')}")
            print(f"      证据: {str(v.get('evidence'))[:120]}")
    return results


def main():
    use_api = bool(os.environ.get("PF_LLM_BASE") or os.environ.get("PF_LLM_KEY"))
    cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            cache = json.load(open(CACHE_FILE))
        except Exception:
            cache = {}
    if len(sys.argv) > 1 and sys.argv[1] == "--all-high-value":
        targets = HIGH_VALUE
    else:
        targets = sys.argv[1:] or HIGH_VALUE[:1]
    print(f"=== LLM 主动安全审计 ({len(targets)} 模块, {'API' if use_api else '无API(跳过)'}) ===")
    all_results = {}
    for mod in targets:
        all_results[mod] = audit_module(mod, cache, use_api)
    json.dump(cache, open(CACHE_FILE, "w"), indent=1, ensure_ascii=False)
    # 汇总可疑点
    print("\n=== 可疑点汇总 ===")
    n = 0
    for mod, results in all_results.items():
        for v in results:
            if v.get("verdict") == "suspicious":
                n += 1
                print(f"[{mod}] {v.get('sec_cm')} @ {v.get('file')}:{v.get('line')}"
                      f" — {v.get('injection_type')} conf={v.get('confidence')}")
    if n == 0:
        print("（无 suspicious 判定）")
    # 保存报告
    out = os.path.join(PF, "fuzz", "proactive_audit.json")
    json.dump(all_results, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\n输出: {out}")


if __name__ == "__main__":
    main()
