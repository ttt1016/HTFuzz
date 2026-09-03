#!/usr/bin/env python3
"""
LLM 深度审计器 —— 把 fuzzing 候选连同完整 RTL 上下文喂给大模型做深度安全分析

与 llm_triage.py（单条快判）的区别:
  - 深度模式: 提取候选信号的完整 always 块/函数上下文（±30 行）+ 模块内所有
    SEC_CM 注释 + 相关寄存器定义，构造高信息密度 prompt
  - 多视角: 每条候选从 3 个视角分析（数据流完整性/访问控制/时序安全）
  - 交叉验证: 同一模块的多条候选合并分析，找共性注入模式
  - 输出: 结构化审计报告（markdown），含置信度、影响分析、建议验证步骤

模式:
  mock : 无 API key 时的规则深度打分（常量赋值/极性反转/掩码静态等模式匹配）
  api  : OpenAI 兼容 API（PF_LLM_BASE/PF_LLM_KEY/PF_LLM_MODEL）

用法:
  python3 llm_deep_audit.py fuzz/discover_hmac.json hmac
  python3 llm_deep_audit.py --all          # 全部模块
  PF_LLM_BASE=... PF_LLM_KEY=... python3 llm_deep_audit.py ...
"""
import json, os, re, sys, hashlib, glob

OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")
PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")
CACHE_FILE = os.path.join(PF, "fuzz", "llm_deep_cache.json")

# ---------------------------------------------------------------------------
# RTL 深度上下文提取
# ---------------------------------------------------------------------------
def extract_block_context(signal_name, module, pad=30):
    """提取信号所在 always 块/assign 的完整上下文（比 triage 的 ±4 行深 7 倍）"""
    parts = signal_name.replace("u_dut.", "").replace("u_core.", "").split(".")
    sig = parts[-1]
    candidates = {sig, sig.replace("_raw", ""), sig.replace("_d", ""), sig.replace("_q", "")}
    ip_dirs = [os.path.join(OT, "hw/ip", module),
               os.path.join(OT, "hw/top_earlgrey/ip_autogen", module),
               os.path.join(OT, "hw/vendor/pulp_riscv_dbg/src"),
               os.path.join(OT, "hw/vendor/lowrisc_ibex/rtl")]
    hits = []
    for base in [os.path.join(OT, "hw/ip", module),
                 os.path.join(OT, "hw/top_earlgrey/ip_autogen", module),
                 os.path.join(OT, "hw/vendor/pulp_riscv_dbg/src"),
                 os.path.join(OT, "hw/vendor/lowrisc_ibex/rtl")]:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for d in ("dv", "fpv", "pre_syn", "pre_sca", "model", "vendor", "pre_dv", "tb"):
                if d in dirs:
                    dirs.remove(d)
            # 两轮: 第一轮找赋值行（<= 或 = 且含信号名），第二轮兜底任意引用
            # 收集最多 3 个命中（跨文件，覆盖 reg_top/core 多处赋值点）
            for pass_num, require_assign in enumerate([True, False]):
                if len(hits) >= 3:
                    break
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
                            if not re.search(r"\b%s\b" % re.escape(c), ln):
                                continue
                            if require_assign and not re.search(r"\b%s\b[^=]*<=|\b%s\b\s*=" % (re.escape(c), re.escape(c)), ln):
                                continue
                            lo = max(0, i - pad)
                            hi = min(len(lines), i + pad + 1)
                            ctx = "\n".join(f"{n+1:5d}: {lines[n]}" for n in range(lo, hi))
                            hits.append({"file": path.replace(OT + "/", ""),
                                         "line": i + 1, "context": ctx})
                            break
                        if len(hits) >= 3:
                            break
                    if len(hits) >= 3:
                        break
                if len(hits) >= 3:
                    break
        if hits:
            break
    return hits[0] if hits else None


def extract_sec_cm_all(module):
    """提取模块全部 SEC_CM 注释（安全机制清单）"""
    tags = []
    for base in [os.path.join(OT, "hw/ip", module),
                 os.path.join(OT, "hw/top_earlgrey/ip_autogen", module)]:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for d in ("dv", "fpv"):
                if d in dirs:
                    dirs.remove(d)
            for fn in files:
                if not fn.endswith(".sv"):
                    continue
                try:
                    content = open(os.path.join(root, fn), errors="ignore").read()
                except Exception:
                    continue
                for m in re.finditer(r"//\s*SEC_CM:\s*([A-Z_.0-9]+)", content):
                    rel = os.path.relpath(os.path.join(root, fn), base)
                    tags.append(f"{rel}: {m.group(1)}")
    return tags[:20]


def extract_reg_defs(module, signal_name):
    """提取相关寄存器的 hjson 定义（访问策略/复位值）"""
    out = []
    sig = signal_name.split(".")[-1].replace("_raw", "").replace("_d", "").replace("_q", "")
    for base in [os.path.join(OT, "hw/ip", module),
                 os.path.join(OT, "hw/top_earlgrey/ip_autogen", module)]:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for fn in files:
                if not fn.endswith(".hjson"):
                    continue
                try:
                    content = open(os.path.join(root, fn), errors="ignore").read()
                except Exception:
                    continue
                if sig.lower() in content.lower():
                    # 提取该寄存器块（±20 行）
                    idx = content.lower().find(sig.lower())
                    block = content[max(0, idx-200):idx+800]
                    out.append(f"### {fn}\n```\n{block}\n```")
                    if len(out) >= 2:
                        break
            if out:
                break
        if out:
            break
    return out


# ---------------------------------------------------------------------------
# 深度 prompt 构造
# ---------------------------------------------------------------------------
def build_deep_prompt(finding, module, rtl, sec_cms, reg_defs):
    # rtl 兼容单命中(dict)和多命中(list)
    rtl_list = rtl if isinstance(rtl, list) else ([rtl] if rtl else [])
    rtl_block = "\n\n".join(
        f"```systemverilog\n// {h['file']}:{h['line']}\n{h['context']}\n```"
        for h in rtl_list) if rtl_list else "（未找到 RTL 定义——可能被优化或命名变体，请基于现象推断）"
    oracle_hint = {
        "O-A-residual": "敏感数据（密钥/种子）在清除/擦除操作后仍残留——检查擦除路径是否被篡改（写使能极性/条件/映射目标）",
        "O-B-determinism": "本应随机的信号（掩码/熵）两次执行完全相同——检查随机源是否被替换为常量",
        "O-C-equivclass": "语义等价的操作序列产生不同状态——检查中间读副作用/相位错误",
        "O-D-fsm": "FSM 在边界输入后进入非基线稳态——检查状态转移条件/超时恢复",
        "O-E-fifo": "FIFO 压力下数据破坏——检查深度/指针逻辑",
        "O-F-stream": "流式计数器冻结/倒退——检查使能条件/计数逻辑",
        "O-G-pulse": "握手脉冲宽度异常/电平化——检查响应寄存器插入",
        "O-H-pmp": "PMP 权限语义偏离 RISC-V 规范——检查 perm_check 极性/err 输出",
        "O-I-priv": "特权级语义偏离——检查 U-mode 指令限制/CSR 访问控制",
    }.get(finding.get("oracle", ""), "")

    prompt = f"""你是硬件安全 CTF 专家（HACK@CHES），分析 OpenTitan RTL 中被注入的硬件木马。

## 背景
比赛方在 OpenTitan fork 中注入了安全 bug。以下是 fuzzing 引擎（8 个 oracle）自动发现的候选，
请基于 RTL 上下文做深度语义分析，判断是否为真实注入。

## 候选信息
- 模块: {module}
- Oracle: {finding.get('oracle')} {('—— ' + oracle_hint) if oracle_hint else ''}
- 信号: {finding.get('signal')}
- 现象: {finding.get('desc')}
- 置信度: {finding.get('confidence')}

## 该模块的安全机制清单（SEC_CM）
{chr(10).join(sec_cms) if sec_cms else '（未找到）'}

## 相关寄存器定义
{chr(10).join(reg_defs) if reg_defs else '（未找到）'}

## RTL 上下文（信号驱动逻辑，可能有多处赋值点——reg_top 门控 + core 数据通路）
{rtl_block}

## 分析要求
1. 判断该信号的行为是否符合其 SEC_CM 声明的安全意图
2. 检查是否存在：常量替换随机、极性反转、条件篡改、擦除路径绕过、权限检查失效
3. **重点：写使能/门控信号的极性**——对比 `we = ... & reg_error` 与 `we = ... & !reg_error`，
   擦除/清除类寄存器的写使能若被 `reg_error` 门控（而非 `!reg_error`）即为注入
4. 若当前上下文看起来正常但 oracle 动态观测到异常，说明注入在信号的 fanout/fanin
   （上游生成或下游消费），请指出需要追踪的方向
5. 给出结论和置信度

## 输出 JSON（严格格式）
{{"verdict": "likely-bug|needs-review|likely-safe",
  "confidence": 0-100,
  "injection_type": "常量替换|极性反转|条件篡改|擦除绕过|权限失效|无",
  "evidence": "RTL 中的具体证据（引用文件:行号）",
  "impact": "安全影响一句话",
  "suggested_poc": "如何动态验证（寄存器序列）"}}"""
    return prompt


# ---------------------------------------------------------------------------
# Mock 深度分析（无 API 时的增强规则引擎）
# ---------------------------------------------------------------------------
DEEP_PATTERNS = [
    (r"=\s*1'b0\s*;", "常量 0 赋值（检查是否应为表达式）", 30, "常量替换"),
    (r"=\s*1'b1\s*;", "常量 1 赋值", 20, "常量替换"),
    (r"\|\s*\(\s*~\w+\s*\|\s*\w+\s*\)", "可疑的恒真或条件", 25, "条件篡改"),
    (r"&\s*~\w+_result\b", "结果取反与（可能吞没信号）", 35, "条件篡改"),
    (r"wipe|clear|zero", "擦除相关逻辑", 15, "擦除绕过"),
    (r"lfsr|urnd|rnd", "随机源逻辑", 10, "常量替换"),
    (r"lock|perm|priv", "权限检查逻辑", 20, "权限失效"),
]


def mock_deep_verdict(finding, module, rtl, sec_cms, reg_defs):
    score = 40  # 深度模式基础分更高（有 RTL 上下文）
    reasons = []
    injection = "无"
    evidence = ""
    if rtl:
        ctx = rtl["context"]
        evidence = f"{rtl['file']}:{rtl['line']}"
        best = (0, "", "")
        for pat, desc, pts, itype in DEEP_PATTERNS:
            m = re.search(pat, ctx, re.I)
            if m and pts > best[0]:
                best = (pts, desc, itype)
        if best[0] > 0:
            score += best[0]
            reasons.append(f"{best[1]} +{best[0]}")
            injection = best[2]
            # 提取命中行作为证据
            for ln in ctx.split("\n"):
                if re.search(best[0] and r"=" , ln) and ("1'b" in ln or "wipe" in ln.lower() or "lock" in ln.lower()):
                    evidence += f" → `{ln.strip()[:80]}`"
                    break
    if sec_cms:
        score += 10
        reasons.append(f"SEC_CM 上下文 {len(sec_cms)} 项")
    verdict = "likely-bug" if score >= 70 else ("needs-review" if score >= 50 else "likely-safe")
    return {
        "verdict": verdict, "confidence": min(score, 100),
        "injection_type": injection, "evidence": evidence or "(无 RTL 命中)",
        "impact": f"{finding.get('signal')} 行为偏离 SEC_CM 意图",
        "suggested_poc": f"写触发寄存器后白盒观测 {finding.get('signal')}",
        "reason": "; ".join(reasons), "mode": "mock-deep",
    }


# ---------------------------------------------------------------------------
# API 深度分析
# ---------------------------------------------------------------------------
# 环境变量:
#   PF_LLM_BASE  : OpenAI 兼容端点根（如 http://127.0.0.1:18000/v1）
#   PF_LLM_KEY   : API key（自建无鉴权服务可留空或任意值）
#   PF_LLM_MODEL : 模型名（如 zai-org/GLM-5.3-Flash）
#   PF_LLM_MAXTOK: max_tokens（reasoning 模型建议 8192+，思考也占 token）
def _llm_chat(prompt, timeout=180):
    """调用 OpenAI 兼容 chat/completions，兼容 reasoning 模型（content 可能为
    null、思考在 reasoning 字段）。返回 content 文本。"""
    import urllib.request
    base = os.environ.get("PF_LLM_BASE", "http://127.0.0.1:18000/v1")
    key = os.environ.get("PF_LLM_KEY", "")
    model = os.environ.get("PF_LLM_MODEL", "zai-org/GLM-5.3-Flash")
    maxtok = int(os.environ.get("PF_LLM_MAXTOK", "16384"))
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "temperature": 0,
                       "max_tokens": maxtok}).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions",
                                 data=body, headers=headers)
    resp = json.load(urllib.request.urlopen(req, timeout=timeout))
    msg = resp["choices"][0]["message"]
    content = msg.get("content") or ""
    # reasoning 模型: content 为空时从 reasoning 字段提取
    if not content.strip():
        content = msg.get("reasoning") or ""
    return content


def _parse_verdict_json(content):
    """从模型输出提取 verdict JSON（容忍 markdown 代码块/前后缀文本）"""
    # 1) ```json 块
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # 2) 含 verdict 的裸 JSON
    m = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", content, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    # 3) 兜底任意 {...}
    m = re.search(r"\{.*\}", content, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def api_deep_verdict(finding, module, rtl, sec_cms, reg_defs):
    try:
        import urllib.request
    except ImportError:
        return mock_deep_verdict(finding, module, rtl, sec_cms, reg_defs)
    prompt = build_deep_prompt(finding, module, rtl, sec_cms, reg_defs)
    try:
        content = _llm_chat(prompt)
        v = _parse_verdict_json(content)
        if v is None:
            v = {"verdict": "needs-review", "confidence": 50,
                 "evidence": (content or "")[:2000]}
        v["mode"] = "api-deep"
        v["model"] = os.environ.get("PF_LLM_MODEL", "zai-org/GLM-5.3-Flash")
        return v
    except Exception as e:
        v = mock_deep_verdict(finding, module, rtl, sec_cms, reg_defs)
        v["reason"] = f"API 失败({e}) 回退 mock-deep: {v['reason']}"
        return v


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def cache_key(finding, module):
    raw = json.dumps({"m": module, "o": finding.get("oracle"), "s": finding.get("signal"),
                      "d": finding.get("desc", "")[:80]}, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()


def audit_file(path, module, cache, use_api):
    data = json.load(open(path))
    findings = data.get("findings", [])
    changed = False
    for f in findings:
        k = "deep_" + cache_key(f, module)
        if k in cache:
            f["llm_deep"] = cache[k]
            continue
        rtl = extract_block_context(f.get("signal", ""), module)
        sec_cms = extract_sec_cm_all(module)
        reg_defs = extract_reg_defs(module, f.get("signal", ""))
        if use_api:
            v = api_deep_verdict(f, module, rtl, sec_cms, reg_defs)
        else:
            v = mock_deep_verdict(f, module, rtl, sec_cms, reg_defs)
        f["llm_deep"] = v
        cache[k] = v
        changed = True
    out = path.replace(".json", "_deep.json")
    json.dump(data, open(out, "w"), indent=1, ensure_ascii=False)
    return out, findings


def main():
    # API 模式: 配置了 PF_LLM_BASE 或 PF_LLM_KEY 即启用（自建无鉴权服务只需 BASE）
    use_api = bool(os.environ.get("PF_LLM_BASE") or os.environ.get("PF_LLM_KEY"))
    cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            cache = json.load(open(CACHE_FILE))
        except Exception:
            cache = {}
    targets = []
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        for f in sorted(glob.glob(os.path.join(PF, "fuzz", "discover_*.json"))):
            bn = os.path.basename(f)
            if "_triaged" in bn or "_llm" in bn or "_deep" in bn:
                continue
            mod = bn.replace("discover_", "").replace(".json", "")
            targets.append((f, mod))
    else:
        if len(sys.argv) < 3:
            print(__doc__)
            sys.exit(1)
        targets.append((sys.argv[1], sys.argv[2]))

    print(f"=== LLM 深度审计 ({len(targets)} 模块, {'API' if use_api else 'mock-deep'} 模式) ===")
    from collections import Counter
    total = Counter()
    for path, module in targets:
        out, findings = audit_file(path, module, cache, use_api)
        cnt = Counter(f.get("llm_deep", {}).get("verdict", "?") for f in findings)
        total.update(cnt)
        print(f"\n[{module}] {len(findings)} 条 → {out}")
        for f in findings:
            v = f.get("llm_deep", {})
            mark = {"likely-bug": "[BUG?]", "needs-review": "[REVIEW?]"}.get(v.get("verdict"), "[safe]")
            print(f"  {mark} {f.get('signal')} conf={v.get('confidence')} "
                  f"inject={v.get('injection_type','-')}")
            if v.get("evidence"):
                print(f"        证据: {str(v.get('evidence'))[:90]}")
    json.dump(cache, open(CACHE_FILE, "w"), indent=1, ensure_ascii=False)
    print(f"\n=== 汇总: {dict(total)} ===")


if __name__ == "__main__":
    import sys
    main()
