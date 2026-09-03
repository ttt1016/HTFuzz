#!/usr/bin/env python3
"""
HTFuzz M7: 异常分诊三级漏斗（规则引擎 + known-safe 缓存 + LLM 分诊接口）
==========================================================================
计划书 M7:
  一级·规则引擎（纯结构，每迭代）: 告警签名去重 + 已知安全模式静态排除
    （SHA 初始常量 H0-H7、总线 hold 值、ready/valid 完成后保持）
  二级·known-safe 数据库（跨迭代累积）: 判定为"已知安全"的签名入库，
    后续同签名直接静默——LLM 调用量随时间递减
  三级·LLM 批量分诊: 按层级路径+桶签名聚类后批量判
    （likely-bug / known-safe / protocol-hold 三分类 + 置信度）
    判定结果缓存（签名→结论），保证可复现且省钱
  LLM 挂了可降级为纯规则模式

本文件实现完整漏斗；LLM 部分留标准接口（比赛时接 API，平时用规则模拟）。
"""

import json
import hashlib
import re
from pathlib import Path

KNOWN_SAFE_DB = Path("/workspace/HTFuzz/fuzz/known_safe.json")
LLM_CACHE = Path("/workspace/HTFuzz/fuzz/llm_cache.json")

# ---------------------------------------------------------------------------
# 一级: 规则引擎——静态已知安全模式
# ---------------------------------------------------------------------------

# SHA-2 初始常量 H0-H7（SHA2-256）与 SHA2-512 IV——读 digest 未完成时是 IV，安全
SHA256_IV = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
SHA512_IV_HI = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

# 总线 hold 值: 完成后保持上一次值（TLUL 协议行为）
BUS_HOLD_PATTERNS = ["d_valid 后保持", "a_ready 保持"]

# 信号名静态安全模式
SAFE_NAME_PATTERNS = [
    r"unused", r"tie", r"constant", r"prim_sec_anchor",  # anchor 防优化
]


def alert_signature(alert):
    """告警签名: oracle 类型 + 信号/寄存器 + 模式（不含具体值，同 bug 多变体归一）"""
    key = "%s|%s|%s" % (alert.get("oracle", "?"),
                        alert.get("signal") or alert.get("reg") or alert.get("off", "?"),
                        alert.get("mode", alert.get("type", "?")))
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def rule_engine_filter(alerts):
    """一级漏斗: 规则引擎初筛。返回 (通过, 排除原因)"""
    passed, excluded = [], []
    for a in alerts:
        sig = alert_signature(a)
        val = a.get("value")
        # 规则 1: SHA IV 常量（digest 未完成时读 IV 是安全的）
        if isinstance(val, int) and val in SHA256_IV:
            excluded.append((a, sig, "SHA-IV 常量"))
            continue
        # 规则 2: 信号名静态安全
        name = str(a.get("signal", ""))
        if any(re.search(p, name.lower()) for p in SAFE_NAME_PATTERNS):
            excluded.append((a, sig, "静态安全信号名"))
            continue
        # 规则 3: 全 0 / 全 F 的 constancy（复位默认，非 bug）
        if a.get("mode") == "P1-constancy" and val in (0, 0xFFFFFFFF):
            excluded.append((a, sig, "复位默认值 constancy"))
            continue
        passed.append((a, sig))
    return passed, excluded


# ---------------------------------------------------------------------------
# 二级: known-safe 数据库
# ---------------------------------------------------------------------------

def load_known_safe():
    if KNOWN_SAFE_DB.exists():
        return json.load(open(KNOWN_SAFE_DB))
    return {}


def save_known_safe(db):
    KNOWN_SAFE_DB.parent.mkdir(parents=True, exist_ok=True)
    json.dump(db, open(KNOWN_SAFE_DB, "w"), indent=1)


def known_safe_filter(alerts_with_sig):
    """二级漏斗: known-safe 数据库静默"""
    db = load_known_safe()
    passed, silenced = [], []
    for a, sig in alerts_with_sig:
        if sig in db and db[sig].get("verdict") == "known-safe":
            silenced.append((a, sig, db[sig].get("reason", "")))
        else:
            passed.append((a, sig))
    return passed, silenced


# ---------------------------------------------------------------------------
# 三级: LLM 批量分诊（带缓存；无 API 时规则模拟）
# ---------------------------------------------------------------------------

def load_llm_cache():
    if LLM_CACHE.exists():
        return json.load(open(LLM_CACHE))
    return {}


def save_llm_cache(cache):
    LLM_CACHE.parent.mkdir(parents=True, exist_ok=True)
    json.dump(cache, open(LLM_CACHE, "w"), indent=1)


def llm_triage(alerts_with_sig, use_llm=False):
    """三级漏斗: LLM 批量分诊（缓存优先）。
    返回: [(alert, sig, verdict, confidence)]
    verdict: likely-bug / known-safe / protocol-hold
    """
    cache = load_llm_cache()
    results = []
    need_llm = []
    for a, sig in alerts_with_sig:
        if sig in cache:
            c = cache[sig]
            results.append((a, sig, c["verdict"], c["confidence"]))
        else:
            need_llm.append((a, sig))

    if need_llm:
        if use_llm:
            # 真实 LLM 调用点（比赛时接入）——此处留接口
            verdicts = _llm_batch_call([a for a, _ in need_llm])
        else:
            # 规则模拟分诊（无 LLM 时的降级模式）
            verdicts = _rule_based_triage([a for a, _ in need_llm])
        for (a, sig), (verdict, conf, reason) in zip(need_llm, verdicts):
            cache[sig] = {"verdict": verdict, "confidence": conf, "reason": reason}
            results.append((a, sig, verdict, conf))
        save_llm_cache(cache)
    return results


def _rule_based_triage(alerts):
    """规则模拟 LLM 分诊（降级模式）——基于告警结构特征"""
    out = []
    for a in alerts:
        mode = a.get("mode", a.get("type", ""))
        name = str(a.get("signal", a.get("reg", "")))
        w = a.get("weight", 0)
        # 高权重 + P2/P3 模式 → likely-bug 候选
        if mode in ("P2-stuck-at", "P3-residue") and w >= 4:
            out.append(("likely-bug", 0.7, "高权重 %s 模式" % mode))
        elif mode == "P4-special-lock":
            out.append(("protocol-hold", 0.5, "特殊值锁定，需协议确认"))
        elif "residue" in mode or "key" in name.lower():
            out.append(("likely-bug", 0.6, "密钥相关残留"))
        else:
            out.append(("known-safe", 0.8, "低权重状态信号模式"))
    return out


def _llm_batch_call(alerts):
    """真实 LLM 批量调用（比赛时实现）——当前返回占位"""
    # TODO: 比赛时接入 LLM API，输入=告警聚类组，输出=三分类+置信度
    return _rule_based_triage(alerts)


# ---------------------------------------------------------------------------
# 完整漏斗入口
# ---------------------------------------------------------------------------

def triage_alerts(alerts, use_llm=False, verbose=True):
    """完整三级漏斗。返回 {"likely-bug": [...], "known-safe": [...], "protocol-hold": [...], "excluded": n}"""
    if verbose:
        print("[漏斗] 输入告警: %d" % len(alerts))
    # 一级
    passed1, excluded = rule_engine_filter(alerts)
    if verbose:
        print("[漏斗 L1 规则引擎] 通过 %d, 排除 %d" % (len(passed1), len(excluded)))
    # 二级
    passed2, silenced = known_safe_filter(passed1)
    if verbose:
        print("[漏斗 L2 known-safe] 通过 %d, 静默 %d" % (len(passed2), len(silenced)))
    # 三级
    triaged = llm_triage(passed2, use_llm=use_llm)
    result = {"likely-bug": [], "known-safe": [], "protocol-hold": []}
    for a, sig, verdict, conf in triaged:
        result[verdict].append({"alert": a, "sig": sig, "confidence": conf})
    if verbose:
        print("[漏斗 L3 分诊] likely-bug=%d known-safe=%d protocol-hold=%d"
              % (len(result["likely-bug"]), len(result["known-safe"]), len(result["protocol-hold"])))
    result["excluded_count"] = len(excluded) + len(silenced)
    return result


# ---------------------------------------------------------------------------
# 演示: 用 O4 的 23 个发现走漏斗
# ---------------------------------------------------------------------------

def main():
    findings = json.load(open("/workspace/HTFuzz/fuzz/o4_findings.json"))
    print("=" * 60)
    print("M7 三级漏斗演示: O4 的 %d 个发现" % len(findings))
    print("=" * 60)
    result = triage_alerts(findings, use_llm=False)
    print()
    print("--- likely-bug 候选（人工/深挖）---")
    for x in result["likely-bug"]:
        a = x["alert"]
        print("  [%s] %s: %s (conf=%.2f)" % (x["sig"], a.get("signal"), a.get("desc"), x["confidence"]))
    print()
    print("--- protocol-hold（需协议确认）---")
    for x in result["protocol-hold"][:5]:
        a = x["alert"]
        print("  [%s] %s: %s" % (x["sig"], a.get("signal"), a.get("desc")))
    print()
    db = load_known_safe()
    print("known-safe 库: %d 签名  LLM 缓存: %d 签名" % (len(db), len(load_llm_cache())))
    print("漏斗总抑制率: %.0f%%" % (100.0 * result["excluded_count"] / max(1, len(findings))))


if __name__ == "__main__":
    main()
