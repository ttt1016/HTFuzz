#!/usr/bin/env python3
"""
HTFuzz M10: 报告生成器（CWE 映射 + 安全影响分析）
====================================================
计划书 M10:
  - 模板化输出: bug 标题 / 触发序列(最小化后) / 观测 vs 期望(oracle 依据) /
    复现步骤 / 根因假设 / CWE 映射 + 安全影响分析
  - 预置硬件 CWE 映射: CWE-1234(IP 锁绕过)、CWE-1259(锁保护不当)、
    CWE-1262(访问控制寄存器接口不当)、CWE-1189(复位域不当)等
  - 每个 bug 走通全流程产出完整报告样例
"""

import json
from pathlib import Path

REPORT_DIR = Path("/workspace/pickerfuzz/reports_new/bugs")

# 硬件 CWE 映射表（计划书 M10 预置）
CWE_MAP = {
    "O1-R2-ro-write": {
        "cwe": "CWE-1262", "name": "Improper Access Control for Register Interface",
        "impact": "RO 寄存器可被软件写穿 → 状态篡改 → 后续安全决策基于被污染的状态"},
    "O1-R1-read-all-ones": {
        "cwe": "CWE-908", "name": "Use of Uninitialized Resource",
        "impact": "读回未初始化/悬空总线值 → 密钥材料或状态可能泄露到软件可见路径"},
    "O3-1-dual-seed": {
        "cwe": "CWE-908", "name": "Use of Uninitialized Resource",
        "impact": "随机初值依赖 → 上电状态不确定 → 密钥/状态残留可被观测"},
    "O3-2-reset-replay": {
        "cwe": "CWE-1189", "name": "Improper Isolation of Shared Resources on Reset",
        "impact": "复位后行为不一致 → 复位域隔离缺陷 → 跨复位状态残留"},
    "O3-3-key-residue": {
        "cwe": "CWE-226", "name": "Sensitive Information in Resource Not Removed Before Re-use",
        "impact": "密钥残留 → 下一个使用者可恢复前次密钥 → 跨会话密钥泄露（FIVE-9 类）"},
    "P2-stuck-at": {
        "cwe": "CWE-1234", "name": "Hardware Internal or Debug Modes Allow Override of Locks",
        "impact": "控制信号失效 → 保护逻辑可被绕过"},
    "P3-residue": {
        "cwe": "CWE-226", "name": "Sensitive Information in Resource Not Removed Before Re-use",
        "impact": "zeroize 声称覆盖但残留 → 密钥恢复"},
    "P4-special-lock": {
        "cwe": "CWE-1259", "name": "Improper Restriction of Security-Token Replacement",
        "impact": "MuBi/lc_ctrl 特殊值硬编码 → 安全状态机可被固定值欺骗（FIVE-12 类）"},
    "wr_err": {
        "cwe": "CWE-1262", "name": "Improper Access Control for Register Interface",
        "impact": "写错误响应异常 → 访问控制语义偏差"},
}


def gen_bug_report(finding, minimized_seq=None, idx=1):
    """从崩溃库条目生成完整 bug 报告"""
    oracle = finding.get("oracle", finding.get("mode", "?"))
    cwe = CWE_MAP.get(oracle, {"cwe": "CWE-Unknown", "name": "Unknown",
                               "impact": "需人工分析"})
    title = "[%s] %s: %s" % (oracle,
                             finding.get("signal") or finding.get("reg") or finding.get("off", "?"),
                             finding.get("desc") or finding.get("type", ""))
    seq_lines = []
    for op in (minimized_seq or finding.get("seq", []))[:30]:
        if isinstance(op, (list, tuple)) and len(op) >= 3:
            seq_lines.append("  %s off=0x%03x data=0x%08x mask=0x%x" %
                             (op[0], op[1], op[2], op[3] if len(op) > 3 else 0xF))
    report = """# BUG-{idx}: {title}

## 1. 摘要

- **Oracle 层**: {oracle}
- **CWE**: {cwe} ({cname})
- **签名**: {sig}
- **发现迭代**: {iter} (seed={seed})

## 2. 触发序列（最小化后）

```
{seq}
```

## 3. 观测 vs 期望

| 项 | 值 |
|---|---|
| 观测 | {observed} |
| 期望 | {expected} |
| Oracle 依据 | {oracle_basis} |

## 4. 复现步骤

1. 加载 per-IP DUT 共享库 `liblibpf_hmac.so`
2. `pf_init(seed={seed})`
3. 按上述序列执行 pf_write/pf_read
4. 触发条件: {trigger}

## 5. 根因假设（LLM 辅助，人工确认）

- 相关 RTL: hmac.sv（待定位具体行）
- 假设: {hypothesis}

## 6. 安全影响分析（CWE 映射）

**{cwe} — {cname}**

{impact}

**利用链**: 攻击者（恶意固件/软件）→ {exploit_chain}

## 7. PoC 复现

- per-IP DUT: 本报告序列直接复现
- 全芯片仿真: 将序列转成固件 mmio 调用，跑 chip_verilator_sim（报告可信度验证）
"""
    # 填充
    obs = finding.get("detail", finding.get("errors", "见序列"))
    rep = report.format(
        idx=idx, title=title, oracle=oracle,
        cwe=cwe["cwe"], cname=cwe["name"], sig=finding.get("sig", "-"),
        iter=finding.get("iter", "-"), seed=finding.get("seed", "-"),
        seq="\n".join(seq_lines) if seq_lines else "（见 findings.jsonl）",
        observed=obs, expected="按 hjson 规格/元变关系应无此行为",
        oracle_basis="%s oracle 检测规则" % oracle,
        trigger=finding.get("desc", "序列执行完成"),
        hypothesis="待 LLM 根因分析（最小化序列 + 相关 RTL 片段输入）",
        impact=cwe["impact"],
        exploit_chain="恶意固件写触发序列 → 观测违规行为 → %s" % cwe["impact"].split("→")[-1].strip(),
    )
    return rep


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="/workspace/pickerfuzz/fuzz/mass/findings.jsonl")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if args.demo:
        # 演示: 用一个合成密钥残留发现生成完整报告
        finding = {
            "oracle": "O3-3-key-residue", "iter": 12345, "seed": 31000,
            "signal": "u_dut.secret_key", "sig": "demo1234",
            "desc": "WIPE_SECRET 后 secret_key[31] 残留 0xDEADBEEF",
            "detail": "wipe 后 secret_key[31]=0xDEADBEEF (期望 0x00000000)",
            "seq": [["W", 0x24, 0xDEADBEEF, 0xF], ["W", 0x20, 0x1, 0xF], ["R", 0x18, 0, 0xF]],
        }
        rep = gen_bug_report(finding, minimized_seq=[("W", 0x24, 0xDEADBEEF, 0xF),
                                                     ("W", 0x20, 0x1, 0xF)], idx=1)
        out = REPORT_DIR / "BUG-001-demo.md"
        out.write_text(rep)
        print("演示报告: %s" % out)
        print(rep[:1500])
        return

    # 从 findings.jsonl 批量生成
    idx = 1
    for line in open(args.findings):
        f = json.loads(line)
        rep = gen_bug_report(f, idx=idx)
        (REPORT_DIR / ("BUG-%03d.md" % idx)).write_text(rep)
        idx += 1
    print("生成 %d 份报告 → %s" % (idx - 1, REPORT_DIR))


if __name__ == "__main__":
    main()
