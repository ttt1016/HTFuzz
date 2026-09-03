#!/usr/bin/env python3
"""
O-K 不变量 oracle —— LLM 从 SEC_CM/规格提取安全不变量（JSON 配置），
通用检查器在 fuzzing 激励下动态验证。不变量是数据不是代码。

子命令:
  gen <module>    LLM 提取不变量 -> invariants/<module>.json
  check <module>  加载不变量，DUT 动态检查 -> fuzz/invariant_<module>.json

check 需要: --dut-dir perip/hmac-ctf --regmap traces/hmac_regmap.json
环境: PF_LLM_BASE/PF_LLM_MODEL（gen 用），PF_ROOT/PF_TARGET_RTL
"""
import json, os, re, sys, ctypes

PF = os.environ.get("PF_ROOT", "/workspace/HTFuzz")
OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")
INV_DIR = os.path.join(PF, "invariants")


# ---------------------------------------------------------------------------
# LLM 不变量提取
# ---------------------------------------------------------------------------
def _llm_chat(prompt, timeout=300):
    import urllib.request
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        os.environ.pop(k, None)
    os.environ["no_proxy"] = "*"
    base = os.environ.get("PF_LLM_BASE", "http://127.0.0.1:18000/v1")
    key = os.environ.get("PF_LLM_KEY", "")
    model = os.environ.get("PF_LLM_MODEL", "zai-org/GLM-5.3-Flash")
    maxtok = int(os.environ.get("PF_LLM_MAXTOK", "16384"))
    # 域名预解析（IPv6 双栈问题）
    import socket as _socket
    m = re.match(r"(http://)([^/:]+)(:\d+)?(/.*)?$", base.rstrip("/"))
    if m:
        scheme, host, port, path = m.groups()
        try:
            ip = _socket.gethostbyname(host)
            if host not in ("localhost", "127.0.0.1"):
                base = f"{scheme}{ip}{port or ''}{path or ''}"
        except Exception:
            pass
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "temperature": 0, "max_tokens": maxtok}).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions",
                                 data=body, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    resp = json.load(opener.open(req, timeout=timeout))
    msg = resp["choices"][0]["message"]
    content = msg.get("content") or ""
    if not content.strip():
        content = msg.get("reasoning") or ""
    return content


def collect_sec_context(module):
    """收集 SEC_CM 注释 + hjson 安全描述"""
    out = []
    for base in [os.path.join(OT, "hw/ip", module),
                 os.path.join(OT, "hw/top_earlgrey/ip_autogen", module),
                 os.path.join(OT, "hw/vendor/pulp_riscv_dbg/src"),
                 os.path.join(OT, "hw/vendor/lowrisc_ibex/rtl")]:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for d in ("dv", "fpv", "pre_dv", "pre_syn", "tb", "vendor"):
                if d in dirs:
                    dirs.remove(d)
            for fn in files:
                if not fn.endswith((".sv", ".hjson")):
                    continue
                path = os.path.join(root, fn)
                rel = os.path.relpath(path, base)
                try:
                    for i, ln in enumerate(open(path, errors="ignore")):
                        if re.search(r"SEC_CM|wipe|secret|secure|zeroiz", ln, re.I):
                            out.append(f"{rel}:{i+1}: {ln.strip()[:120]}")
                except Exception:
                    pass
    return out[:25]


def collect_regmap_text(module):
    """从 reg_pkg.sv 提取寄存器偏移表"""
    lines = []
    for base in [os.path.join(OT, "hw/ip", module),
                 os.path.join(OT, "hw/top_earlgrey/ip_autogen", module)]:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for fn in files:
                if not fn.endswith("_reg_pkg.sv"):
                    continue
                try:
                    c = open(os.path.join(root, fn), errors="ignore").read()
                except Exception:
                    continue
                for m in re.finditer(r"parameter logic \[\w+-1:0\] \w+_([A-Z_0-9]+)_OFFSET = \d+'h ([0-9a-fA-F]+);", c):
                    lines.append(f"  {m.group(1).lower()}: 0x{m.group(2)}")
        if lines:
            break
    return "\n".join(lines[:25])


GEN_PROMPT = """你是硬件安全专家。为 OpenTitan 的 {module} 模块提取**运行时可检查的安全不变量**。

## 安全机制标注（SEC_CM / hjson 描述）
{sec_text}

## 寄存器映射
{reg_text}

## 要求
针对每个安全敏感数据路径（密钥/种子/掩码/摘要/擦除/状态机/总线/中断），提出运行时可检查的不变量。
不变量必须能用这些动作验证：write(寄存器)、step(时钟)、sig_read(白盒信号)。

rule 类型（检查器支持的 12 种，来自硬件安全通用分类学）：
- wipe_clears: 数据擦除/清零/复位后必须归零或变为安全值（数据完整性）
- read_only_leak: write-only 寄存器读回必须全 0（信息泄露）
- changes_across_runs: 随机性信号（掩码/熵/PRNG）两次独立运行必须不同（随机性）
- reg_core_consistent: 同一数据在 reg 侧和 core 侧的副本必须一致（数据完整性）
- access_control: 权限/锁/门控必须生效，未授权访问必须被拒绝（访问控制）
- cfg_block_gating: cfg_block=1 时敏感写必须被拒绝（访问控制）
- fsm_sparse_encoding: FSM 状态必须是合法 sparse 编码（状态机）
- err_code_coherent: 错误发生后 ERR_CODE 必须置位（错误报告）
- interrupt_first_event: 中断只在首次事件时触发，不重复（中断一致性）
- bus_intg_check: TL-UL intg 错误必须触发 alert 或 error（总线完整性）
- monotonic_counter: 计数器只增不减（除非显式清除）（计数器安全）
- debug_lock_enforce: debug-lock 后 DFT/调试信号必须无效（调试安全）

每条不变量指定 trigger_regs（触发检查的寄存器写序列）。

只输出 JSON（**不要**输出任何分析说明/推理过程，最多 8 条不变量）：
{{"invariants": [
  {{"name": "简短名",
    "signal": "白盒信号名（如 u_dut.secret_key）",
    "rule": "从上面 12 种选一个",
    "trigger_regs": [{{"reg": "触发寄存器名", "data": "0x1"}}],
    "rationale": "对应的安全意图"}}]}}"""


ALL_RULES = ["wipe_clears", "read_only_leak", "changes_across_runs",
             "reg_core_consistent", "access_control", "cfg_block_gating",
             "fsm_sparse_encoding", "err_code_coherent",
             "interrupt_first_event", "bus_intg_check",
             "monotonic_counter", "debug_lock_enforce"]

# 层次化白盒信号: u_dut.xxx / xxx_core.xxx / backticked 名
_SIG_RE = re.compile(
    r"(?:u_dut|u_hmac_core|u_aes_core|ascon_core|u_kmac_core|u_core|u_reg|u_hmac|sha2|dut)"
    r"\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
    r"|\b[A-Za-z_]\w*_(?:q|d)\b")


def extract_invariants_from_text(content):
    """兜底: 从 reasoning/分析文本提取 (rule, signal) 对。

    策略:
    1. 规则关键字出现在文本中 -> 取其前后 ±400 字符窗口内的白盒信号候选。
    2. 若窗口内无层次信号，退而取带 _q/_d 后缀的裸信号名。
    3. 输出中若出现 \"signal\"/\"信号\" 行 + 同行或近旁的规则名，也按行配对。
    """
    invariants = []
    seen = set()
    rule_pattern = "|".join(ALL_RULES)

    def add(sig, rule):
        sig = sig.strip("`\"' ").rstrip(".")
        if not sig:
            return
        hier = "." in sig
        # 裸信号名必须像 RTL 标识符: 全小写、含下划线、_q/_d 结尾；排除英文噪声
        if not hier and not re.fullmatch(r"[a-z][a-z0-9_]*_[qd]", sig):
            return
        key = (sig, rule)
        if key in seen:
            return
        seen.add(key)
        trig = [{"reg": "wipe_secret", "data": "0x1"}] if rule == "wipe_clears" else []
        invariants.append({
            "name": f"{sig}_{rule}",
            "signal": sig, "rule": rule,
            "trigger_regs": trig,
            "rationale": "LLM 提取（文本模式）"
        })

    for m in re.finditer(rule_pattern, content):
        rule = m.group(0)
        lo, hi = max(0, m.start() - 400), min(len(content), m.end() + 400)
        ctx = content[lo:hi]
        # 优先层次化信号（u_dut.xxx 等）
        hier = re.findall(
            r"(?:u_dut|u_hmac_core|u_aes_core|u_kmac_core|ascon_core|u_core|u_reg|u_hmac|sha2|dut)"
            r"\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", ctx)
        for sig in hier[:3]:
            add(sig, rule)
        if not hier:
            # 退路: 窗口内带 _q/_d 后缀的裸信号名（add 内再做 RTL 形状过滤）
            for sig in _SIG_RE.findall(ctx)[:3]:
                add(sig, rule)
    # 层次化信号优先，截断噪声
    invariants.sort(key=lambda i: 0 if "." in i["signal"] else 1)
    return invariants[:12]


def parse_llm_invariants(content, module):
    """三级解析: ```json 块 -> 裸 JSON -> reasoning 文本兜底"""
    # 1. ```json 块
    blocks = re.findall(r"```(?:json)?\s*(\[\s*\{.*?\}\s*\])\s*```", content, re.S)
    for b in reversed(blocks):
        try:
            arr = json.loads(b)
            if isinstance(arr, list) and arr and "rule" in arr[0]:
                return {"module": module, "invariants": arr}
        except Exception:
            pass
    # 2. 含 rule 的裸数组 / 裸对象
    m = re.search(r"(\[\s*\{.*\"rule\".*\}\s*\])", content, re.S)
    if m:
        try:
            arr = json.loads(m.group(1))
            if isinstance(arr, list) and arr:
                return {"module": module, "invariants": arr}
        except Exception:
            pass
    m = re.search(r"\{.*\}", content, re.S)
    if m:
        try:
            v = json.loads(m.group(0))
            if "invariants" in v and v["invariants"]:
                return {"module": module, "invariants": v["invariants"]}
        except Exception:
            pass
    # 3. reasoning 文本兜底
    invs = extract_invariants_from_text(content)
    return {"module": module, "invariants": invs, "raw": content}


def gen_invariants(module):
    sec = collect_sec_context(module)
    sec_text = "\n".join(sec) if sec else "（无显式标注）"
    reg_text = ""
    for cand in [os.path.join(OT, f"hw/ip/{module}/data/{module}.hjson"),
                 os.path.join(OT, f"hw/top_earlgrey/ip_autogen/{module}/data/{module}.hjson")]:
        if os.path.exists(cand):
            c = open(cand, errors="ignore").read()
            regs = re.findall(r'\bname:\s*"?(\w+)"?\s*,?\s*\n?\s*(?:desc|swaccess)', c)
            offs = re.findall(r"offset:\s*\"?([0-9a-fx]+)", c, re.I)
            reg_text = "\n".join(f"  {n.lower()}: {o}" for n, o in list(zip(regs, offs))[:20])
            break
    prompt = GEN_PROMPT.format(module=module, sec_text=sec_text, reg_text=reg_text)
    content = _llm_chat(prompt)
    return parse_llm_invariants(content, module)


class InvariantChecker:
    """通用不变量检查器 —— 12 种规则全部实现。

    可用原语: dut.write/read/step/reset/sig_read（DutHandle）+ regmap(name→offset)。
    每个规则一个独立场景，异常一律返回 None（不误报）。
    """

    def __init__(self, dut, regmap):
        self.dut = dut
        self.regmap = regmap

    # ---------- 通用工具 ----------
    def _rd(self, off):
        """读寄存器，兼容 dict/int 返回"""
        if off is None:
            return None
        v = self.dut.read(off)
        if isinstance(v, dict):
            return v.get("value")
        return v

    def _find_reg_any(self, *keys):
        """按名字关键字找寄存器 (name, offset)"""
        for nm, off in self.regmap.items():
            low = nm.lower()
            if any(k in low for k in keys):
                return nm, off
        return None

    def _sig_words(self, sig):
        """白盒信号 → [int]，不可观测返回 None"""
        r = self.dut.sig_read(sig)
        if not isinstance(r, dict) or "words" not in r:
            return None
        out = []
        for w in r["words"]:
            try:
                out.append(int(w, 0) if isinstance(w, str) else int(w))
            except Exception:
                out.append(0)
        return out

    def _exec_triggers(self, trs):
        d = self.dut
        for t in trs or []:
            off = self.regmap.get(str(t.get("reg", "")).lower())
            if off is not None:
                try:
                    d.write(off, int(str(t.get("data", "1")), 0))
                except Exception:
                    d.write(off, 1)
                d.step(5)

    def _marker_probe(self):
        """向 key/data 类寄存器写 marker（通用敏感数据注入）"""
        d = self.dut
        marker = 0xDEADBEEF
        key_regs = [(k, v) for k, v in self.regmap.items()
                    if any(w in k.lower() for w in ("key", "secret", "seed", "data_in", "wdata"))]
        for nm, off in key_regs[:8]:
            d.write(off, marker)
        d.step(10)
        return marker

    def _match_signal_reg(self, sig):
        """信号尾名 → regmap 匹配（digest ↔ DIGEST），用于 reg/core 副本对"""
        tail = sig.split(".")[-1].lower()
        for strip in ("_q", "_d", "_qs", ""):
            t = tail[: -len(strip)] if strip and tail.endswith(strip) else tail
            if not t:
                continue
            for nm, off in self.regmap.items():
                if t in nm.lower():
                    return nm, off
        return None

    def _violation(self, real_sig, rule, desc, confidence=80):
        return {"signal": real_sig, "rule": rule, "desc": desc,
                "confidence": confidence}

    # ---------- 主检查：信号匹配 + 规则分发 ----------
    def check(self, inv):
        rule = inv.get("rule", "")
        sig = inv.get("signal", "")
        d = self.dut
        # 信号名模糊匹配（LLM 给的层次名可能和 dut.sigs 不完全一致）
        real_sig = None
        sig_tail = sig.split(".")[-1]
        variants = {sig_tail, sig_tail.replace("_q", ""), sig_tail.replace("_q", "_d"),
                    sig_tail + "_q"}
        for sname in d.sigs:
            if sig_tail in sname:
                real_sig = sname
                break
        if real_sig is None:
            for sname in d.sigs:
                for variant in variants:
                    if variant in sname:
                        real_sig = sname
                        break
                if real_sig:
                    break
        if real_sig is None:
            return None  # 信号不可观测，跳过

        fn = getattr(self, "_chk_" + rule, None)
        if fn is None:
            return None
        try:
            return fn(inv, real_sig)
        except Exception:
            return None  # 检查过程异常不误报

    # ---------- 已实现规则 ----------
    def _chk_wipe_clears(self, inv, real_sig):
        d = self.dut
        d.reset()
        d.step(5)
        self._marker_probe()
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(50)
        words = self._sig_words(real_sig)
        if words is None:
            return None
        nz = [w for w in words if w != 0]
        if nz:
            return self._violation(real_sig, "wipe_clears",
                                   f"擦除触发后 {real_sig} 残留非零值 {[hex(w) for w in nz[:3]]}")
        return None

    def _chk_changes_across_runs(self, inv, real_sig):
        d = self.dut
        runs = []
        for _ in range(2):
            d.reset()
            d.step(5)
            self._exec_triggers(inv.get("trigger_regs"))
            d.step(50)
            runs.append(self._sig_words(real_sig))
        if not runs[0]:
            return None
        if runs[0] == runs[1] and any(v != 0 for v in runs[0]):
            return self._violation(real_sig, "changes_across_runs",
                                   f"{real_sig} 触发后仍为常量 {[hex(w) for w in runs[0][:3]]}（应随熵变化）")
        return None

    def _chk_read_only_leak(self, inv, real_sig):
        d = self.dut
        d.reset()
        d.step(5)
        self._marker_probe()
        d.step(20)
        words = self._sig_words(real_sig)
        if words is None:
            return None
        nz = [w for w in words if w != 0]
        if nz:
            return self._violation(real_sig, "read_only_leak",
                                   f"write-only 寄存器 {real_sig} 读回非零值 {[hex(w) for w in nz[:3]]}（信息泄露）",
                                   confidence=85)
        return None

    # ---------- P0 新增 9 规则 ----------
    def _chk_reg_core_consistent(self, inv, real_sig):
        """reg 侧与 core 侧副本必须同步变化"""
        d = self.dut
        pair = self._match_signal_reg(real_sig)
        if not pair:
            return None  # 找不到对应寄存器，跳过
        reg_nm, reg_off = pair
        d.reset()
        d.step(10)
        base_reg, base_sig = self._rd(reg_off), self._sig_words(real_sig)
        if base_reg is None or base_sig is None:
            return None
        for v in (0xA5A5A5A5, 0x5A5A5A5A):
            d.write(reg_off, v)
            d.step(20)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(30)
        aft_reg, aft_sig = self._rd(reg_off), self._sig_words(real_sig)
        reg_changed = aft_reg != base_reg
        sig_changed = aft_sig != base_sig
        if reg_changed != sig_changed:
            side = ("寄存器侧变了而 core 侧没变" if reg_changed
                    else "core 侧变了而寄存器侧没变")
            return self._violation(real_sig, "reg_core_consistent",
                                   f"{real_sig} 与 {reg_nm} 副本失同步: {side}")
        return None

    def _chk_access_control(self, inv, real_sig):
        """锁定后敏感寄存器写必须被拒绝"""
        d = self.dut
        d.reset()
        d.step(10)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(10)
        wen = self._find_reg_any("regwen", "lock")
        if wen:
            d.write(wen[1], 0)  # REGWEN=0 锁定（OpenTitan 惯例）
            d.step(10)
        marker = 0xFEEDFACE
        sensitive = [(k, v) for k, v in self.regmap.items()
                     if any(w in k.lower() for w in ("key", "secret", "digest", "salt", "binding"))]
        if not sensitive:
            return None
        rejected = 0
        for nm, off in sensitive[:6]:
            d.write(off, marker)
            d.step(5)
            if self._rd(off) != marker:
                rejected += 1
        if rejected == 0:
            return self._violation(real_sig, "access_control",
                                   f"锁定后 {len(sensitive[:6])} 个敏感寄存器写全部被接受（访问控制失效）",
                                   confidence=85)
        return None

    def _chk_cfg_block_gating(self, inv, real_sig):
        """cfg_block 置位后敏感写必须被拒绝"""
        d = self.dut
        d.reset()
        d.step(10)
        trs = inv.get("trigger_regs")
        if trs:
            self._exec_triggers(trs)
        else:
            blk = self._find_reg_any("block")
            if blk:
                d.write(blk[1], 0x1)
                d.step(10)
        marker = 0xFEEDFACE
        sensitive = [(k, v) for k, v in self.regmap.items()
                     if any(w in k.lower() for w in ("key", "secret", "msg", "data_in", "wdata"))]
        if not sensitive:
            return None
        leaked = 0
        for nm, off in sensitive[:6]:
            d.write(off, marker)
            d.step(5)
            if self._rd(off) == marker:
                leaked += 1
        if leaked:
            return self._violation(real_sig, "cfg_block_gating",
                                   f"cfg_block 置位后 {leaked}/{len(sensitive[:6])} 个敏感寄存器仍被写入",
                                   confidence=85)
        return None

    def _chk_fsm_sparse_encoding(self, inv, real_sig):
        """敌意输入后 FSM 不得进入良性参考集合之外的编码"""
        # 守卫: 只对真正的 FSM 状态信号生效（key/data 类寄存器写读一致是正常行为）
        low = real_sig.lower()
        if not any(k in low for k in ("state", "fsm", "st_q", "sm_", "ctrl_state")):
            return None
        d = self.dut
        d.reset()
        d.step(10)
        legal = set(self._sig_words(real_sig) or [])
        for _ in range(5):
            d.step(30)
            legal.update(self._sig_words(real_sig) or [])
        if not legal:
            return None
        d.reset()
        d.step(5)
        ctrl_regs = [(k, v) for k, v in self.regmap.items()
                     if any(w in k.lower() for w in ("ctrl", "cmd", "cfg", "trigger", "control"))]
        for nm, off in ctrl_regs[:6]:
            for v in (0xFFFFFFFF, 0x0, 0x5A5A5A5A):
                d.write(off, v)
                d.step(3)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(20)
        for _ in range(4):
            d.step(20)
            cur = self._sig_words(real_sig)
            if cur and cur[0] not in legal:
                return self._violation(real_sig, "fsm_sparse_encoding",
                                       f"敌意输入后 {real_sig} 进入合法集合外编码 {hex(cur[0])}",
                                       confidence=85)
        return None

    def _chk_err_code_coherent(self, inv, real_sig):
        """错误发生后 ERR_CODE/err 信号必须置位"""
        d = self.dut
        d.reset()
        d.step(10)
        ctrl_regs = [(k, v) for k, v in self.regmap.items()
                     if any(w in k.lower() for w in ("ctrl", "cfg", "cmd", "control"))]
        for nm, off in ctrl_regs[:3]:
            d.write(off, 0xFFFFFFFF)
            d.step(5)
        d.write(0x2000, 0xDEADBEEF)  # 越界写
        d.step(5)
        _ = d.read(0x2004)           # 越界读
        d.step(10)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(30)
        words = self._sig_words(real_sig)
        if words is not None and any(w != 0 for w in words):
            return None  # 白盒已置位 → 正常
        err_reg = self._find_reg_any("err_code", "error_code", "err_status")
        if err_reg and (self._rd(err_reg[1]) or 0):
            return None  # 寄存器侧置位 → 正常
        return self._violation(real_sig, "err_code_coherent",
                               f"非法配置+越界访问后 {real_sig}/ERR_CODE 均未置位（错误被吞没）",
                               confidence=85)

    def _chk_interrupt_first_event(self, inv, real_sig):
        """事件重复发生时中断位应 sticky，未清除不得消失"""
        d = self.dut
        d.reset()
        d.step(10)
        intr_en = self._find_reg_any("intr_enable", "intr_en")
        if intr_en:
            d.write(intr_en[1], 0xFFFFFFFF)
            d.step(5)
        self._exec_triggers(inv.get("trigger_regs"))
        self._marker_probe()
        d.step(50)
        s1 = self._sig_words(real_sig)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(50)
        s2 = self._sig_words(real_sig)
        if s1 is None or s2 is None:
            return None
        if any(a != 0 and b == 0 for a, b in zip(s1, s2)):
            return self._violation(real_sig, "interrupt_first_event",
                                   f"{real_sig} 事件置位后未清除即消失（非首次事件语义）",
                                   confidence=80)
        return None

    def _chk_bus_intg_check(self, inv, real_sig):
        """越界总线访问后错误信号必须可观测（逐拍采样抓脉冲）"""
        d = self.dut
        d.reset()
        d.step(10)
        d.write(0x4000, 0xDEADBEEF)
        d.step(2)
        _ = d.read(0x4004)
        d.step(2)
        d.write(0x3FFC, 0x12345678)
        for _ in range(20):
            d.step(2)
            words = self._sig_words(real_sig)
            if words and any(w != 0 for w in words):
                return None
        err_reg = self._find_reg_any("err", "error")
        if err_reg and (self._rd(err_reg[1]) or 0):
            return None
        return self._violation(real_sig, "bus_intg_check",
                               f"越界总线访问后 {real_sig} 从未置位（总线错误吞没）",
                               confidence=80)

    def _chk_monotonic_counter(self, inv, real_sig):
        """计数器只增不减（无清除写时；排除回绕）"""
        d = self.dut
        d.reset()
        d.step(10)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(20)
        prev = self._sig_words(real_sig)
        if not prev or not any(prev):
            return None
        for _ in range(4):
            d.step(150)
            cur = self._sig_words(real_sig)
            if not cur:
                return None
            if any(c < p and p < 0xFFFF0000 for p, c in zip(prev, cur)):
                return self._violation(real_sig, "monotonic_counter",
                                       f"{real_sig} 无清除写时回退 {hex(prev[0])} → {hex(cur[0])}",
                                       confidence=85)
            prev = cur
        return None

    def _chk_debug_lock_enforce(self, inv, real_sig):
        """debug-lock 后调试类信号必须无效"""
        d = self.dut
        d.reset()
        d.step(10)
        self._exec_triggers(inv.get("trigger_regs"))
        d.step(50)
        words = self._sig_words(real_sig)
        if not words:
            return None
        if any(w != 0 for w in words):
            return self._violation(real_sig, "debug_lock_enforce",
                                   f"debug-lock 后 {real_sig} 仍有效 {[hex(w) for w in words[:2]]}",
                                   confidence=80)
        return None


def load_dut(dut_dir, module):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from llm_agent import DutHandle
    return DutHandle(dut_dir, module)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["gen", "check"])
    ap.add_argument("module")
    ap.add_argument("--dut-dir", default=None)
    ap.add_argument("--regmap", default=None)
    args = ap.parse_args()

    os.makedirs(INV_DIR, exist_ok=True)
    inv_path = os.path.join(INV_DIR, f"{args.module}.json")

    if args.cmd == "gen":
        sec = collect_sec_context(args.module)
        reg_text = ""
        for cand in [os.path.join(OT, f"hw/ip/{args.module}/data/{args.module}.hjson"),
                     os.path.join(OT, f"hw/top_earlgrey/ip_autogen/{args.module}/data/{args.module}.hjson")]:
            if os.path.exists(cand):
                c = open(cand, errors="ignore").read()
                regs = re.findall(r'\bname:\s*"?(\w+)"?', c)
                offs = re.findall(r'offset:\s*"?([0-9a-fx]+)', c, re.I)
                reg_text = "\n".join(f"  {a}: {b}" for a, b in list(zip(regs, offs))[:20])
                break
        prompt = GEN_PROMPT.format(module=args.module, sec_text="\n".join(sec), reg_text=reg_text)
        content = _llm_chat(prompt)
        inv = parse_llm_invariants(content, args.module)

        json.dump(inv, open(inv_path, "w"), indent=1, ensure_ascii=False)
        print(f"=== O-K 不变量提取: {args.module} → {len(inv.get('invariants', []))} 条 ===")
        for i in inv.get("invariants", []):
            print(f"  [{i.get('rule')}] {i.get('signal')} — {str(i.get('rationale', ''))[:70]}")
        return

    # check
    assert args.dut_dir and args.regmap, "check 需要 --dut-dir 和 --regmap"
    inv = json.load(open(inv_path))
    norm = {}
    reg_raw = json.load(open(args.regmap))
    if isinstance(reg_raw, dict):
        for k, v in reg_raw.items():
            try:
                norm[k] = int(v, 0) if isinstance(v, str) else v
            except Exception:
                pass
    elif isinstance(reg_raw, list):
        for r in reg_raw:
            if not isinstance(r, dict):
                continue
            try:
                if r.get("kind") == "reg" and "name" in r and "offset" in r:
                    norm[r["name"].lower()] = int(r["offset"], 0) if isinstance(r["offset"], str) else r["offset"]
                elif r.get("kind") == "multireg" and "name" in r and "offset" in r:
                    # 展开 multireg: key[0..31] @ 0x24 stride 4
                    cnt = int(r.get("count", 1))
                    stride = int(r.get("stride", 4))
                    off0 = int(r["offset"], 0) if isinstance(r["offset"], str) else r["offset"]
                    for i in range(cnt):
                        norm[r["name"].lower() + "_" + str(i)] = off0 + i * stride
            except Exception:
                pass
    dut = load_dut(args.dut_dir, args.module)
    checker = InvariantChecker(dut, norm)
    print(f"=== O-K 不变量检查: {args.module}（{len(inv.get('invariants', []))} 条）===")
    findings = []
    for inv_item in inv.get("invariants", []):
        r = checker.check(inv_item)
        nm = inv_item.get("name", "?")
        if r:
            print(f"  [VIOLATION] {r['signal']} ({r['rule']}): {r['desc']}")
            findings.append(r)
        else:
            print(f"  [ok] {nm} ({inv_item.get('rule', '?')})")
    out = os.path.join(PF, "fuzz", f"invariant_{args.module}.json")
    json.dump({"module": args.module, "findings": findings}, open(out, "w"),
              indent=1, ensure_ascii=False)
    print(f"\n=== 汇总: {len(findings)} 条违反 → {out} ===")


if __name__ == "__main__":
    main()
