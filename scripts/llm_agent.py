#!/usr/bin/env python3
"""
HTFuzz Agent —— LLM 驱动的动态验证 agent（ReAct 循环）

LLM 作为策略层，工具 API 作为 action space：
  write(addr, data)   寄存器写
  read(addr)          寄存器读
  step(n)             推进时钟 n 拍
  sig_read(name)      观测白盒信号
  conclude(verdict)   结束并给出结论

用途：给定 fuzzing 候选（findings JSON），agent 自主设计寄存器序列动态验证，
      把 LLM 的静态推断变成可复现的动态证据。

用法:
  PF_LLM_BASE=http://127.0.0.1:18000/v1 PF_LLM_MODEL=zai-org/GLM-5.3-Flash \
  python3 llm_agent.py perip/hmac-ctf hmac traces/hmac_regmap.json \
      fuzz/discover_hmac_deep.json [--max-steps 30]
"""
import json, os, re, sys, ctypes, glob

PF = os.environ.get("PF_ROOT", "/workspace/pickerfuzz")
OT = os.environ.get("PF_TARGET_RTL", "/workspace/opentitan")


# ---------------------------------------------------------------------------
# 工具层：DUT API 封装（agent 的 action space）
# ---------------------------------------------------------------------------
class DutHandle:
    def __init__(self, dut_dir, module):
        objdir = os.path.abspath(os.path.join(dut_dir, "obj_so"))
        libs = sorted(f for f in os.listdir(objdir) if f.endswith(".so"))
        dut_libs = [f for f in libs if f.startswith("liblibpf")]
        api_libs = [f for f in libs if not f.startswith("liblibpf")]
        self.dut_lib = None
        for f in dut_libs:
            try:
                self.dut_lib = ctypes.CDLL(os.path.join(objdir, f), mode=ctypes.RTLD_GLOBAL)
                break
            except OSError:
                continue
        self.api = None
        for f in api_libs:
            try:
                self.api = ctypes.CDLL(os.path.join(objdir, f), mode=ctypes.RTLD_GLOBAL)
                break
            except OSError:
                continue
        if self.api is None:
            self.api = self.dut_lib
        if self.api is None:
            raise RuntimeError("no .so loaded")
        self._bind()
        self.sigs = {}
        for i in range(self.api.pf_sig_count()):
            name = self.api.pf_sig_name(i).decode()
            self.sigs[name] = self.api.pf_sig_words(i)
        self.api.pf_init(0)

    def _bind(self):
        a = self.api
        a.pf_init.argtypes = [ctypes.c_uint]; a.pf_init.restype = ctypes.c_int
        a.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        a.pf_write.restype = ctypes.c_int
        a.pf_read.argtypes = [ctypes.c_uint32]; a.pf_read.restype = ctypes.c_uint32
        a.pf_step.argtypes = [ctypes.c_int]
        a.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
        a.pf_sig_read.restype = ctypes.c_uint32
        a.pf_sig_count.restype = ctypes.c_int
        a.pf_sig_name.restype = ctypes.c_char_p
        a.pf_sig_words.restype = ctypes.c_int
        a.pf_reset.restype = None

    def write(self, addr, data):
        err = self.api.pf_write(addr, data, 0xF)
        return {"error": bool(err)}

    def read(self, addr):
        return {"value": self.api.pf_read(addr)}

    def step(self, n):
        self.api.pf_step(min(n, 10000))
        return {"ok": True}

    def sig_read(self, name):
        words = self.sigs.get(name)
        if words is None:
            # 模糊匹配
            cands = [s for s in self.sigs if name.lower() in s.lower()]
            if not cands:
                return {"error": f"signal '{name}' 不存在", "available": list(self.sigs)[:10]}
            name = cands[0]
            words = self.sigs[name]
        vals = [self.api.pf_sig_read(name.encode(), w) for w in range(words)]
        return {"name": name, "words": [hex(v) for v in vals]}

    def reset(self):
        self.api.pf_reset()
        return {"ok": True}


# ---------------------------------------------------------------------------
# Agent 层：ReAct 循环
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """你是硬件安全验证 agent，任务是**动态验证**一个 fuzzing 候选是否为真实硬件注入。

## 你的工具（每次输出一个 JSON 动作）
{{"action": "write", "addr": "0x28", "data": "0x10"}}   寄存器写（addr/data 十六进制）
{{"action": "read", "addr": "0x28"}}                     寄存器读
{{"action": "step", "n": 100}}                           推进时钟 n 拍
{{"action": "sig_read", "name": "u_dut.secret_key"}}     观测白盒信号
{{"action": "reset"}}                                    复位 DUT
{{"action": "conclude", "verdict": "confirmed|refuted|inconclusive", "evidence": "..."}}

## 可用白盒信号
{signals}

## 寄存器映射
{regmap}

## 验证策略
1. 先写标记值到敏感寄存器（如 KEY=0xDEADBEEF，含特征 bit）
2. 执行触发操作（如 WIPE/CLEAR/触发命令）
3. 推进时钟后观测白盒信号——标记值残留 = 注入确认
4. 对照实验：正常路径下同样操作，确认行为差异
5. 最多 {max_steps} 步，每步都要有明确目的

## 输出格式
只输出一个 JSON 动作，不要其他文本。"""


def llm_chat(prompt):
    import urllib.request
    # 清理代理环境变量（容器内 http_proxy 会劫持本地/内网端点）
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        os.environ.pop(k, None)
    os.environ["no_proxy"] = "*"
    base = os.environ.get("PF_LLM_BASE", "http://127.0.0.1:18000/v1")
    key = os.environ.get("PF_LLM_KEY", "")
    model = os.environ.get("PF_LLM_MODEL", "zai-org/GLM-5.3-Flash")
    maxtok = int(os.environ.get("PF_LLM_MAXTOK", "4096"))
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "temperature": 0, "max_tokens": maxtok}).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions",
                                 data=body, headers=headers)
    resp = json.load(urllib.request.urlopen(req, timeout=180))
    msg = resp["choices"][0]["message"]
    content = msg.get("content") or ""
    if not content.strip():
        content = msg.get("reasoning") or ""
    return content


def parse_action(content):
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r"\{[^{}]*\"action\"[^{}]*\}", content, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def run_agent(dut, regmap, finding, max_steps=25):
    signals = "\n".join(f"  {n} ({w} word)" for n, w in list(dut.sigs.items())[:15])
    regmap_s = "\n".join(f"  {k}: 0x{v:x}" for k, v in sorted(regmap.items(), key=lambda kv: kv[1])[:20])
    sys_prompt = SYSTEM_PROMPT.format(
        signals=signals, regmap=regmap_s, max_steps=max_steps)

    history = [f"## 待验证候选\n- 信号: {finding.get('signal')}\n"
               f"- oracle: {finding.get('oracle')}\n"
               f"- 现象: {finding.get('desc')}\n"
               f"- LLM 静态分析建议: {str(finding.get('llm_deep', {}).get('suggested_poc', ''))[:400]}"]

    trace = []
    for step_i in range(max_steps):
        prompt = sys_prompt + "\n\n" + "\n\n".join(history[-8:])
        try:
            content = llm_chat(prompt)
        except Exception as e:
            print(f"  [agent] LLM 调用失败: {e}")
            break
        act = parse_action(content)
        if act is None:
            print(f"  [agent] step{step_i}: 无法解析动作，终止")
            break
        action = act.get("action", "")
        if action == "conclude":
            print(f"  [agent] 结论: {act.get('verdict')} — {str(act.get('evidence'))[:150]}")
            trace.append({"step": step_i, "action": act})
            return act, trace
        # 执行动作
        obs = {}
        try:
            if action == "write":
                addr = int(str(act.get("addr", "0")), 0)
                data = int(str(act.get("data", "0")), 0)
                obs = dut.write(addr, data)
                obs["desc"] = f"write 0x{addr:x} <= 0x{data:x}"
            elif action == "read":
                addr = int(str(act.get("addr", "0")), 0)
                r = dut.read(addr)
                obs = {"desc": f"read 0x{addr:x} -> 0x{r['value']:x}", "value": r["value"]}
            elif action == "step":
                n = int(act.get("n", 10))
                dut.step(n)
                obs = {"desc": f"step {n}"}
            elif action == "sig_read":
                obs = dut.sig_read(str(act.get("name", "")))
                obs["desc"] = f"sig_read {obs.get('name', act.get('name'))} -> {obs.get('words', obs.get('error'))}"
            elif action == "reset":
                dut.reset()
                obs = {"desc": "reset"}
            else:
                obs = {"error": f"未知动作 {action}"}
        except Exception as e:
            obs = {"error": str(e)[:150]}
        print(f"  [agent] step{step_i}: {obs.get('desc', obs)}")
        history.append(f"### 动作\n```json\n{json.dumps(act)}\n```\n### 观测\n{json.dumps(obs, ensure_ascii=False)}")
        trace.append({"step": step_i, "action": act, "obs": obs})
    return {"verdict": "inconclusive", "evidence": "步数耗尽"}, trace


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    dut_dir, module, regmap_path, findings_path = sys.argv[1:5]
    max_steps = int(sys.argv[sys.argv.index("--max-steps") + 1]) if "--max-steps" in sys.argv else 25
    regmap_raw = json.load(open(regmap_path))
    norm = {}
    if isinstance(regmap_raw, dict):
        for k, v in regmap_raw.items():
            try:
                norm[k] = int(v, 0) if isinstance(v, str) else v
            except Exception:
                pass
    elif isinstance(regmap_raw, list):
        # hjson 提取格式: [{kind: reg, name: X, offset: N}, ...]
        for r in regmap_raw:
            if isinstance(r, dict) and r.get("kind") == "reg" and "name" in r and "offset" in r:
                try:
                    norm[r["name"].lower()] = int(r["offset"], 0) if isinstance(r["offset"], str) else r["offset"]
                except Exception:
                    pass
    data = json.load(open(findings_path))
    findings = data.get("findings", [])
    # 只验证 likely-bug / needs-review 候选
    targets = [f for f in findings
               if f.get("llm_deep", {}).get("verdict") in ("likely-bug", "needs-review")]
    # 去重（按信号）
    seen = set()
    uniq = []
    for f in targets:
        if f.get("signal") not in seen:
            seen.add(f.get("signal"))
            uniq.append(f)
    print(f"=== HTFuzz Agent: {module}（{len(uniq)} 个待验证候选, 最多 {max_steps} 步/个）===")
    dut = DutHandle(dut_dir, module)
    results = []
    for f in uniq:
        print(f"\n--- 验证: {f.get('signal')} ---")
        verdict, trace = run_agent(dut, norm, f, max_steps)
        results.append({"signal": f.get("signal"), "agent_verdict": verdict,
                        "trace": trace})
    out = findings_path.replace(".json", "_agent.json")
    data["agent_results"] = results
    json.dump(data, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\n=== 汇总 ===")
    from collections import Counter
    cnt = Counter(r["agent_verdict"].get("verdict") for r in results)
    print(dict(cnt))
    print(f"输出: {out}")


if __name__ == "__main__":
    main()
