#!/usr/bin/env python3
"""
HTFuzz Environment 抽象接口 —— DUT 环境与 agent 逻辑解耦

Environment.execute(action) -> dict 是唯一接口。
DutEnvironment 实现 Verilator per-IP DUT 的 write/read/step/sig_read/reset。
支持多 DUT 实例（跨模块联动验证的基础）。

用法:
  from environments.dut_env import DutEnvironment
  env = DutEnvironment("perip/hmac-ctf", "hmac")
  env.execute({"action": "write", "addr": 0x20, "data": 0xDEADBEEF})
"""
import json, os, re, sys, ctypes


class BaseEnvironment:
    """环境抽象接口——子类实现 execute(action) -> dict"""

    def execute(self, action: dict) -> dict:
        raise NotImplementedError

    def get_signals(self) -> dict:
        """返回可观测信号 {name: words}"""
        raise NotImplementedError

    def serialize(self) -> dict:
        return {"environment_type": self.__class__.__name__}


class DutEnvironment(BaseEnvironment):
    """Verilator per-IP DUT 环境——封装 write/read/step/sig_read/reset"""

    def __init__(self, dut_dir: str, module: str):
        self.dut_dir = dut_dir
        self.module = module
        objdir = os.path.abspath(os.path.join(dut_dir, "obj_so"))
        libs = sorted(f for f in os.listdir(objdir) if f.endswith(".so"))
        dut_libs = [f for f in libs if f.startswith("liblibpf")]
        api_libs = [f for f in libs if not f.startswith("liblibpf")]
        self.dut_lib = None
        for f in dut_libs:
            try:
                self.dut_lib = ctypes.CDLL(os.path.join(objdir, f),
                                           mode=ctypes.RTLD_GLOBAL)
                break
            except OSError:
                continue
        self.api = None
        for f in api_libs:
            try:
                self.api = ctypes.CDLL(os.path.join(objdir, f),
                                       mode=ctypes.RTLD_GLOBAL)
                break
            except OSError:
                continue
        if self.api is None:
            self.api = self.dut_lib
        if self.api is None:
            raise RuntimeError(f"no .so loaded from {objdir}")
        self._bind()
        self.sigs = {}
        for i in range(self.api.pf_sig_count()):
            name = self.api.pf_sig_name(i).decode()
            self.sigs[name] = self.api.pf_sig_words(i)
        self.api.pf_init(0)

    def _bind(self):
        a = self.api
        a.pf_init.argtypes = [ctypes.c_uint]
        a.pf_init.restype = ctypes.c_int
        a.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        a.pf_write.restype = ctypes.c_int
        a.pf_read.argtypes = [ctypes.c_uint32]
        a.pf_read.restype = ctypes.c_uint32
        a.pf_step.argtypes = [ctypes.c_int]
        a.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
        a.pf_sig_read.restype = ctypes.c_uint32
        a.pf_sig_count.restype = ctypes.c_int
        a.pf_sig_name.restype = ctypes.c_char_p
        a.pf_sig_words.restype = ctypes.c_int
        a.pf_reset.restype = None

    def execute(self, action: dict) -> dict:
        """执行一个动作，返回观测结果"""
        kind = action.get("action", "")
        if kind == "write":
            addr = int(str(action.get("addr", "0")), 0)
            data = int(str(action.get("data", "0")), 0)
            err = self.api.pf_write(addr, data, 0xF)
            return {"error": bool(err), "addr": addr, "data": data}
        elif kind == "read":
            addr = int(str(action.get("addr", "0")), 0)
            val = self.api.pf_read(addr)
            return {"value": val, "addr": addr}
        elif kind == "step":
            n = min(int(action.get("n", 10)), 10000)
            self.api.pf_step(n)
            return {"stepped": n}
        elif kind == "sig_read":
            return self.sig_read(str(action.get("name", "")))
        elif kind == "reset":
            self.api.pf_reset()
            return {"reset": True}
        return {"error": f"unknown action: {kind}"}

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
            cands = [s for s in self.sigs if name.lower() in s.lower()]
            if not cands:
                return {"error": f"signal '{name}' not found",
                        "available": list(self.sigs)[:10]}
            name = cands[0]
            words = self.sigs[name]
        vals = [self.api.pf_sig_read(name.encode(), w) for w in range(words)]
        return {"name": name, "words": [hex(v) for v in vals]}

    def reset(self):
        self.api.pf_reset()
        return {"ok": True}

    def get_signals(self):
        return dict(self.sigs)

    def serialize(self):
        return {"environment_type": "DutEnvironment",
                "dut_dir": self.dut_dir, "module": self.module}
