#!/usr/bin/env python3
"""
全模块 fresh DUT 批建 —— 差分层的干净参照物

对每个 perip/<module>-ctf:
  1. hw 文件集从 opentitan-fresh 对应拷贝（缺件回退 CTF 版并记录——
     回退文件多为 TraceFuzz 生成 shim，需人工复核是否影响差分纯度）
  2. rtl_wrapper/ harness/ filelist.f 复用 CTF 版
  3. 容器内 verilator --lib-create pf_<module>_fresh + harness + .so
产物: perip/<module>-fresh/obj_so/libpf_<module>_fresh.so
日志: reports/fresh_build.log
"""
import os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

PF = os.environ.get("PF_ROOT",
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRESH_TREE = os.environ.get("PF_FRESH_RTL", "/Users/fantasy/Desktop/home/workspace/opentitan-fresh")
CTF_TREE = os.environ.get("PF_TARGET_RTL_HOST", "/Users/fantasy/Desktop/home/workspace/opentitan")
LOG = open(os.path.join(PF, "reports", "fresh_build.log"), "a")

SKIP_MODULES = {"hmac"}  # 已建成


def log(msg):
    print(msg, flush=True)
    LOG.write(msg + "\n")
    LOG.flush()


def copy_closure(module):
    """策略: CTF 闭包整体拷贝(保证可编译) → fresh 树同名 hw 文件覆盖(DUT 内容干净版)。
    fresh 树缺失的文件保留 CTF 版并记录(多为 shim/生成件, 差分纯度待人工复核)。"""
    ctf = f"{PF}/perip/{module}-ctf"
    dst = f"{PF}/perip/{module}-fresh"
    if os.path.exists(dst):
        shutil.rmtree(dst)
    # 1) CTF 整体拷贝(排除构建产物)
    shutil.copytree(ctf, dst,
                    ignore=shutil.ignore_patterns("obj_*", "*.o", "*.so", "*.a",
                                                  "__pycache__", "*.mk", "*.dat",
                                                  "*.gch", "*.d", "selftest*",
                                                  "pre_syn", "pre_sca", "syn",
                                                  "lint", "dv", "fpv", "doc"),
                    symlinks=True)
    # 2) fresh 树同名覆盖
    src_hw = os.path.join(FRESH_TREE, "hw")
    dst_hw = os.path.join(dst, "hw")
    fallbacks = []
    if os.path.isdir(src_hw):
        for root, dirs, files in os.walk(src_hw):
            for fn in files:
                if not fn.endswith((".sv", ".svh", ".svpp")):
                    continue
                rel = os.path.relpath(os.path.join(root, fn), src_hw)
                dstp = os.path.join(dst_hw, rel)
                if os.path.exists(dstp):
                    shutil.copy(os.path.join(root, fn), dstp)
                else:
                    fallbacks.append(rel + " (fresh 无此文件, 保留 CTF 版)")
    return fallbacks


TIMING_MODULES = {"keymgr"}  # wrapper 含事件控制(@), 需 --timing（C++ 驱动时钟, 无 #delay）

FRESH_COMPAT = {
    # keymgr: fresh keymgr.sv/kmac_if 需要新版 kmac_pkg 字段与带 SkewCycles 的 prim 组件
    "keymgr": ["hw/ip/prim/rtl/prim_alert_sender.sv",
               "hw/ip/prim/rtl/prim_diff_decode.sv",
               "hw/ip/kmac/rtl/kmac_pkg.sv",
               "hw/ip/kmac/rtl/sha3_pkg.sv",
               "hw/ip/prim/rtl/prim_sec_anchor_const.sv"],
}


def fresh_compat(module, dst):
    """按模块登记的 fresh 版本兼容层: 从 fresh 树覆盖指定依赖文件"""
    for f in FRESH_COMPAT.get(module, []):
        src = os.path.join(FRESH_TREE, f)
        dstp = os.path.join(dst, f)
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dstp), exist_ok=True)
            shutil.copy(src, dstp)
    if module == "keymgr":
        wp = os.path.join(dst, "rtl_wrapper", "keymgr_perip_tb.sv")
        if os.path.exists(wp):
            s = open(wp).read()
            s = s.replace("""  assign kmac_rsp.ready = 1'b1;
  assign kmac_rsp.done = 1'b1;
  assign kmac_rsp.digest_share0 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.digest_share1 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.error = 1'b0;""",
"""  // fresh kmac_pkg 的 app_rsp_t 字段名
  assign kmac_rsp.req_ready = 1'b1;
  assign kmac_rsp.rsp_valid = kmac_req.req_valid;
  assign kmac_rsp.rsp_finish = kmac_req.req_valid;
  assign kmac_rsp.digest_s0 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.digest_s1 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.error = 1'b0;""")
            open(wp, "w").write(s)


def overlay_own_rtl(module, dst):
    """回退策略 B: 仅覆盖 DUT 自身 rtl（hw/ip/<module>/rtl/）为 fresh 版,
    公共闭包保持 CTF 版——规避 fresh 包文件引入的未满足新依赖。
    覆盖范围=模块自身 RTL（per-IP 注入的主战场）; 共享文件注入不覆盖(已记录)。"""
    src_rtl = os.path.join(FRESH_TREE, "hw", "ip", module, "rtl")
    dst_rtl = os.path.join(dst, "hw", "ip", module, "rtl")
    n = 0
    if os.path.isdir(src_rtl) and os.path.isdir(dst_rtl):
        for root, dirs, files in os.walk(src_rtl):
            for fn in files:
                if not fn.endswith((".sv", ".svh", ".svpp")):
                    continue
                rel = os.path.relpath(os.path.join(root, fn), src_rtl)
                shutil.copy(os.path.join(root, fn), os.path.join(dst_rtl, rel))
                n += 1
    return n


def build_one(module):
    if f"{module}-fresh" in os.listdir(f"{PF}/perip") and \
       os.path.exists(f"{PF}/perip/{module}-fresh/obj_so/libpf_{module}_fresh.so"):
        log(f"[{module}] SKIP (已建成)")
        return module, "ok"
    fb = copy_closure(module)
    fresh_compat(module, f"{PF}/perip/{module}-fresh")
    # 无 filelist 的模块（老会话构建）→ 通用生成器推导
    if not os.path.exists(f"{PF}/perip/{module}-fresh/filelist.f"):
        g = subprocess.run([sys.executable,
                            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "gen_filelist.py"),
                            f"{PF}/perip/{module}-fresh"],
                           capture_output=True, text=True, timeout=120)
        if not os.path.exists(f"{PF}/perip/{module}-fresh/filelist.f"):
            log(f"[{module}] filelist 生成失败: {g.stderr[-200:]}")
            return module, "no_filelist"
        log(f"[{module}] filelist 由 gen_filelist 生成")
    if fb:
        log(f"[{module}] fresh 缺件回退 {len(fb)} 个: {fb[:3]}{'...' if len(fb) > 3 else ''}")
    harness_cpp = ""
    hd = f"{PF}/perip/{module}-fresh/harness"
    if os.path.isdir(hd):
        cpps = [f for f in os.listdir(hd) if f.endswith(".cpp")]
        if not cpps:
            log(f"[{module}] 无 harness cpp, SKIP")
            return module, "no_harness"
        harness_cpp = cpps[0]
    wrapper_sv = f"{PF}/perip/{module}-fresh/rtl_wrapper/{module}_perip_tb.sv"
    if not os.path.exists(wrapper_sv):
        log(f"[{module}] 无 wrapper {wrapper_sv}, SKIP")
        return module, "no_wrapper"
    extra = "--timing" if module in TIMING_MODULES else ""
    cmd = f'''
export PATH=/tools/verilator/v5.050/bin:$PATH
cd /workspace/HTFuzz/perip/{module}-fresh
rm -rf obj_so
verilator --cc --lib-create pf_{module}_fresh --top-module {module}_perip_tb \
  -f filelist.f --Mdir obj_so -CFLAGS -fPIC -LDFLAGS -fPIC -Wno-fatal {extra} -j 10 \
  2>&1 | grep -E "%Error" | head -4
cd obj_so
python3 /workspace/HTFuzz/scripts/gen_bindings.py .. 2>&1 | head -2
g++ -c -fPIC -fcoroutines -O2 -I/tools/verilator/v5.050/share/verilator/include \
  -I/tools/verilator/v5.050/share/verilator/include/vltstd -I. \
  ../harness/{harness_cpp} -o pf_fresh_harness.o 2>&1 | head -3
make -f V{module}_perip_tb.mk libpf_{module}_fresh.a libpf_{module}_fresh.so \
  VK_USER_OBJS=pf_fresh_harness.o -j 10 2>&1 | grep -E "%Error|error:" | head -4
ls libpf_{module}_fresh.so >/dev/null 2>&1 && echo FRESH_BUILD_OK
'''
    for attempt in ("full-overlay", "own-rtl-only"):
        # MODMISSING 自动补件（最多 4 轮）: 从 fresh 树找缺失模块拷入闭包
        for rnd in range(4):
            p = subprocess.run(["docker", "exec", "opentitan-env-fwt", "bash", "-c", cmd],
                               capture_output=True, text=True, timeout=1800)
            out = p.stdout + p.stderr
            if "FRESH_BUILD_OK" in out:
                break
            missing = sorted(set(re.findall(
                r"Cannot find file containing module: '([^']+)'", out)))
            added = 0
            # PINNOTFOUND(参数/引脚不存在) → 实例化的子模块文件过旧, 从 fresh 树覆盖
            for mfile, mline, pn in sorted(set(re.findall(
                    r"(hw/[^: ]+\.sv):(\d+):\d+: (?:Parameter|Pin) not found: '(\w+)'", out))):
                parent = os.path.join(f"{PF}/perip/{module}-fresh", mfile)
                if not os.path.exists(parent):
                    continue
                plines = open(parent, errors="ignore").read().splitlines()
                # 从报错行向上找实例化语句的模块类型名
                modtype = None
                for ln in range(int(mline) - 1, max(0, int(mline) - 12), -1):
                    mm = re.match(r"\s*(\w+)\s*(?:#\s*\(|\w)", plines[ln - 1])
                    if mm and mm.group(1) not in (pn,):
                        cand = mm.group(1)
                        if not cand.startswith(("logic", "assign", "wire", "reg")):
                            modtype = cand
                            break
                if not modtype:
                    continue
                hit = None
                for root2, dirs2, files2 in os.walk(FRESH_TREE):
                    if modtype + ".sv" in files2:
                        hit = os.path.join(root2, modtype + ".sv")
                        break
                if hit:
                    rel = os.path.relpath(hit, FRESH_TREE)
                    dstp = os.path.join(f"{PF}/perip/{module}-fresh", rel)
                    os.makedirs(os.path.dirname(dstp), exist_ok=True)
                    shutil.copy(hit, dstp)
                    log(f"[{module}] PINNOTFOUND 补件: {rel} ({modtype}.{pn})")
                    added += 1
            if not missing:
                break
            for modname in missing:
                if "/" in modname:
                    # 路径式: 检查闭包内文件是否存在, 缺则从 fresh 树补
                    rel = modname
                    dstp = os.path.join(f"{PF}/perip/{module}-fresh", rel)
                    if not os.path.exists(dstp):
                        srcp = os.path.join(FRESH_TREE, rel)
                        if os.path.exists(srcp):
                            os.makedirs(os.path.dirname(dstp), exist_ok=True)
                            shutil.copy(srcp, dstp)
                            added += 1
                    continue
                hits = []
                for root, dirs, files in os.walk(FRESH_TREE):
                    if modname + ".sv" in files:
                        hits.append(os.path.join(root, modname + ".sv"))
                        break
                if hits:
                    rel = os.path.relpath(hits[0], FRESH_TREE)
                    dstp = os.path.join(f"{PF}/perip/{module}-fresh", rel)
                    os.makedirs(os.path.dirname(dstp), exist_ok=True)
                    shutil.copy(hits[0], dstp)
                    # 若 filelist 未含该文件 → 追加到 wrapper 之前
                    fl = f"{PF}/perip/{module}-fresh/filelist.f"
                    lines = open(fl).read().rstrip("\n").split("\n")
                    tail = [l for l in lines if "rtl_wrapper/" in l]
                    body = [l for l in lines if "rtl_wrapper/" not in l]
                    if rel not in body:
                        body.append(rel)
                        open(fl, "w").write("\n".join(body + tail) + "\n")
                    added += 1
            log(f"[{module}] MODMISSING 轮{rnd}: 补 {added}/{len(missing)} ({', '.join(missing[:4])})")
            if added == 0:
                break
        if "FRESH_BUILD_OK" in out:
            log(f"[{module}] BUILD OK ({attempt})")
            return module, "ok"
        if attempt == "full-overlay":
            # 回退策略 B: 公共闭包回 CTF 版, 仅 DUT 自身 rtl 保持 fresh 覆盖
            log(f"[{module}] 全量覆盖失败 → 回退 own-rtl-only")
            ctf_hw = f"{PF}/perip/{module}-ctf/hw"
            dst_hw = f"{PF}/perip/{module}-fresh/hw"
            shutil.rmtree(dst_hw)
            shutil.copytree(ctf_hw, dst_hw,
                            ignore=shutil.ignore_patterns("pre_syn", "pre_sca", "syn",
                                                          "lint", "dv", "fpv", "doc"),
                            symlinks=True)
            n = overlay_own_rtl(module, f"{PF}/perip/{module}-fresh")
            fresh_compat(module, f"{PF}/perip/{module}-fresh")
            log(f"[{module}] own-rtl 覆盖 {n} 个文件 + compat 重应用")
            g = subprocess.run([sys.executable,
                                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "gen_filelist.py"),
                                f"{PF}/perip/{module}-fresh"],
                               capture_output=True, text=True, timeout=120)
            log(f"[{module}] 回退后 filelist 重新生成")
    err = [l for l in out.splitlines() if "%Error" in l][:3]
    log(f"[{module}] BUILD FAIL: {' | '.join(err) or out[-200:]}")
    return module, "fail: " + ("; ".join(err) or out[-120:])


def main():
    mods = sys.argv[1:]
    if not mods:
        mods = sorted(d[:-4] for d in os.listdir(f"{PF}/perip")
                      if d.endswith("-ctf") and os.path.isdir(f"{PF}/perip/{d}/rtl_wrapper"))
        mods = [m for m in mods if m not in SKIP_MODULES]
    log(f"=== fresh 批建开始: {len(mods)} 模块 ===")
    results = {}
    workers = 2 if len(mods) > 1 else 1
    with ThreadPoolExecutor(max_workers=2 if len(mods) > 1 else 1) as ex:
        for module, status in ex.map(build_one, mods):
            results[module] = status
            ok = sum(1 for v in results.values() if v == "ok")
            log(f"--- 进度 {len(results)}/{len(mods)} (成功 {ok}) ---")
    ok = [m for m, v in results.items() if v == "ok"]
    fail = {m: v for m, v in results.items() if v != "ok"}
    log(f"=== 完成: 成功 {len(ok)}  失败 {len(fail)} ===")
    for m, v in fail.items():
        log(f"  FAIL {m}: {v[:150]}")
    json.dump(results, open(f"{PF}/fuzz/fresh_build_status.json", "w"), indent=1)


import json
if __name__ == "__main__":
    main()
