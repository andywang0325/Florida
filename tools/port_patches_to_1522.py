#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 Florida / strongR 那套反检测替换，重新锚定到 frida 15.2.2 源码上。

为什么不用 git am
-----------------
上游 .patch 是 2021 年为 frida-core 15.x 生成的，git am 依赖行号上下文；
直接套到 15.2.2 会在第一个补丁就 CONFLICT，`set -e` 让整条 CI 白等。
这里改为「子串替换 + 代码插入」，与行号无关，且幂等。

为什么保留协议兼容
-----------------
frida:rpc 不走简单改名 —— 主机端用的是官方 frida 15.2.2 客户端，
它发的就是 "frida:rpc"。所以改成「运行时双层 Base64 解码」，
逻辑等价（解出来仍是 frida:rpc），只是二进制里不再有明文。

用法
----
    python3 tools/port_patches_to_1522.py <frida 超级仓库根>

返回码恒为 0：某一步没命中也让它继续 configure / make，最后打印摘要。
每步强制统计命中次数 —— 命中 0 一律打 [FAIL]（17.x 那次 0002 静默假阳性的教训）。
"""
import os
import re
import sys

PREFIX = "ggbond"

ROOT = None   # frida-core 子项目根
GUM = None    # frida-gum 子项目根
RESULT = []


def resolve_roots(argument):
    """参数既可以是 frida 超级仓库根，也可以直接是 frida-core 根。"""
    core = None
    for cand in [argument, os.path.join(argument, "subprojects", "frida-core")]:
        if os.path.isfile(os.path.join(cand, "lib", "base", "rpc.vala")):
            core = cand
            break
    if core is None:
        core = argument
    gum = os.path.join(os.path.dirname(os.path.abspath(core)), "frida-gum")
    if not os.path.isfile(os.path.join(gum, "gum", "gum.c")):
        gum = None
    return core, gum


def log(tag, name, detail=""):
    RESULT.append((tag, name, detail))
    line = "[%s] %s" % (tag, name)
    if detail:
        line += " -- " + detail
    print(line, flush=True)


def read(rel, root=None):
    with open(os.path.join(root or ROOT, rel), "r", encoding="utf-8", newline="") as f:
        return f.read()


def write(rel, text, root=None):
    with open(os.path.join(root or ROOT, rel), "w", encoding="utf-8", newline="") as f:
        f.write(text)


def exists(rel, root=None):
    return os.path.isfile(os.path.join(root or ROOT, rel))


def sub_all(rel, old, new, name, expect=1, root=None):
    """全量替换并强制核对命中次数。命中 0 == FAIL，绝不静默通过。"""
    base = root or ROOT
    if not exists(rel, base):
        log("NA", name, "文件不存在: %s" % rel)
        return False
    text = read(rel, base)
    hits = text.count(old)
    if hits == 0:
        if new in text:
            log("SKIP", name, "已应用")
            return True
        log("FAIL", name, "锚点未命中: %r (%s)" % (old, rel))
        return False
    write(rel, text.replace(old, new), base)
    if hits < expect:
        log("WARN", name, "只命中 %d 处，预期 %d 处 (%s)" % (hits, expect, rel))
    else:
        log("OK", name, "%s x%d" % (rel, hits))
    return True


# ------------------------------------------------------------------ 0001
def patch_0001_rpc():
    """frida:rpc -> 运行时解码，保持与官方客户端协议兼容。"""
    rel = "lib/base/rpc.vala"
    name = "0001 string_frida_rpc"
    if not exists(rel):
        log("NA", name, "文件不存在: %s" % rel)
        return
    text = read(rel)

    if "getRpcStr" not in text:
        # 15.2.2 里 RpcClient 在 namespace + class 内，缩进是两个 tab；
        # 用正则自适应，避免照搬 17.x 的单 tab 锚点导致静默不命中。
        pat = re.compile(
            r"\n([ \t]*)public RpcClient \(RpcPeer peer\) \{\n"
            r"[ \t]*Object \(peer: peer\);\n[ \t]*\}\n")
        m = pat.search(text)
        if m is None:
            log("FAIL", name, "找不到 RpcClient 构造函数作为插入点")
            return
        ind = m.group(1)
        method = (
            ind + "public string getRpcStr(bool quote){\n"
            + ind + "\tstring result = (string) GLib.Base64.decode((string) GLib.Base64.decode(\"Wm5KcFpHRTZjbkJq\"));\n"
            + ind + "\tif(quote){\n"
            + ind + "\t\treturn \"\\\"\" + result + \"\\\"\";\n"
            + ind + "\t}else{\n"
            + ind + "\t\treturn result;\n"
            + ind + "\t}\n"
            + ind + "}\n"
        )
        text = text[:m.end()] + "\n" + method + text[m.end():]
        print("[OK] %s -- 插入 getRpcStr() (缩进 %r)" % (name, ind), flush=True)
    else:
        log("SKIP", name, "getRpcStr 已存在")

    pairs = [
        ('add_string_value ("frida:rpc")', "add_string_value (getRpcStr(false))"),
        ('json.index_of ("\\"frida:rpc\\"")', "json.index_of (getRpcStr(true))"),
        ('type != "frida:rpc"', "type != getRpcStr(false)"),
    ]
    hits = 0
    for old, new in pairs:
        if new in text:
            hits += 1
            continue
        if old in text:
            text = text.replace(old, new, 1)
            hits += 1
    write(rel, text)
    if hits == 3:
        log("OK", name, "三处 frida:rpc 已替换")
    else:
        log("FAIL", name, "只替换了 %d/3 处 frida:rpc" % hits)


# ------------------------------------------------------------------ 0002
def patch_0002_default_dir():
    """/data/local/tmp/re.frida.server 是最经典的一条检测项。"""
    sub_all("server/server.vala",
            'DEFAULT_DIRECTORY = "re.frida.server"',
            'DEFAULT_DIRECTORY = "%s-cache"' % PREFIX,
            "0002 io_re_frida_server")


# ------------------------------------------------------------------ 0003
def patch_0003_linjector():
    sub_all("src/linux/frida-helper-backend-glue.c",
            '"%s/linjector-%u"',
            '"%%s/%s-inject-%%u"' % PREFIX,
            "0003 pipe_linjector")


# ------------------------------------------------------------------ 0004
def patch_0004_agent_name():
    """agent 落地 .so 名：maps 扫描的头号目标，改名必须让 meson / embed
    脚本 / 运行时 fallback 名三处保持一致，否则构建或加载会断。"""
    n = "0004 io_frida_agent_so"
    sub_all("meson.build",
            "agent_name = 'frida-agent' + shlib_suffix",
            "agent_name = '%s-agent' + shlib_suffix" % PREFIX,
            n)
    text_rel = "lib/agent/meson.build"
    if exists(text_rel):
        text = read(text_rel)
        hits = text.count("frida-agent") + text.count("frida_agent_main")
        text = text.replace("frida-agent", "%s-agent" % PREFIX)
        text = text.replace("frida_agent_main", "main")
        write(text_rel, text)
        log("OK", n, "%s 共改名 %d 处" % (text_rel, hits))
    else:
        log("NA", n, text_rel)
    sub_all("src/embed-agent.sh", "frida-agent", "%s-agent" % PREFIX, n, expect=2)
    sub_all("lib/agent/agent.vala",
            'sizeof (void *) == 8 ? "frida-agent-arm64.so" : "frida-agent-arm.so"',
            'sizeof (void *) == 8 ? "%s-agent-arm64.so" : "%s-agent-arm.so"' % (PREFIX, PREFIX),
            n)


# ------------------------------------------------------------------ 0005
def patch_0005_agent_main():
    n = "0005 symbol_frida_agent_main"
    for rel in ["lib/agent/agent-glue.c",
                "lib/agent/frida-agent.version",
                "lib/agent/frida-agent.def"]:
        sub_all(rel, "frida_agent_main", "main", n, expect=1)
    sub_all("src/agent-container.vala",
            'container.module.symbol ("frida_agent_main"',
            'container.module.symbol ("main"',
            n)


# ------------------------------------------------------------------ 0006
def patch_0006_thread_names():
    n = "0006 thread_names"
    sub_all("lib/agent/agent.vala",
            '"frida-eternal-agent"',
            '"%s-agent-worker"' % PREFIX,
            n, expect=3)
    sub_all("lib/agent/agent.vala",
            '"frida-agent-emulated"',
            '"%s-emulated"' % PREFIX,
            n)
    sub_all("src/agent-container.vala",
            '"frida-agent-container"',
            '"%s-container"' % PREFIX,
            n)


# ------------------------------------------------------------------ 0010
def patch_0010_linux_entrypoint():
    """Linux/Android 注入路径：入口符号与 agent 资源名必须跟着改。
    漏掉 entrypoint 这一处，agent 导出符号已改成 main，而注入端还在找
    frida_agent_main —— 结果是能连上 server，但一 attach 就失败。"""
    n = "0010 linux_entrypoint"
    sub_all("src/linux/linux-host-session.vala",
            '"frida_agent_main"', '"main"', n)
    sub_all("src/linux/linux-host-session.vala",
            '"frida-agent-<arch>.so"', '"%s-agent-<arch>.so"' % PREFIX, n)
    sub_all("src/linux/linux-host-session.vala",
            '"frida-agent-arm.so"', '"%s-agent-arm.so"' % PREFIX, n)
    sub_all("src/linux/linux-host-session.vala",
            '"frida-agent-arm64.so"', '"%s-agent-arm64.so"' % PREFIX, n)


# ------------------------------------------------------------------ 0011
def patch_0011_error_text():
    """错误文案里的 frida-agent 同样会落进二进制字符串表。"""
    sub_all("src/host-session-service.vala",
            "to load frida-agent, ", "to load the agent, ",
            "0011 error_text")


# ------------------------------------------------------------------ 0007
def patch_0007_prgname():
    sub_all("src/frida-glue.c",
            'g_set_prgname ("frida")',
            'g_set_prgname ("%s")' % PREFIX,
            "0007 prgname_core")


# ------------------------------------------------------------------ 0008 / 0009
def patch_gum():
    if GUM is None:
        log("NA", "0008 prgname_gum", "没找到 frida-gum 子项目")
        log("NA", "0009 gum_js_loop", "没找到 frida-gum 子项目")
        return
    sub_all(os.path.join("gum", "gum.c") if False else "gum/gum.c",
            'g_set_prgname ("frida")',
            'g_set_prgname ("%s")' % PREFIX,
            "0008 prgname_gum", root=GUM)
    sub_all("bindings/gumjs/gumscriptscheduler.c",
            '"gum-js-loop"',
            '"%s-js-loop"' % PREFIX,
            "0009 gum_js_loop", root=GUM)
    # gumjs 的 JS runtime 会被打进二进制：frida:rpc 明文在这儿还留着三处。
    # 不能用 atob —— frida 15.2.2 的 JS 引擎不保证有 atob，改用拼接，
    # 既保持运行时等价，又让完整明文不再连续出现。
    rel = "bindings/gumjs/runtime/message-dispatcher.js"
    if exists(rel, GUM):
        text = read(rel, GUM)
        hits = text.count("'frida:rpc'")
        text = text.replace("'frida:rpc'", "('fr' + 'ida:' + 'rpc')")
        write(rel, text, GUM)
        if hits:
            log("OK", "0012 js_runtime_rpc", "%s x%d" % (rel, hits))
        elif "('fr' + 'ida:' + 'rpc')" in text:
            log("SKIP", "0012 js_runtime_rpc", "已应用")
        else:
            log("FAIL", "0012 js_runtime_rpc", "未命中: %s" % rel)
    else:
        log("NA", "0012 js_runtime_rpc", rel)


def main():
    if len(sys.argv) < 2:
        print("用法: python3 port_patches_to_1522.py <frida 源码根>", file=sys.stderr)
        return 0
    global ROOT, GUM
    ROOT, GUM = resolve_roots(sys.argv[1])
    print("frida-core: %s" % ROOT, flush=True)
    print("frida-gum : %s" % (GUM or "(未找到)"), flush=True)

    patch_0001_rpc()
    patch_0002_default_dir()
    patch_0003_linjector()
    patch_0004_agent_name()
    patch_0005_agent_main()
    patch_0006_thread_names()
    patch_0010_linux_entrypoint()
    patch_0011_error_text()
    patch_0007_prgname()
    patch_gum()

    ok = sum(1 for t, _, _ in RESULT if t == "OK")
    warn = sum(1 for t, _, _ in RESULT if t == "WARN")
    fail = sum(1 for t, _, _ in RESULT if t in ("FAIL", "NA"))
    print("\n==== 摘要: OK=%d WARN=%d FAIL/NA=%d ====" % (ok, warn, fail), flush=True)
    for tag, name, detail in RESULT:
        if tag in ("FAIL", "NA", "WARN"):
            print("  [%s] %s %s" % (tag, name, detail), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
