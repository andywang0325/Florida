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

# agent 入口符号的新名字。
# 不能叫 "main"：clang 把 main 当保留入口函数，签名不符是硬错误
#   error: first parameter of 'main' (argument count) must be of type 'int'
# 且 -Wmain 关不掉（Florida 之所以能用 main，是因为它压根不在源码层改名，
# 而是构建后用 lief 改 .so 的符号表 —— 见文件末尾说明）。
# 用 "agent_main"：编译期完成、不含 frida、也不是魔改版常见的 "main" 特征。
AGENT_ENTRY = "agent_main"

ROOT = None   # frida-core 子项目根
GUM = None    # frida-gum 子项目根
TOP = None    # frida 超级仓库根（Makefile.linux.mk 在这一层）
RESULT = []

CORE_MARKER = os.path.join("lib", "base", "rpc.vala")
GUM_MARKER = os.path.join("gum", "gum.c")


def resolve_roots(argument):
    """参数既可以是 frida 超级仓库根，也可以直接是 frida-core 根。

    坑（2026-10 首次跑 CI 就是栽在这）：frida 的目录布局改过 ——
        15.x : <super>/frida-core           <super>/frida-gum          （顶层）
        16+  : <super>/subprojects/frida-core   .../subprojects/frida-gum
    只认 subprojects/ 的话，15.2.2 上会全部退化成 NA 且静默不报错。
    所以两种布局都要探测，并把超级仓库根一起返回。
    """
    arg = os.path.abspath(argument)

    core = None
    for cand in [os.path.join(arg, "subprojects", "frida-core"),
                 os.path.join(arg, "frida-core"),
                 arg]:
        if os.path.isfile(os.path.join(cand, CORE_MARKER)):
            core = cand
            break
    if core is None:
        core = arg

    gum = None
    for cand in [os.path.join(os.path.dirname(core), "frida-gum"),
                 os.path.join(arg, "subprojects", "frida-gum"),
                 os.path.join(arg, "frida-gum")]:
        if os.path.isfile(os.path.join(cand, GUM_MARKER)):
            gum = cand
            break

    if os.path.isdir(os.path.join(arg, "frida-core")) or \
       os.path.isdir(os.path.join(arg, "subprojects")):
        top = arg
    else:
        top = os.path.dirname(core)
    return core, gum, top


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
    """agent 落到目标进程 tempdir 时的文件名 —— maps 扫描的头号目标。

    采用 Florida 的做法：**运行时随机 UUID**，而不是在 meson 层把 agent 改名。
    为什么不能在 meson 层改名（15.2.2 上的三个连环坑）：
      1. shared_library('frida-agent') 一改，vala 生成的头文件就跟着变成
         <新名>.h，而 lib/agent/agent-glue.c 里写死 #include "frida-agent.h"；
      2. lib/agent/meson.build 引用同名的 frida-agent.def / frida-agent.version，
         只改文本、不重命名磁盘文件，meson 直接报「文件不存在」；
      3. Makefile.linux.mk 里 -Dagent_modern=.../lib/agent/frida-agent.so 是硬编码的。
    随机化只动「运行时文件名」，构建链路一个字都不用碰，风险最小。
    """
    n = "0004 agent_runtime_name"
    rel = "src/linux/linux-host-session.vala"
    if not exists(rel):
        log("NA", n, "文件不存在: %s" % rel)
        return

    text = read(rel)
    if "random_prefix" in text:
        log("SKIP", n, "已应用")
    else:
        pat = re.compile(
            r'(\n([ \t]*)agent = new AgentDescriptor \(PathTemplate \("frida-agent-<arch>\.so"\),)')
        m = pat.search(text)
        if m is None:
            log("FAIL", n, "找不到 AgentDescriptor 锚点: %s" % rel)
            return
        ind = m.group(2)
        head = text[:m.start(1)]
        tail = text[m.end(1):]
        text = (head
                # 用裸 Uuid.string_random ()：15.2.2 自身在 rpc.vala / session.vala
                # 里就是这么用的，绑定一定存在。
                + "\n" + ind + "var random_prefix = Uuid.string_random ();\n"
                + ind + 'agent = new AgentDescriptor (PathTemplate (random_prefix + "-<arch>.so"),'
                + tail)
        for old, new in [
            ('new AgentResource ("frida-agent-arm.so"',
             'new AgentResource (random_prefix + "-arm.so"'),
            ('new AgentResource ("frida-agent-arm64.so"',
             'new AgentResource (random_prefix + "-arm64.so"'),
        ]:
            if old not in text:
                log("FAIL", n, "锚点未命中: %r" % old)
                return
            text = text.replace(old, new, 1)
        write(rel, text)
        log("OK", n, "%s 运行时名改为随机 UUID" % rel)

    # agent 自己拼 emulated agent 路径时那个 "frida-agent-arm64.so" 字面量，
    # 会随 agent .so 一起被加载进目标进程，顺手去掉：改由自身文件名推导。
    rel2 = "lib/agent/agent.vala"
    if not exists(rel2):
        log("NA", n, "文件不存在: %s" % rel2)
        return
    t2 = read(rel2)
    old2 = 'sizeof (void *) == 8 ? "frida-agent-arm64.so" : "frida-agent-arm.so"'
    if old2 in t2:
        new2 = ('Path.get_basename (agent_path)'
                '\n\t\t\t\t\t.replace ("-64.so", "-arm64.so")'
                '\n\t\t\t\t\t.replace ("-32.so", "-arm.so")')
        write(rel2, t2.replace(old2, new2, 1))
        log("OK", n, "%s 去掉 frida-agent 字面量" % rel2)
    elif "frida-agent-arm64" not in t2:
        log("SKIP", n, "agent.vala 已处理")
    else:
        log("FAIL", n, "agent.vala 锚点未命中")


# ------------------------------------------------------------------ 0005
def patch_0005_agent_main():
    n = "0005 symbol_frida_agent_main"
    for rel in ["lib/agent/agent-glue.c",
                "lib/agent/frida-agent.version",
                "lib/agent/frida-agent.def"]:
        sub_all(rel, "frida_agent_main", AGENT_ENTRY, n, expect=1)
    sub_all("src/agent-container.vala",
            'container.module.symbol ("frida_agent_main"',
            'container.module.symbol ("%s"' % AGENT_ENTRY,
            n)
    # —— 定义侧（最容易漏，漏了必炸）——
    # 15.2.2 的 agent 入口在 agent.vala 第 2 行写作
    #     namespace Frida.Agent { public void main (...) }
    # C 符号 frida_agent_main 是 valac 按「namespace 前缀 + 方法名」拼出来的，
    # 源码里根本没有这个字面量，grep 不到。改调用方/导出脚本而不改这里，
    # 链接阶段就是 ld: error: undefined symbol: <新名>。
    # 用 [CCode (cname = ...)] 覆盖 valac 生成的 C 函数名。
    # 名字必须避开 "main"（clang 会按宿主入口函数校验签名并报 error）。
    sub_all("lib/agent/agent.vala",
            "\tpublic void main (string agent_parameters,",
            '\t[CCode (cname = "%s")]\n' % AGENT_ENTRY +
            "\tpublic void main (string agent_parameters,",
            n)
    # darwin 分支专用（Android 走不到，但保持一致，避免以后编 macOS 时漏）
    sub_all("lib/agent/meson.build",
            "-Wl,-exported_symbol,_frida_agent_main",
            "-Wl,-exported_symbol,_%s" % AGENT_ENTRY, n)


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
    # 注意：agent 资源名那两处已由 0004 改成随机 UUID，这里只管入口符号。
    sub_all("src/linux/linux-host-session.vala",
            '"frida_agent_main"', '"%s"' % AGENT_ENTRY, n)


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
    # 不能用 atob —— frida 15.2.2 的 JS 引擎不保证有 atob。
    # 也不能用 ('fr' + 'ida:' + 'rpc') —— 常量表达式会被 quickjs 折叠回
    # 完整明文（实测产物里仍剩 2 处完整 'frida:rpc'，多半就是这么来的）。
    # 改成「函数内对局部变量累加」：涉及变量，不会被常量折叠。
    rel = "bindings/gumjs/runtime/message-dispatcher.js"
    helper = ("var _rpcTag = function () {\n"
              "  var s = 'fr';\n"
              "  s += 'ida:';\n"
              "  s += 'rpc';\n"
              "  return s;\n"
              "};\n")
    if exists(rel, GUM):
        text = read(rel, GUM)
        hits = text.count("'frida:rpc'")
        if hits:
            text = text.replace("'frida:rpc'", "_rpcTag()")
            if "_rpcTag = function" not in text:
                text = helper + text
            write(rel, text, GUM)
            log("OK", "0012 js_runtime_rpc", "%s x%d（含辅助函数）" % (rel, hits))
        elif "_rpcTag()" in text:
            log("SKIP", "0012 js_runtime_rpc", "已应用")
        else:
            log("FAIL", "0012 js_runtime_rpc", "未命中: %s" % rel)
    else:
        log("NA", "0012 js_runtime_rpc", rel)


def main():
    if len(sys.argv) < 2:
        print("用法: python3 port_patches_to_1522.py <frida 源码根>", file=sys.stderr)
        return 0
    global ROOT, GUM, TOP
    ROOT, GUM, TOP = resolve_roots(sys.argv[1])
    print("super     : %s" % TOP, flush=True)
    print("frida-core: %s" % ROOT, flush=True)
    print("frida-gum : %s" % (GUM or "(未找到)"), flush=True)
    if not os.path.isfile(os.path.join(ROOT, CORE_MARKER)):
        print("\n[FATAL] 没找到 frida-core（判据: %s）。" % CORE_MARKER, flush=True)
        print("        当前目录下有: %s" % sorted(os.listdir(sys.argv[1]))[:20], flush=True)
        print("        请先确认子模块已初始化：git submodule update --init", flush=True)

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

    # 2026-10 首次 CI 的教训：脚本全部 NA 时仍然返回 0，于是 CI 继续往下编，
    # 白白跑 20 分钟产出一个【原版】server（特征一个没改，ggbond 计数为 0）。
    # 所以默认「严格模式」：只要有一处 FAIL/NA 就返回 1，让 CI 立刻停。
    # 需要放行时用 FRIDA_PATCH_STRICT=0。
    if fail > 0 and os.environ.get("FRIDA_PATCH_STRICT", "1") != "0":
        print("\n[FATAL] 有 %d 处补丁未命中，终止构建。" % fail, flush=True)
        print("        若确认可以忽略，设 FRIDA_PATCH_STRICT=0 再跑。", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
