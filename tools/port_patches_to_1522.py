#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 Florida 那套为 frida-core 15.x 写的补丁，重新锚定到 17.23.3 的源码上。

背景
----
上游 patches/ 里的 .patch 是 2021 年为 frida-core 15.x 生成的，git am 依赖
行号上下文。到 17.23.3 上下文已经漂了，第一个补丁就会 CONFLICT，
而 `set -e` 会让整个 job 直接失败 —— 白等一小时。

做法
----
不做 git am，改为在源码文本上做「子串/正则替换 + 插入」，因此与行号无关，
且幂等（重复执行会打印 SKIP 而不是重复插入）。

用法
----
    python3 port_patches_to_17233.py <frida 源码根目录>

返回码恒为 0：让 CI 继续 configure / make，不会因为某个补丁缺失而整条链路报废。
每步打印 [OK] / [SKIP] / [FAIL] / [NA]，最后输出摘要。
"""
import os
import re
import sys

ROOT = None   # frida-core 子项目根
GUM = None    # frida-gum 子项目根
RESULT = []


def resolve_roots(argument):
    """参数既可以是 frida 超级仓库根，也可以直接是 frida-core 根 —— 自动识别，
    避免把 ROOT 写错导致「全部 FAIL 却静默产出原版」这种坑。"""
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
    line = f"[{tag}] {name}"
    if detail:
        line += f" -- {detail}"
    print(line, flush=True)


def read(rel):
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8", newline="") as f:
        return f.read()


def write(rel, text):
    with open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="") as f:
        f.write(text)


def exists(rel):
    return os.path.isfile(os.path.join(ROOT, rel))


def sub_once(rel, old, new, name):
    """只替换第一次出现；已替换过就跳过（幂等）。"""
    if not exists(rel):
        log("NA", name, f"文件不存在，17.x 可能已移除: {rel}")
        return False
    text = read(rel)
    if new in text:
        log("SKIP", name, "已应用")
        return True
    if old not in text:
        log("FAIL", name, f"找不到锚点: {old!r}")
        return False
    write(rel, text.replace(old, new, 1))
    log("OK", name, rel)
    return True


# ------------------------------------------------------------------ 0001
# string_frida_rpc：把明文 "frida:rpc" 换成运行时 Base64 解码出来的串
def patch_0001():
    rel = "lib/base/rpc.vala"
    name = "0001 string_frida_rpc"
    if not exists(rel):
        log("NA", name, f"文件不存在: {rel}")
        return
    text = read(rel)

    if "getRpcStr" not in text:
        ctor = "\t\tpublic RpcClient (RpcPeer peer) {\n\t\t\tObject (peer: peer);\n\t\t}\n"
        method = (
            "\t\tpublic string getRpcStr(bool quote){\n"
            '\t\t\tstring result = (string) GLib.Base64.decode((string) GLib.Base64.decode("Wm5KcFpHRTZjbkJq"));\n'
            "\t\t\tif(quote){\n"
            '\t\t\t\treturn "\\"" + result + "\\"";\n'
            "\t\t\t}else{\n"
            "\t\t\t\treturn result;\n"
            "\t\t\t}\n"
            "\t\t}\n"
        )
        if ctor not in text:
            log("FAIL", name, "找不到 RpcClient 构造函数锚点")
            return
        text = text.replace(ctor, ctor + "\n" + method, 1)
        print("[OK] 0001 string_frida_rpc -- 插入 getRpcStr()", flush=True)
    else:
        log("SKIP", name, "getRpcStr 已存在")

    pairs = [
        ('add_string_value ("frida:rpc")', "add_string_value (getRpcStr(false))"),
        ('json.index_of ("\\"frida:rpc\\"")', "json.index_of (getRpcStr(true))"),
        ('type != "frida:rpc"', "type != getRpcStr(false)"),
    ]
    changed = False
    for old, new in pairs:
        if new in text:
            continue
        if old in text:
            text = text.replace(old, new, 1)
            changed = True
    if changed:
        write(rel, text)
        print("[OK] 0001 string_frida_rpc -- 替换 frida:rpc 三处", flush=True)


# ------------------------------------------------------------------ 0002
# frida_agent_so：agent 落地文件名加随机前缀
def patch_0002():
    rel = "src/linux/linux-host-session.vala"
    name = "0002 frida_agent_so"
    if not exists(rel):
        log("NA", name, f"文件不存在: {rel}")
        return
    text = read(rel)
    if "random_prefix" in text:
        log("SKIP", name, "已应用")
        return

    m = re.search(r'\n([ \t]*)([A-Za-z_][\w.]*)\s*=\s*new AgentDescriptor \(PathTemplate \("frida-agent-<arch>\.so"\),', text)
    if not m:
        log("FAIL", name, "找不到 AgentDescriptor 锚点")
        return
    ind, var = m.group(1), m.group(2)
    new = (
        f"\n{ind}var random_prefix = GLib.Uuid.string_random();\n"
        f'{ind}{var} = new AgentDescriptor (PathTemplate (random_prefix + "-<arch>.so"),'
    )
    text = text[:m.start()] + new + text[m.end():]

    n1 = text.count('new AgentResource ("frida-agent-arm.so"')
    n2 = text.count('new AgentResource ("frida-agent-arm64.so"')
    text = text.replace('new AgentResource ("frida-agent-arm.so"', 'new AgentResource (random_prefix + "-arm.so"')
    text = text.replace('new AgentResource ("frida-agent-arm64.so"', 'new AgentResource (random_prefix + "-arm64.so"')
    write(rel, text)
    log("OK", name, f"{rel} (AgentResource 改名 {n1}+{n2} 处)")


# ------------------------------------------------------------------ 0003 + 0004 + 0005 + 0007
# symbol_frida_agent_main：agent 入口符号改名；并把 lief 洗符号脚本一次性写成最终版
# （上游是 0003 建文件、0004/0005 追加线程名、0007 整体重写，这里合并成一步，避免级联冲突）
ANTI_ANTI = '''import lief
import sys
import random
import os

def log_color(msg):
    print(f"\\033[1;31;40m{msg}\\033[0m")

if __name__ == "__main__":
    input_file = sys.argv[1]
    random_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    log_color(f"[*] Patch frida-agent: {input_file}")
    binary = lief.parse(input_file)

    if not binary:
        log_color(f"[*] Not elf, exit")
        exit()

    random_name = "".join(random.sample(random_charset, 5))
    log_color(f"[*] Patch `frida` to `{random_name}`")

    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"

        if "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", random_name)

        if "FRIDA" in symbol.name:
            symbol.name = symbol.name.replace("FRIDA", random_name)

    # 字符串特征修改：等长反转，避免破坏偏移
    all_patch_string = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]
    for section in binary.sections:
        if section.name != ".rodata":
            continue
        for patch_str in all_patch_string:
            addr_all = section.search_all(patch_str)
            for addr in addr_all:
                patch = [ord(n) for n in list(patch_str)[::-1]]
                log_color(f"[*] Patching section name={section.name} offset={hex(section.file_offset + addr)} orig:{patch_str} new:{''.join(list(patch_str)[::-1])}")
                binary.patch_address(section.file_offset + addr, patch)

    binary.write(input_file)

    # 线程名随机化
    random_name = "".join(random.sample(random_charset, 11))
    log_color(f"[*] Patch `gum-js-loop` to `{random_name}`")
    os.system(f"sed -b -i s/gum-js-loop/{random_name}/g {input_file}")

    random_name = "".join(random.sample(random_charset, 5))
    log_color(f"[*] Patch `gmain` to `{random_name}`")
    os.system(f"sed -b -i s/gmain/{random_name}/g {input_file}")

    random_name = "".join(random.sample(random_charset, 5))
    log_color(f"[*] Patch `gdbus` to `{random_name}`")
    os.system(f"sed -b -i s/gdbus/{random_name}/g {input_file}")

    log_color(f"[*] Patch Finish")
'''

HOST_SESSIONS = [
    "src/agent-container.vala",
    "src/darwin/darwin-host-session.vala",
    "src/freebsd/freebsd-host-session.vala",
    "src/linux/linux-host-session.vala",
    "src/qnx/qnx-host-session.vala",
    "src/windows/windows-host-session.vala",
]
TESTS = ["tests/test-agent.vala", "tests/test-injector.vala"]


def patch_0003():
    # 先落脚本文件（内容一致时判定为 SKIP，保证幂等）
    target = os.path.join(ROOT, "src", "anti-anti-frida.py")
    try:
        same = os.path.isfile(target) and read("src/anti-anti-frida.py") == ANTI_ANTI
    except Exception:
        same = False
    if same:
        log("SKIP", "0003/0004/0005/0007 anti-anti-frida.py", "已是最终版")
    else:
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(ANTI_ANTI)
        log("OK", "0003/0004/0005/0007 anti-anti-frida.py", "写入最终版洗符号脚本")

    for rel in HOST_SESSIONS + TESTS:
        if not exists(rel):
            log("NA", f"0003 {rel}", "文件不存在，跳过")
            continue
        text = read(rel)
        if "frida_agent_main" not in text:
            log("SKIP", f"0003 {rel}", "无 frida_agent_main")
            continue
        write(rel, text.replace("frida_agent_main", "main"))
        log("OK", f"0003 {rel}", "入口符号改名 frida_agent_main -> main")


# ------------------------------------------------------------------ 0006
# protocol_unexpected_command：droidy 客户端在 17.23.3 已不存在，无需移植
def patch_0006():
    rel = "src/droidy/droidy-client.vala"
    if not exists(rel):
        log("NA", "0006 protocol_unexpected_command",
            "src/droidy/droidy-client.vala 在 17.23.3 已删除（droidy 只剩 axml/host-session/injector/jdwp），该特征随之消失，无需移植")
        return
    sub_once(rel,
             'throw new Error.PROTOCOL ("Unexpected command");',
             'break; // throw new Error.PROTOCOL ("Unexpected command");',
             "0006 protocol_unexpected_command")


# ------------------------------------------------------------------ 0008
# pool-frida：改进程名（影响 /proc/self/comm、ps 输出）
def patch_0008():
    rel = "src/frida-glue.c"
    name = "0008 pool-frida (prgname)"
    if not exists(rel):
        log("NA", name, f"文件不存在: {rel}")
        return
    text = read(rel)
    if "g_set_prgname" in text:
        log("SKIP", name, "已应用")
        return
    # 必须插在 gum_init() 之后 —— 因为 frida-gum 的 gum_init_embedded() 里
    # 自己会 g_set_prgname("frida")，插太早会被它盖掉（gum 那处另行处理）。
    m = re.search(r"\n([ \t]*)(if \(runtime == FRIDA_RUNTIME_OTHER\))", text)
    if not m:
        log("FAIL", name, "找不到 `if (runtime == FRIDA_RUNTIME_OTHER)` 锚点")
        return
    ind = m.group(1)
    text = text[:m.start()] + f'\n{ind}g_set_prgname ("ggbond");\n' + text[m.start():]
    write(rel, text)
    log("OK", name, rel + "（插在 gum_init 之后）")


# ---------------------------------------------------------------- gum
# frida-gum 的 gum_init_embedded() 里也有一次 g_set_prgname("frida")，
# 它会在 gum_init() 时覆盖掉 core 那次，所以必须一起改。
def patch_gum_prgname():
    name = "gum pool-frida (prgname)"
    if not GUM:
        log("NA", name, "找不到 frida-gum 子项目（只传了 frida-core 根？）")
        return
    rel = os.path.join(GUM, "gum", "gum.c")
    try:
        with open(rel, "r", encoding="utf-8", newline="") as f:
            text = f.read()
    except Exception as e:
        log("FAIL", name, repr(e))
        return
    if 'g_set_prgname ("ggbond")' in text:
        log("SKIP", name, "已应用")
        return
    if 'g_set_prgname ("frida")' not in text:
        log("FAIL", name, '找不到 g_set_prgname ("frida") 锚点')
        return
    with open(rel, "w", encoding="utf-8", newline="") as f:
        f.write(text.replace('g_set_prgname ("frida")', 'g_set_prgname ("ggbond")'))
    log("OK", name, rel)


# ------------------------------------------------------------------ 0009
# memfd-name-jit-cache：memfd_create 的 name 参数写死成 "jit-cache"
def patch_0009():
    sub_once("lib/base/linux.vala",
             "Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);",
             'Linux.syscall (LinuxSyscall.MEMFD_CREATE, "jit-cache", flags);',
             "0009 memfd-name-jit-cache")


# ------------------------------------------------------------------ 0010
# exec anti-anti-frida.py：把 agent 打进资源之后，跑一遍符号清洗
def patch_0010():
    rel = "src/embed-agent.py"
    name = "0010 exec anti-anti-frida.py"
    if not exists(rel):
        log("NA", name, f"文件不存在: {rel}")
        return
    text = read(rel)
    if "anti-anti-frida.py" in text:
        log("SKIP", name, "已应用")
        return
    m = re.search(r'([ \t]*)embedded_agent\.write_bytes\(b""\)\n', text)
    if not m:
        log("FAIL", name, "找不到 embed 锚点（embedded_agent.write_bytes）")
        return
    ind = m.group(1)
    block = (
        f'{ind}import os\n'
        f'{ind}custom_script=str(output_dir)+"/../../../../frida/subprojects/frida-core/src/anti-anti-frida.py"\n'
        f'{ind}return_code = os.system("python3 "+custom_script+" "+str(priv_dir / f"frida-agent-{{flavor}}.so"))\n'
        f'{ind}if return_code == 0:\n'
        f'{ind}    print("anti-anti-frida finished")\n'
        f'{ind}else:\n'
        f'{ind}    print("anti-anti-frida error. Code:", return_code)\n'
    )
    text = text[:m.end()] + block + text[m.end():]
    write(rel, text)
    log("OK", name, rel)


STEPS = [
    patch_0001,
    patch_0002,
    patch_0003,
    patch_0006,
    patch_gum_prgname,
    patch_0008,
    patch_0009,
    patch_0010,
]


def main():
    global ROOT, GUM
    if len(sys.argv) < 2:
        print("用法: port_patches_to_17233.py <frida 源码根目录 或 frida-core 根目录>")
        return 0
    arg = sys.argv[1]
    if not os.path.isdir(arg):
        print(f"[FAIL] 目录不存在: {arg}")
        return 0
    ROOT, GUM = resolve_roots(arg)
    print(f"=== Florida 魔改（17.23.3 适配版）坐标 ===")
    print(f"    frida-core: {ROOT}")
    print(f"    frida-gum : {GUM}")
    print(f"=== 开始应用 ===", flush=True)
    for fn in STEPS:
        try:
            fn()
        except Exception as e:
            log("FAIL", fn.__name__, repr(e))
    ok = sum(1 for t, _, _ in RESULT if t == "OK")
    skip = sum(1 for t, _, _ in RESULT if t == "SKIP")
    fail = sum(1 for t, _, _ in RESULT if t == "FAIL")
    na = sum(1 for t, _, _ in RESULT if t == "NA")
    print(f"=== 摘要: OK={ok} SKIP={skip} FAIL={fail} NA(17.x已无此文件)={na} ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
