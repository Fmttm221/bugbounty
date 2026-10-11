#!/usr/bin/env python3
"""Clash 节点管理（可选功能）：查看 / 切换 / 轮换

适配性设计:
    * Clash 是**可选**的。没有 Clash 也能正常用本 skill —— 只要 .env 里
      填好 BB_PROXY_OS_LOCAL / BB_PROXY_OS_KALI（任意 HTTP 代理都行）。
    * 检测不到 Clash 时**静默跳过**（退出码 0），不阻塞主流程。
    * 控制口端口是随机的，因此从配置动态读取；也可在 .env 显式指定。
    * 探测顺序: .env 的 CLASH_CONTROLLER -> 各常见 Clash 变体的配置路径。

用法:
    python scripts/clash.py status
    python scripts/clash.py list [组名]
    python scripts/clash.py switch <组名> <节点名>
    python scripts/clash.py next [组名]
    python scripts/clash.py ip
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from env import load  # noqa: E402

DEFAULT_GROUP = "GLOBAL"

# 常见 Clash 变体的配置路径（支持 ~ 与 %VAR% 展开）
CONFIG_CANDIDATES = [
    "~/.config/clash/config.yaml",                                       # Clash for Windows / ClashX
    "~/.config/clash-verge/config.yaml",                                 # Clash Verge
    "~/.config/clash-verge-rev/config.yaml",                             # Clash Verge Rev
    "%APPDATA%/io.github.clash-verge-rev.clash-verge-rev/config.yaml",   # Verge Rev (Windows)
    "%APPDATA%/clash-verge/config.yaml",                                 # Verge (Windows)
    "~/.config/mihomo/config.yaml",                                      # mihomo
    "~/.config/mihomo/config.yml",
    "~/.config/clash/config.yml",
    "/etc/mihomo/config.yaml",
]

SKIP_NODES = {"DIRECT", "REJECT", "Proxy", "🤖AI服务", "⚓️其他流量",
              "🍎苹果服务", "❌不代理", "GLOBAL"}


def _expand(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def _mixed_port_from_env() -> int:
    url = (load().get("BB_PROXY_OS_LOCAL") or "").strip()
    if url:
        try:
            return int(url.rsplit(":", 1)[-1].split("/")[0])
        except ValueError:
            pass
    return 7890


def clash_config():
    """返回 {config, controller, secret, mixed_port}；检测不到返回 None。"""
    cfg = load()
    ctrl = (cfg.get("CLASH_CONTROLLER") or "").strip()
    if ctrl:
        return {
            "config": "(来自 .env)",
            "controller": ctrl,
            "secret": (cfg.get("CLASH_SECRET") or "").strip(),
            "mixed_port": _mixed_port_from_env(),
        }
    for cand in CONFIG_CANDIDATES:
        p = _expand(cand)
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^external-controller:\s*(\S+)", text, re.M)
        if not m:
            continue
        s = re.search(r"^secret:\s*(\S+)", text, re.M)
        mp = re.search(r"^mixed-port:\s*(\d+)", text, re.M)
        return {
            "config": str(p),
            "controller": m.group(1).strip().strip("\"'"),
            "secret": s.group(1).strip().strip("\"'") if s else "",
            "mixed_port": int(mp.group(1)) if mp else _mixed_port_from_env(),
        }
    return None


def _no_clash() -> int:
    print("[clash] 未检测到 Clash —— 这是可选功能，已跳过。")
    print("        不用 Clash 也能正常使用本 skill，只需在 .env 填好：")
    print("          BB_PROXY_OS_LOCAL / BB_PROXY_OS_KALI （任意 HTTP 代理均可）")
    print("        如需启用节点切换，在 .env 填 CLASH_CONTROLLER / CLASH_SECRET")
    return 0


def api(path: str, method: str = "GET", body=None):
    cfg = clash_config()
    url = "http://" + cfg["controller"] + path
    headers = {}
    if cfg["secret"]:
        headers["Authorization"] = "Bearer " + cfg["secret"]
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 控制口必须直连
    try:
        with opener.open(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError("Clash API HTTP " + str(exc.code)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("连不上 Clash 控制口 " + cfg["controller"] + ": " + str(exc.reason)) from exc


def default_group() -> str:
    try:
        mode = str(api("/configs").get("mode", "")).lower()
    except RuntimeError:
        return DEFAULT_GROUP
    return "Proxy" if mode == "rule" else "GLOBAL"


def egress_ip() -> str:
    cfg = clash_config()
    if not cfg:
        return "(无 Clash)"
    proxy = "http://127.0.0.1:" + str(cfg["mixed_port"])
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    for url in ("http://members.3322.org/dyndns/getip", "https://api.ipify.org"):
        try:
            with opener.open(url, timeout=15) as resp:
                return resp.read().decode("utf-8", "replace").strip()
        except Exception:
            continue
    return "(取不到)"


def cmd_status(_args) -> int:
    cfg = clash_config()
    if not cfg:
        return _no_clash()
    proxies = api("/proxies").get("proxies", {})
    conf = api("/configs")
    print("配置      : " + cfg["config"])
    print("控制口    : " + cfg["controller"])
    print("代理端口  : " + str(cfg["mixed_port"]))
    print("模式      : " + str(conf.get("mode")))
    print("")
    for name in ("GLOBAL", "Proxy"):
        g = proxies.get(name)
        if g:
            print("  组 " + name + "  当前=" + str(g.get("now")) + "  可选=" + str(len(g.get("all", []))))
    for name in proxies:
        g = proxies[name]
        if g.get("type") in ("Selector",) and name not in ("GLOBAL", "Proxy"):
            print("  组 " + name + "  当前=" + str(g.get("now")) + "  可选=" + str(len(g.get("all", []))))
    print("")
    print("出口 IP   : " + egress_ip())
    return 0


def cmd_list(args) -> int:
    if not clash_config():
        return _no_clash()
    group = args.group or default_group()
    g = api("/proxies").get("proxies", {}).get(group)
    if not g:
        print("没有这个组: " + group, file=sys.stderr)
        return 1
    print("组 [" + group + "]  当前=" + str(g.get("now")) + "  共 " + str(len(g.get("all", []))))
    for i, node in enumerate(g.get("all", []), 1):
        print(("  *" if node == g.get("now") else "   ") + " " + str(i).rjust(2) + ". " + node)
    return 0


def cmd_switch(args) -> int:
    if not clash_config():
        return _no_clash()
    group, node = args.group, args.node
    g = api("/proxies").get("proxies", {}).get(group)
    if not g:
        print("没有这个组: " + group, file=sys.stderr)
        return 1
    if node not in g.get("all", []):
        print("组 " + group + " 里没有节点: " + node + "（用 list 查看）", file=sys.stderr)
        return 1
    api("/proxies/" + group, method="PUT", body={"name": node})
    print("已切换 " + group + " -> " + node)
    print("出口 IP: " + egress_ip())
    return 0


def cmd_next(args) -> int:
    if not clash_config():
        return _no_clash()
    group = args.group or default_group()
    g = api("/proxies").get("proxies", {}).get(group)
    if not g:
        print("没有这个组: " + group, file=sys.stderr)
        return 1
    nodes = [n for n in g.get("all", []) if n not in SKIP_NODES]
    if args.prefer:
        nodes = [n for n in nodes if args.prefer in n] or nodes
    if not nodes:
        print("组 " + group + " 没有可轮换的节点", file=sys.stderr)
        return 1
    now = g.get("now")
    idx = nodes.index(now) if now in nodes else -1
    nxt = nodes[(idx + 1) % len(nodes)]
    api("/proxies/" + group, method="PUT", body={"name": nxt})
    print("轮换 " + group + ": " + str(now) + " -> " + nxt)
    print("出口 IP: " + egress_ip())
    return 0


def cmd_ip(_args) -> int:
    if not clash_config():
        return _no_clash()
    print(egress_ip())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Clash 节点管理（可选）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("ip").set_defaults(fn=cmd_ip)
    p = sub.add_parser("list"); p.add_argument("group", nargs="?"); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("switch"); p.add_argument("group"); p.add_argument("node"); p.set_defaults(fn=cmd_switch)
    p = sub.add_parser("next"); p.add_argument("group", nargs="?")
    p.add_argument("--prefer", help="只在名字含该子串的节点里轮换，如 Lv3 / 香港")
    p.set_defaults(fn=cmd_next)
    args = ap.parse_args()
    try:
        return args.fn(args)
    except RuntimeError as exc:
        print("[clash] " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
