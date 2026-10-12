#!/usr/bin/env python3
"""preflight —— 开工前本机环境自检

用法:
    python scripts/preflight.py

只检查本机侧。Kali 侧检查由 agent 经 kali MCP 执行，见 SKILL.md §1.4。
"""
from __future__ import annotations

import socket
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from env import ENV_FILE, ROOT, load  # noqa: E402

OK, BAD, WARN = "OK  ", "FAIL", "WARN"


def _tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _split(url: str):
    body = url.split("://", 1)[-1].split("/", 1)[0]
    if ":" in body:
        host, port = body.rsplit(":", 1)
        return host, int(port)
    return body, 80


def main() -> int:
    cfg = load()
    failures = []

    def report(tag: str, name: str, detail: str = "") -> None:
        print("[" + tag + "] " + name + ("  -- " + detail if detail else ""))
        if tag == BAD:
            failures.append(name)

    # 1) .env
    if ENV_FILE.exists():
        report(OK, ".env 存在", str(len(cfg)) + " 个变量")
    else:
        report(BAD, ".env 存在", "未找到 " + str(ENV_FILE))

    # 2) Clash 端口
    local = cfg.get("BB_PROXY_OS_LOCAL", "")
    proxy_alive = False
    if not local:
        report(BAD, "BB_PROXY_OS_LOCAL", "未配置")
    else:
        host, port = _split(local)
        proxy_alive = _tcp(host, port)
        report(OK if proxy_alive else BAD, "Clash 端口 " + host + ":" + str(port),
               "" if proxy_alive else "连不上，检查 Clash 是否运行")

    # 3) 国外出口实探
    if proxy_alive:
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": local, "https": local}))
            with opener.open("https://api.ipify.org", timeout=12) as resp:
                egress = resp.read().decode("utf-8", "replace").strip()
            report(OK, "国外出口", "出口 IP " + egress)
        except Exception as exc:
            report(WARN, "国外出口", "请求失败: " + str(exc))
    else:
        report(WARN, "国外出口", "跳过（代理不可用）")

    # 4) runs/ 可写
    runs = ROOT / "runs"
    try:
        runs.mkdir(parents=True, exist_ok=True)
        probe = runs / ".preflight-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        report(OK, "runs/ 可写", str(runs))
    except OSError as exc:
        report(BAD, "runs/ 可写", str(exc))

    # 5) 必填项
    for key in ("KALI_HOST", "KALI_USER"):
        report(OK if cfg.get(key) else BAD, key + " 已配置")

    # 6) provider key 覆盖率
    providers = ["QUAKE_API_KEY_1", "HUNTER_API_KEY", "ZOOMEYE_API_KEY",
                 "SHODAN_API_KEY", "CENSYS_API_KEY", "NETLAS_API_KEY",
                 "ABUSEIPDB_API_KEY", "IPINFO_API_KEY", "URLSCAN_API_KEY",
                 "OTX_API_KEY", "GITHUB_TOKEN"]
    ready = [k for k in providers if cfg.get(k)]
    report(OK if ready else WARN, "provider key",
           str(len(ready)) + "/" + str(len(providers)) + " 已配置")

    print()
    if failures:
        print("自检未通过: " + str(len(failures)) + " 项失败 -> " + ", ".join(failures))
        return 1
    print("自检通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
