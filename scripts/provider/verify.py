#!/usr/bin/env python3
"""验证各 provider 的 key 与连通性

原则：**优先打不消耗额度的账号/配额接口**，只在没有这类接口时才做最小查询。

用法:
    python scripts/provider/verify.py                # 全部
    python scripts/provider/verify.py shodan otx     # 指定几个
    python scripts/provider/verify.py --proxy http://127.0.0.1:7890
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import http_json, load, mask  # noqa: E402

UA = {"User-Agent": "raven/0.1"}

# 命中这些标记 = key 认证通过了，只是额度/权限不足 —— 与"key 无效"要区分开
LIMITED_MARKERS = ("credits_insufficient", "rate_limit", "quota",
                   "无 API 访问权限", "requires an organization",
                   "insufficient", "decommissioned")


def q(url, **params):
    return url + ("?" + urllib.parse.urlencode(params) if params else "")


# ---------------------------------------------------------------- 各 provider

def c_shodan(k, p):
    return http_json(q("https://api.shodan.io/api-info", key=k), headers=UA, proxy=p)


def c_censys(k, p):
    # Censys 旧版 search API 已于 2026-09-30 下线，改走 v3 平台 API。
    # 免费账号只能按 IP/ID 取资产，search 端点需组织 ID。
    h = dict(UA); h["Authorization"] = "Bearer " + k
    return http_json("https://api.platform.censys.io/v3/global/asset/host/8.8.8.8",
                     headers=h, proxy=p)


def c_zoomeye(k, p):
    # .org 在国内已停用（提示改用 .ai）；.ai 的 /v2/search 只接受 POST
    h = dict(UA); h["API-KEY"] = k
    return http_json("https://api.zoomeye.ai/v2/search", method="POST",
                     headers=h, body={"q": "title:test", "page": 1, "size": 1}, proxy=p)


def c_hunter(k, p):
    # 无独立配额接口，做最小查询（page_size=1），会消耗 1 次额度
    return http_json(q("https://hunter.qianxin.com/openApi/search",
                       **{"api-key": k, "search": 'ip="1.1.1.1"',
                          "page": 1, "page_size": 1, "is_web": 1}), headers=UA, proxy=p)


def c_netlas(k, p):
    h = dict(UA); h["X-API-Key"] = k
    return http_json("https://app.netlas.io/api/users/current/", headers=h, proxy=p)


def c_abuseipdb(k, p):
    h = dict(UA); h["Key"] = k; h["Accept"] = "application/json"
    return http_json(q("https://api.abuseipdb.com/api/v2/check",
                       ipAddress="8.8.8.8", maxAgeInDays=90), headers=h, proxy=p)


def c_ipinfo(k, p):
    return http_json(q("https://ipinfo.io/8.8.8.8", token=k), headers=UA, proxy=p)


def c_urlscan(k, p):
    h = dict(UA); h["api-key"] = k
    return http_json("https://urlscan.io/user/quotas/", headers=h, proxy=p)


def c_otx(k, p):
    h = dict(UA); h["X-OTX-API-KEY"] = k
    return http_json("https://otx.alienvault.com/api/v1/user/me", headers=h, proxy=p)


def c_github(k, p):
    h = dict(UA); h["Authorization"] = "Bearer " + k; h["Accept"] = "application/vnd.github+json"
    return http_json("https://api.github.com/user", headers=h, proxy=p)


def c_crtsh(_k, p):
    return http_json("https://crt.sh/?q=example.com&output=json", headers=UA, proxy=p)


def c_wayback(_k, p):
    return http_json("http://archive.org/wayback/available?url=example.com", headers=UA, proxy=p)


def c_certspotter(k, p):
    h = dict(UA)
    if k:
        h["Authorization"] = "Bearer " + k
    return http_json(q("https://api.certspotter.com/v1/issuances",
                       domain="example.com", include_subdomains="true",
                       expand="dns_names"), headers=h, proxy=p)


def _cnt(v):
    return str(len(v)) + " 条" if isinstance(v, list) else "?"


CHECKS = [
    ("shodan",      "SHODAN_API_KEY",      True,  c_shodan,
     lambda d: "plan=" + str(d.get("plan")) + "  剩余查询=" + str(d.get("query_credits"))),
    ("censys",      "CENSYS_API_KEY",      True,  c_censys,
     lambda d: "8.8.8.8 查询成功 ip=" + str(((d.get("result") or {}).get("resource") or {}).get("ip", "?"))),
    ("zoomeye",     "ZOOMEYE_API_KEY",     True,  c_zoomeye,
     lambda d: "code=" + str(d.get("code")) + " " + str(d.get("error") or d.get("message", ""))[:40]),
    ("hunter",      "HUNTER_API_KEY",      False, c_hunter,
     lambda d: "code=" + str(d.get("code")) + "  " + str(d.get("message", ""))[:40]),
    ("netlas",      "NETLAS_API_KEY",      True,  c_netlas,
     lambda d: "用户=" + str(d.get("username") or d.get("email") or "?")),
    ("abuseipdb",   "ABUSEIPDB_API_KEY",   True,  c_abuseipdb,
     lambda d: "8.8.8.8 滥用分=" + str((d.get("data") or {}).get("abuseConfidenceScore", "?"))),
    ("ipinfo",      "IPINFO_API_KEY",      True,  c_ipinfo,
     lambda d: "8.8.8.8 -> " + str(d.get("city", "?")) + "/" + str(d.get("country", "?"))),
    ("urlscan",     "URLSCAN_API_KEY",     True,  c_urlscan,
     lambda d: "search 日剩余=" + str(((d.get("limits") or {}).get("search") or {}).get("day", {}).get("remaining", "?"))),
    ("otx",         "OTX_API_KEY",         True,  c_otx,
     lambda d: "用户=" + str(d.get("username", "?"))),
    ("github",      "GITHUB_TOKEN",        True,  c_github,
     lambda d: "登录=" + str(d.get("login", "?")) + "  配额=" + str(d.get("plan", {}).get("name", "?"))),
    ("crtsh",       None,                  True,  c_crtsh,
     lambda d: "example.com 证书 " + _cnt(d)),
    ("wayback",     None,                  True,  c_wayback,
     lambda d: "快照=" + str(bool((d.get("archived_snapshots") or {}).get("closest")))),
    ("certspotter", None,                  True,  c_certspotter,
     lambda d: "example.com 签发 " + _cnt(d)),
]


def try_call(fn, key, proxies):
    """依次尝试各出口，返回 (成功标记, 结果或错误, 用的出口)"""
    last = None
    for label, proxy in proxies:
        try:
            return True, fn(key, proxy), label
        except Exception as exc:
            last = str(exc)[:120]
    return False, last, "-"


def main() -> int:
    ap = argparse.ArgumentParser(description="验证 provider key")
    ap.add_argument("only", nargs="*", help="只验证指定 provider")
    ap.add_argument("--proxy", default="", help="强制使用该代理")
    args = ap.parse_args()

    cfg = load()
    local = args.proxy or (cfg.get("RVN_PROXY_OS_LOCAL") or "").strip()
    direct = [("直连", None)]
    viaproxy = [("代理", local)] if local else []
    foreign_routes = direct + viaproxy
    cn_routes = direct

    ok_n = 0
    for name, var, foreign, fn, summary in CHECKS:
        if args.only and name not in args.only:
            continue
        key = (cfg.get(var) or "").strip() if var else ""
        if var and not key:
            print("  {:<12} SKIP   未配置 {} ".format(name, var))
            continue
        routes = foreign_routes if foreign else cn_routes
        good, res, route = try_call(fn, key, routes)
        if good:
            ok_n += 1
            try:
                detail = summary(res)
            except Exception:
                detail = json.dumps(res, ensure_ascii=False)[:80]
            print("  {:<12} OK     [{:<4}] {}".format(name, route, detail))
        else:
            limited = any(m in str(res) for m in LIMITED_MARKERS)
            print("  {:<12} {}   {}".format(name, "LIMIT" if limited else "FAIL ", res))
    print("")
    print("通过 " + str(ok_n) + " 个")
    return 0 if ok_n else 1


if __name__ == "__main__":
    raise SystemExit(main())
