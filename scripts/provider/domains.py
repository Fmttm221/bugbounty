#!/usr/bin/env python3
"""域名资产枚举：证书透明度 + 历史 URL + 被动 DNS

把多个免费源聚合到一个入口 —— agent 的问题是「这个域有哪些子域/URL」，
不是「我要调 crtsh」。

源:
    crtsh       证书透明度      无需 key  需代理  站点不稳定，自带重试
    certspotter 证书签发        无需 key  直连
    otx         ~~被动 DNS~~    **已停用**  —— key 无效（公开 indicator 端点仍可用，见 ip_intel）
    wayback     历史 URL        无需 key  需代理
    netlas      域名资产        需 key    直连

用法:
    python scripts/provider/domains.py example.com
    python scripts/provider/domains.py example.com --source crtsh,certspotter
    python scripts/provider/domains.py example.com --out runs/x/assets/domains.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import http_json, load  # noqa: E402

UA = {"User-Agent": "raven/0.1"}


def _norm(names):
    out = set()
    for n in names or []:
        if not n:
            continue
        for part in str(n).replace("\n", " ").split():
            part = part.strip().lower().lstrip("*.")
            if part and "." in part and " " not in part:
                out.add(part)
    return out


def _otx_key() -> str:
    v = (load().get("OTX_API_KEY") or "").strip()
    if not v:
        raise RuntimeError("未配置 OTX_API_KEY（此端点需认证）")
    return v


def s_crtsh(domain, proxy):
    """证书透明度。crt.sh 不稳定，重试 3 次。"""
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
    last = None
    for i in range(3):
        try:
            rows = http_json(url, headers=UA, proxy=proxy, timeout=45)
            subs = set()
            for r in rows if isinstance(rows, list) else []:
                subs |= _norm([r.get("name_value")])
            return {"subdomains": sorted(subs), "certs": len(rows)}
        except Exception as exc:
            last = exc
            time.sleep(2 * (i + 1))
    raise RuntimeError(str(last)[:120])


def s_certspotter(domain, proxy):
    url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(
        {"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
    rows = http_json(url, headers=UA, proxy=proxy, timeout=30)
    subs = set()
    for r in rows if isinstance(rows, list) else []:
        subs |= _norm(r.get("dns_names"))
    return {"subdomains": sorted(subs), "certs": len(rows)}


def s_otx(domain, proxy):
    """OTX 被动 DNS —— 此端点**需要认证**（公开的只有 indicator 查询）。"""
    url = "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns"
    d = http_json(url, headers=UA, proxy=proxy, timeout=30)
    subs = _norm([r.get("hostname") for r in (d.get("passive_dns") or [])])
    return {"subdomains": sorted(subs), "records": len(d.get("passive_dns") or [])}


def s_wayback(domain, proxy):
    """历史 URL。CDX 极慢且不稳定：实测 limit=100 可能要 44s，collapse 会 504。
    fastLatest=true 可把耗时压到 ~10s，因此不用 collapse。"""
    url = "http://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(
        {"url": domain + "/*", "output": "json", "limit": 500,
         "fastLatest": "true", "fl": "original"})
    rows = http_json(url, headers=UA, proxy=proxy, timeout=90)
    if not isinstance(rows, list) or len(rows) < 2:
        return {"urls": [], "records": 0}
    urls = sorted({r[0] for r in rows[1:] if r})
    return {"urls": urls, "records": len(urls)}


def s_netlas(domain, proxy):
    key = (load().get("NETLAS_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("未配置 NETLAS_API_KEY")
    url = "https://app.netlas.io/api/domains/?" + urllib.parse.urlencode(
        {"q": "domain:" + domain, "size": 100})
    d = http_json(url, headers={**UA, "X-API-Key": key}, proxy=proxy, timeout=30)
    items = d.get("items") or []
    subs = _norm([(i.get("data") or {}).get("domain") or i.get("domain") for i in items])
    return {"subdomains": sorted(subs), "records": len(items)}


SOURCES = {
    "crtsh":       (s_crtsh,       "代理"),
    "certspotter": (s_certspotter, "直连"),
    "otx":         (s_otx,         "直连"),
    "wayback":     (s_wayback,     "代理"),
    "netlas":      (s_netlas,      "直连"),
}

# 已停用：账号无额度 / 无权限 / key 无效 —— 默认跳过，防止真实使用时反复报错。
# 修好 key 后把对应项从这里删掉即可恢复；也可用 --source 显式指定强制运行。
DISABLED = {
    "otx": "被动 DNS 端点需认证，当前 key 无效（公开的 indicator 端点不受影响）",
}


def main() -> int:
    ap = argparse.ArgumentParser(description="域名资产枚举")
    ap.add_argument("domain")
    ap.add_argument("--source", default="", help="逗号分隔，默认全部：" + ",".join(SOURCES))
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    cfg = load()
    proxy = (cfg.get("RVN_PROXY_OS_LOCAL") or "").strip() or None
    explicit = [s.strip() for s in args.source.split(",") if s.strip()]
    if explicit:
        names = explicit
    else:
        names = [s for s in SOURCES if s not in DISABLED]
        for d, why in DISABLED.items():
            print("  [跳过停用源] %s —— %s" % (d, why))

    subdomains, urls, stats, errors = set(), set(), {}, {}
    for name in names:
        if name not in SOURCES:
            errors[name] = "未知源"
            continue
        fn, route = SOURCES[name]
        use_proxy = proxy if route == "代理" else None
        try:
            r = fn(args.domain, use_proxy)
            stats[name] = {k: v for k, v in r.items() if not isinstance(v, list)}
            subdomains |= set(r.get("subdomains") or [])
            urls |= set(r.get("urls") or [])
            print("  %-12s OK   [%s] %s" % (name, route, json.dumps(stats[name], ensure_ascii=False)))
        except Exception as exc:
            errors[name] = str(exc)[:120]
            print("  %-12s FAIL %s" % (name, errors[name]))

    result = {
        "domain": args.domain,
        "subdomains": sorted(subdomains),
        "urls": sorted(urls),
        "stats": stats,
        "errors": errors,
        "count": {"subdomains": len(subdomains), "urls": len(urls)},
    }
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print("\n  已写入 " + args.out)
    else:
        print("\n" + text)
    print("  子域 %d / URL %d" % (len(subdomains), len(urls)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
