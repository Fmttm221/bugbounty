#!/usr/bin/env python3
"""IP 情报聚合：地理/ASN + 滥用记录 + 开放端口/服务

源:
    ipinfo     地理/ASN        需 key(可选)  直连
    abuseipdb  滥用记录        需 key        直连
    shodan     端口/服务/指纹   需 key        直连
    censys     主机资产        需 key        直连  v3 平台 API
    otx        IP 情报         无需 key      直连  公开端点

用法:
    python scripts/provider/ip_intel.py 1.1.1.1
    python scripts/provider/ip_intel.py 1.1.1.1 --source ipinfo,shodan
    python scripts/provider/ip_intel.py 1.1.1.1 --out runs/x/assets/ip.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from base import http_json, load  # noqa: E402

UA = {"User-Agent": "bugbounty-skill/0.1"}


def _key(name: str) -> str:
    v = (load().get(name) or "").strip()
    if not v:
        raise RuntimeError("未配置 " + name)
    return v


def s_ipinfo(ip, proxy):
    d = http_json("https://ipinfo.io/" + ip + "?token=" + _key("IPINFO_API_KEY"),
                  headers=UA, proxy=proxy, timeout=20)
    return {"org": d.get("org"), "country": d.get("country"), "city": d.get("city"),
            "hostname": d.get("hostname"), "raw_keys": list(d.keys())}


def s_abuseipdb(ip, proxy):
    d = http_json("https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90",
                  headers={**UA, "Key": _key("ABUSEIPDB_API_KEY"), "Accept": "application/json"},
                  proxy=proxy, timeout=20)
    r = d.get("data") or {}
    return {"abuse_score": r.get("abuseConfidenceScore"), "total_reports": r.get("totalReports"),
            "country": r.get("countryCode"), "isp": r.get("isp"), "domain": r.get("domain")}


def s_shodan(ip, proxy):
    d = http_json("https://api.shodan.io/shodan/host/" + ip + "?key=" + _key("SHODAN_API_KEY"),
                  headers=UA, proxy=proxy, timeout=30)
    return {"ports": d.get("ports"), "org": d.get("org"), "os": d.get("os"),
            "hostnames": d.get("hostnames"), "domains": d.get("domains"),
            "vulns": list((d.get("vulns") or {}).keys())[:10]}


def s_censys(ip, proxy):
    d = http_json("https://api.platform.censys.io/v3/global/asset/host/" + ip,
                  headers={**UA, "Authorization": "Bearer " + _key("CENSYS_API_KEY")},
                  proxy=proxy, timeout=30)
    res = ((d.get("result") or {}).get("resource") or {})
    loc = res.get("location") or {}
    return {"country": loc.get("country"), "city": loc.get("city"),
            "services": len(res.get("services") or []),
            "autonomous_system": (res.get("autonomous_system") or {}).get("name")}


def s_otx(ip, proxy):
    """OTX indicator 查询是公开端点，无需 key。"""
    d = http_json("https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/general",
                  headers=UA, proxy=proxy, timeout=25)
    # 注意：asn / whois 都是**字符串**，不是字典
    pi = d.get("pulse_info") or {}
    return {"reputation": d.get("reputation"),
            "asn": d.get("asn"),
            "pulse_count": pi.get("count"),
            "pulses": [x.get("name") for x in (pi.get("pulses") or [])][:5]}


SOURCES = {
    "ipinfo":    (s_ipinfo,    "直连"),
    "abuseipdb": (s_abuseipdb, "直连"),
    "shodan":    (s_shodan,    "直连"),
    "censys":    (s_censys,    "直连"),
    "otx":       (s_otx,       "直连"),
}


def main() -> int:
    ap = argparse.ArgumentParser(description="IP 情报聚合")
    ap.add_argument("ip")
    ap.add_argument("--source", default="", help="逗号分隔，默认全部：" + ",".join(SOURCES))
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    cfg = load()
    proxy = (cfg.get("BB_PROXY_OS_LOCAL") or "").strip() or None
    names = [s.strip() for s in args.source.split(",") if s.strip()] or list(SOURCES)

    results, errors = {}, {}
    for name in names:
        if name not in SOURCES:
            errors[name] = "未知源"
            continue
        fn, route = SOURCES[name]
        try:
            results[name] = fn(args.ip, proxy if route == "代理" else None)
            print("  %-11s OK   [%s] %s" % (name, route, json.dumps(results[name], ensure_ascii=False)))
        except Exception as exc:
            errors[name] = str(exc)[:120]
            print("  %-11s FAIL %s" % (name, errors[name]))

    out = {"ip": args.ip, "results": results, "errors": errors, "sources_ok": len(results)}
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print("\n  已写入 " + args.out)
    else:
        print("\n" + text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
