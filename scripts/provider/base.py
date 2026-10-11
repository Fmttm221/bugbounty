#!/usr/bin/env python3
"""provider 通用基础设施：HTTP、代理、配额记账

设计要点:
    - 代理显式控制：不传 proxy 就走直连（屏蔽系统代理），传了才走
    - 配额持久化到 runs/.quota.json（gitignored），按月自动重置
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent          # scripts/provider
ROOT = HERE.parent.parent                        # skill 根目录
sys.path.insert(0, str(HERE.parent))             # scripts/ 供 env 导入
from env import load  # noqa: E402

QUOTA_FILE = ROOT / "runs" / ".quota.json"


def http_json(url, *, method="GET", headers=None, body=None, proxy=None, timeout=30):
    """发请求并返回解析后的 JSON。proxy=None 表示强制直连。"""
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    else:
        handler = urllib.request.ProxyHandler({})   # 显式直连
    opener = urllib.request.build_opener(handler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        raise RuntimeError("HTTP " + str(exc.code) + ": " + raw[:400]) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("网络失败: " + str(exc.reason)) from exc


def mask(key: str) -> str:
    """凭证脱敏显示，禁止把完整 key 打进日志。"""
    return key[:8] + "..." + key[-4:] if len(key) > 14 else "***"


def _period() -> str:
    return datetime.now().strftime("%Y-%m")


def quota_load() -> dict:
    if QUOTA_FILE.exists():
        try:
            return json.loads(QUOTA_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def quota_save(data: dict) -> None:
    QUOTA_FILE.parent.mkdir(parents=True, exist_ok=True)
    QUOTA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def quota_used(provider: str, key: str) -> int:
    """本周期已用次数。跨月自动归零。"""
    entry = quota_load().get(provider, {}).get(key)
    if not entry or entry.get("period") != _period():
        return 0
    return int(entry.get("used", 0))


def quota_consume(provider: str, key: str, limit: int) -> int:
    """记一次消耗并返回消耗后次数；超限抛异常。"""
    data = quota_load()
    bucket = data.setdefault(provider, {})
    entry = bucket.get(key)
    if not entry or entry.get("period") != _period():
        entry = {"used": 0, "period": _period()}
    used = int(entry.get("used", 0))
    if used >= limit:
        raise RuntimeError(provider + " 配额已用尽 (" + str(used) + "/" + str(limit) + ", " + _period() + ")")
    entry["used"] = used + 1
    bucket[key] = entry
    quota_save(data)
    return entry["used"]
