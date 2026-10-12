#!/usr/bin/env python3
"""mitmproxy addon：把微信/小程序流量以 JSONL 写入 runs 目录

日志路径由环境变量 WECHAT_LOG 指定（由 wechat_capture.py 注入）。
用法: mitmdump -s scripts/wechat_addon.py -p 8082

设计要点:
    * 采集期就脱敏 —— 落盘前替换 PII，而不是事后在证据里补
    * 静态资源过滤，避免日志被图片/字体稀释
    * 单条流量异常绝不中断抓包
    * 日志超过上限自动停止写入，防止撑爆磁盘
"""
from __future__ import annotations

import json
import os
import re
import time

from mitmproxy import http

LOG_PATH = os.environ.get("WECHAT_LOG") or os.path.join(
    os.environ.get("TEMP", "/tmp"), "mini_req.log")
MAX_BODY = 8000
MAX_LOG_BYTES = 256 * 1024 * 1024

# 强制记录的主机（命中则即使是静态资源也记）。由 wechat_capture.py 注入 WECHAT_KEEP_HOSTS
KEEP_HOSTS = re.compile(
    os.environ.get("WECHAT_KEEP_HOSTS")
    or r"(weixin|wechat|tencent|qpic\.cn|qlogo\.cn|servicewechat)",
    re.IGNORECASE,
)

# 噪音主机（本机软件的后台流量）。由 wechat_capture.py 注入 WECHAT_EXCLUDE_HOSTS
EXCLUDE_HOSTS = set(filter(None, (os.environ.get("WECHAT_EXCLUDE_HOSTS") or "").split(",")))

STATIC_EXT = re.compile(
    r"\.(png|jpe?g|gif|webp|svg|ico|css|js|mp4|woff2?|ttf|eot|zip|apk|dmg|exe)(\?|$)",
    re.IGNORECASE)
STATIC_CT = re.compile(
    r"^(image/|font/|video/|audio/|text/css|application/javascript|text/javascript)",
    re.IGNORECASE)

# 采集期脱敏：身份证 / 手机号 / 姓名 / openid
PII_RULES = [
    (re.compile(r"\b\d{17}[\dXx]\b"), "<ID_CARD>"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "<PHONE>"),
    (re.compile(r'(?i)("(?:patient_?name|real_?name|name)"\s*:\s*")[^"]{1,30}(")'), r"\g<1><NAME>\g<2>"),
    (re.compile(r'(?i)((?:[a-z_]*open_?id)\b"?\s*[:=]\s*"?)([A-Za-z0-9_\-]{10,})'), r"\g<1><OPENID>"),
]


def _redact(text):
    if not text:
        return ""
    out = text
    for pattern, repl in PII_RULES:
        out = pattern.sub(repl, out)
    return out


def _truncate(text):
    if not text:
        return ""
    return _redact(text)[:MAX_BODY]


def response(flow: http.HTTPFlow) -> None:
    try:
        req = flow.request
        resp = flow.response
        host = req.pretty_host or ""
        if not host or host in EXCLUDE_HOSTS:
            return

        path = req.path or ""
        resp_ct = (resp.headers.get("content-type", "") if resp else "") or ""
        req_ct = req.headers.get("content-type", "") or ""

        if not KEEP_HOSTS.search(host):
            if STATIC_EXT.search(path) or STATIC_CT.match(resp_ct):
                return

        try:
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > MAX_LOG_BYTES:
                return
        except OSError:
            pass

        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": req.method,
            "scheme": req.scheme,
            "host": host,
            "path": path,
            "url": req.pretty_url,
            "req_ct": req_ct,
            "resp_ct": resp_ct,
            "resp_code": resp.status_code if resp else None,
            "resp_len": len(resp.content) if (resp and resp.content) else 0,
            "req_body": _truncate(req.get_text(strict=False)),
            "req_headers": {k: _redact(v) for k, v in req.headers.items()},
        }
        os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # 抓包插件绝不能因单条流量报错而中断
        pass
