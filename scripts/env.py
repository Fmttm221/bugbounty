#!/usr/bin/env python3
"""env —— .env 读取入口

用法:
    from env import load          # 代码调用（scripts/provider/* 用这个）
    python scripts/env.py KEY     # 取单个变量的值（agent 用）
    python scripts/env.py --list  # 只列变量名，不返回值（agent 用）

设计要点:
    --list 只输出变量名。agent 可以安全地"看有什么可用"，
    而不必把 .env 里的全部密钥拉进上下文。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"


def load(path=None) -> dict:
    """解析 .env，返回 {KEY: VALUE}。文件不存在时返回空 dict。"""
    p = path or ENV_FILE
    cfg: dict = {}
    if not p.exists():
        return cfg
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        cfg[key.strip()] = val.strip().strip('"').strip("'")
    return cfg


def main(argv) -> int:
    cfg = load()
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] in ("-l", "--list"):
        for key in sorted(cfg):
            print(key)
        return 0
    key = argv[0]
    if key not in cfg:
        print("[env] undefined: " + key, file=sys.stderr)
        return 1
    print(cfg[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
