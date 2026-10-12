#!/usr/bin/env python3
"""一致性校验：防止文档与代码漂移

为什么需要它:
    同一批变量名在 SKILL.md / README / .env.example / 代码 四处出现，
    手工同步必然漂移（本项目历史上已发生 7 次）。
    与其禁止重复（README 面向人、SKILL.md 面向 agent，重复是合理的），
    不如把「对账」变成一条机械命令。

用法:
    python scripts/check_consistency.py
    python scripts/check_consistency.py --verbose

退出码: 0 = 全过；1 = 发现漂移
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 由 wechat_capture.py 注入、不需要出现在 .env.example 的变量
INJECTED = {"WECHAT_LOG"}

# OS 环境变量，不是本 skill 的配置项
OS_ENV = {"TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "APPDATA",
          "LOCALAPPDATA", "PATH", "USER", "USERNAME", "LANG", "PYTHONIOENCODING"}

# 运行时才产生的路径（不是静态文件，不校验存在性）
RUNTIME_PREFIX = ("runs/",)


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def env_names() -> set:
    c = _read(ROOT / ".env.example")
    return set(re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=", c))


def main() -> int:
    ap = argparse.ArgumentParser(description="一致性校验")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    problems = []
    checked = 0
    env = env_names()

    # ---- 1. .env 与 .env.example 变量名一致（.env 可选）----
    dotenv = ROOT / ".env"
    if dotenv.exists():
        checked += 1
        a = set(re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=", _read(dotenv)))
        only_env = a - env
        only_tmpl = env - a
        if only_env:
            problems.append(".env 有而 .env.example 没有: " + ", ".join(sorted(only_env)))
        if only_tmpl:
            problems.append(".env 缺而 .env.example 有: " + ", ".join(sorted(only_tmpl)))

    # ---- 2. 文档提到的变量都在 .env.example ----
    for doc in ("SKILL.md", "README.md"):
        p = ROOT / doc
        if not p.exists():
            continue
        checked += 1
        for m in sorted(set(re.findall(r"(RVN_[A-Z0-9_]+)", _read(p)))):
            if m not in env:
                problems.append(doc + " 提到 " + m + "，但 .env.example 里没有")
        for m in sorted(set(re.findall(r"`(KALI_[A-Z_]+)`", _read(p)))):
            if m not in env:
                problems.append(doc + " 提到 " + m + "，但 .env.example 里没有")

    # ---- 3. 文档引用的静态路径真实存在 ----
    for doc in ("SKILL.md", "README.md"):
        p = ROOT / doc
        if not p.exists():
            continue
        checked += 1
        text = _read(p)
        for m in re.finditer(r"(?<![\w./-])((?:scripts|assets|references)/[\w./-]+)", text):
            path = m.group(1)
            # 模板占位（如 assets/report_<平台>.md）后面紧跟 <，跳过
            if text[m.end():m.end() + 1] == "<":
                continue
            if path.startswith(RUNTIME_PREFIX):
                continue
            m = path
            target = m.rstrip(".").rstrip("/")
            if not (ROOT / target).exists():
                problems.append(doc + " 引用 " + m + "，但文件不存在")

    # ---- 4. 脚本读取的变量都在 .env.example ----
    checked += 1
    for py in sorted((ROOT / "scripts").rglob("*.py")):
        if py.name == "check_consistency.py":
            continue
        text = _read(py)
        found = set()
        found |= set(re.findall(r'(?:load\(\)|cfg)\.get\(\s*"([A-Z][A-Z0-9_]+)"', text))
        found |= set(re.findall(r'_key\(\s*"([A-Z][A-Z0-9_]+)"', text))
        found |= set(re.findall(r'os\.environ\.get\(\s*"([A-Z][A-Z0-9_]+)"', text))
        found = {v for v in found if not v.endswith("_")}   # 排除 QUAKE_API_KEY_ 这类前缀拼接
        for v in sorted(found - env - INJECTED - OS_ENV):
            problems.append("scripts/" + py.name + " 读取 " + v + "，但 .env.example 里没有")

    # ---- 5. 经验库索引覆盖全部条目 ----
    exp = ROOT / "references" / "experience"
    idx = exp / "INDEX.md"
    if idx.exists():
        checked += 1
        itext = _read(idx)
        for f in sorted(exp.glob("*.md")):
            if f.name != "INDEX.md" and f.name not in itext:
                problems.append("经验条目 " + f.name + " 未登记到 INDEX.md")

    print("检查项 " + str(checked) + " 组")
    if problems:
        print("发现 " + str(len(problems)) + " 处漂移：")
        for x in problems:
            print("  !! " + x)
        return 1
    print("无漂移 ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
