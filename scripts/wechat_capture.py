#!/usr/bin/env python3
"""微信 / 小程序抓包控制器（Windows 侧）

流程:
    1. agent 执行 start  -> 启动 mitmdump 并把系统代理指向它
    2. 人类在电脑版微信打开小程序并正常点击
    3. agent 执行 stop   -> 停掉 mitmdump，**原样恢复**系统代理
    4. agent 执行 parse  -> 把 flows.jsonl 解析成端点清单

产出全部落在 runs/<target>/<ts>/wechat/（见 SKILL.md §1.1）。

设计要点:
    * mitmdump 上游串接本机代理（.env 的 BB_PROXY_OS_LOCAL），保证出口不变
    * 改系统代理前先备份，stop 时原样恢复 —— 绝不把用户网络留在半配置状态
    * 端口被占用时明确报错，不静默失败
    * 抓包产物、状态文件全部落在 runs 内

用法:
    python scripts/wechat_capture.py start --target example.com
    python scripts/wechat_capture.py start --target example.com --direct
    python scripts/wechat_capture.py stop
    python scripts/wechat_capture.py status
    python scripts/wechat_capture.py parse [--mini-only]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from env import load  # noqa: E402

REG_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
IS_WIN = os.name == "nt"


# ---------------------------------------------------------------- 运行目录

def resolve_wechat_dir(target: str, run_dir: str) -> Path:
    """定位 runs/<target>/<ts>/wechat/。给 --run-dir 则直接用；否则取该目标最新一次任务。"""
    if run_dir:
        base = Path(run_dir)
    else:
        if not target:
            raise RuntimeError("需要 --target 或 --run-dir")
        base = ROOT / "runs" / target
        subs = sorted((p for p in base.iterdir() if p.is_dir()), reverse=True) if base.exists() else []
        base = subs[0] if subs else base / time.strftime("%Y%m%d-%H%M")
    d = base / "wechat"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- mitmdump

def find_mitmdump() -> str:
    cfg = load()
    explicit = (cfg.get("MITMDUMP_PATH") or "").strip()
    if explicit:
        if Path(explicit).exists():
            return explicit
        print("[!] .env 的 MITMDUMP_PATH 不存在: " + explicit, file=sys.stderr)
    for name in ("mitmdump", "mitmdump.exe"):
        found = shutil.which(name)
        if found:
            return found
    home = Path.home()
    for pat in ("AppData/Local/Programs/Python/*/Scripts/mitmdump.exe",
                "AppData/Roaming/Python/*/Scripts/mitmdump.exe",
                ".local/bin/mitmdump"):
        for hit in home.glob(pat):
            return str(hit)
    print("[!] 未找到 mitmdump。任选其一：", file=sys.stderr)
    print("    1) 把 mitmproxy 的 Scripts 目录加入 PATH", file=sys.stderr)
    print("    2) 在 .env 填 MITMDUMP_PATH=<mitmdump 完整路径>", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------- Windows 代理

def reg_query(name: str):
    if not IS_WIN:
        return None
    try:
        out = subprocess.run(["reg", "query", REG_KEY, "/v", name],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == name:
            return parts[-1]
    return None


def reg_set(name: str, value: str, type_: str = "REG_SZ") -> None:
    if not IS_WIN:
        return
    subprocess.run(["reg", "add", REG_KEY, "/v", name, "/t", type_, "/d", value, "/f"],
                   capture_output=True, text=True, timeout=20)


def notify_wininet() -> None:
    """让已运行的程序感知代理变化。"""
    if not IS_WIN:
        return
    ps = ('$sig=\'[DllImport("wininet.dll",SetLastError=true)]public static extern bool '
          'InternetSetOption(IntPtr h,int o,IntPtr b,int l);\';'
          '$t=Add-Type -MemberDefinition $sig -Name W -Namespace I -PassThru;'
          '[void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);'
          '[void]$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0);')
    subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                   capture_output=True, text=True, timeout=30)


# ---------------------------------------------------------------- 进程工具

def pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq " + str(pid), "/NH"],
                             capture_output=True, text=True, timeout=20).stdout
        return str(pid) in out
    except Exception:
        return False


def port_in_use(port: int):
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "TCP" and parts[3] == "LISTENING":
            if parts[1].endswith(":" + str(port)):
                return int(parts[4])
    return None


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(path: Path, d: dict) -> None:
    path.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- 子命令

def cmd_start(args) -> int:
    wdir = resolve_wechat_dir(args.target, args.run_dir)
    state_path = wdir / ".capture_state.json"
    log_path = wdir / "flows.jsonl"

    st = load_state(state_path)
    if st.get("pid") and pid_alive(int(st["pid"])):
        print("[=] 已在运行 pid=" + str(st["pid"]) + "，先 stop 再 start")
        return 0

    port = int(args.port)
    holder = port_in_use(port)
    if holder:
        print("[!] 端口 " + str(port) + " 已被占用 pid=" + str(holder) +
              "，请用 --port 换端口", file=sys.stderr)
        return 3

    if args.fresh and log_path.exists():
        log_path.unlink()
        print("[+] 已清空 " + str(log_path))

    mitmdump = find_mitmdump()
    cfg = load()
    upstream = (cfg.get("BB_PROXY_OS_LOCAL") or "").strip()

    cmd = [mitmdump, "-s", str(HERE / "wechat_addon.py"), "-p", str(port),
           "--set", "termlog_verbosity=info", "--set", "flow_detail=0"]
    if args.direct:
        print("[+] 直连模式：不经上游代理")
    elif upstream:
        cmd += ["--mode", "upstream:" + upstream]
        print("[+] 上游: " + upstream)
    else:
        print("[!] .env 未配置 BB_PROXY_OS_LOCAL，按直连处理", file=sys.stderr)

    env = dict(os.environ)
    env["WECHAT_LOG"] = str(log_path)
    env["WECHAT_KEEP_HOSTS"] = args.keep_hosts or ""

    creation = 0x00000008 if IS_WIN else 0
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, creationflags=creation, env=env)
    time.sleep(6.0)
    if not pid_alive(proc.pid):
        print("[!] mitmdump 启动失败（进程已退出）", file=sys.stderr)
        return 1

    st = {"pid": proc.pid, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
          "listen": "127.0.0.1:" + str(port),
          "upstream": "direct" if args.direct else upstream,
          "log": str(log_path),
          "prev_enable": reg_query("ProxyEnable"),
          "prev_server": reg_query("ProxyServer")}

    if not args.no_proxy:
        if not IS_WIN:
            print("[!] 非 Windows，无法自动改系统代理，请手动把代理指向 127.0.0.1:" +
                  str(port), file=sys.stderr)
        else:
            reg_set("ProxyEnable", "1", "REG_DWORD")
            reg_set("ProxyServer", "127.0.0.1:" + str(port))
            notify_wininet()
            print("[+] 系统代理 -> 127.0.0.1:" + str(port) +
                  "  (原: " + str(st["prev_server"]) + ")")

    save_state(state_path, st)
    print("[+] mitmdump pid=" + str(proc.pid))
    print("[+] 日志: " + str(log_path))
    print("[*] 请在电脑版微信打开目标小程序并操作；完成后执行 stop")
    return 0


def cmd_stop(args) -> int:
    wdir = resolve_wechat_dir(args.target, args.run_dir)
    state_path = wdir / ".capture_state.json"
    st = load_state(state_path)

    pid = int(st.get("pid") or 0)
    if pid:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, text=True, timeout=30)
        print("[+] 已结束 mitmdump pid=" + str(pid))

    if st.get("prev_enable") is not None:
        reg_set("ProxyEnable", str(st["prev_enable"]), "REG_DWORD")
        if st.get("prev_server"):
            reg_set("ProxyServer", str(st["prev_server"]))
        notify_wininet()
        print("[+] 系统代理已恢复: " + str(st.get("prev_server")) +
              " (enable=" + str(st.get("prev_enable")) + ")")

    log_path = Path(st.get("log") or (wdir / "flows.jsonl"))
    n = sum(1 for _ in log_path.open(encoding="utf-8", errors="ignore")) if log_path.exists() else 0
    print("[+] 抓包条数: " + str(n) + "  (" + str(log_path) + ")")
    if state_path.exists():
        state_path.unlink()
    return 0


def cmd_status(args) -> int:
    wdir = resolve_wechat_dir(args.target, args.run_dir)
    state_path = wdir / ".capture_state.json"
    st = load_state(state_path)
    alive = pid_alive(int(st.get("pid") or 0))
    print("mitmdump : " + ("RUNNING" if alive else "stopped") + " pid=" + str(st.get("pid")))
    print("目录     : " + str(wdir))
    print("state    : " + json.dumps(st, ensure_ascii=False))
    if IS_WIN:
        print("系统代理 : ProxyEnable=" + str(reg_query("ProxyEnable")) +
              " ProxyServer=" + str(reg_query("ProxyServer")))
    log_path = Path(st.get("log") or (wdir / "flows.jsonl"))
    n = sum(1 for _ in log_path.open(encoding="utf-8", errors="ignore")) if log_path.exists() else 0
    print("日志     : " + str(log_path) + " 条数=" + str(n))
    return 0


def cmd_parse(args) -> int:
    wdir = resolve_wechat_dir(args.target, args.run_dir)
    log_path = wdir / "flows.jsonl"
    out = Path(args.out) if args.out else (wdir / "endpoints.json")
    cmd = [sys.executable, str(HERE / "wechat_parse.py"),
           "--log", str(log_path), "--out", str(out)]
    if args.mini_only:
        cmd.append("--mini-only")
    return subprocess.run(cmd, cwd=str(ROOT)).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description="微信/小程序抓包控制器")
    def add_target(p):
        p.add_argument("--target", default="", help="目标标识，定位 runs/<target>/<最新>/wechat")
        p.add_argument("--run-dir", default="", help="直接指定 run 目录")

    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("start"); add_target(p)
    p.add_argument("--port", type=int, default=int(load().get("WECHAT_LISTEN_PORT") or 8082))
    p.add_argument("--no-proxy", action="store_true", help="不改系统代理")
    p.add_argument("--direct", action="store_true", help="不经上游代理")
    p.add_argument("--fresh", action="store_true", default=True, help="清空旧日志（默认）")
    p.add_argument("--keep-hosts", default="", help="覆盖主机白名单正则")
    p.set_defaults(fn=cmd_start)

    p = sub.add_parser("stop"); add_target(p); p.set_defaults(fn=cmd_stop)
    p = sub.add_parser("status"); add_target(p); p.set_defaults(fn=cmd_status)
    p = sub.add_parser("parse"); add_target(p)
    p.add_argument("--out", default=""); p.add_argument("--mini-only", action="store_true")
    p.set_defaults(fn=cmd_parse)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except RuntimeError as exc:
        print("[wechat] " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
