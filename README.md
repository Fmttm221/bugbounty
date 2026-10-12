# raven

> 渡鸦以**会使用工具、会规划多步任务、会记住教训**著称。
> 这个 skill 照着同一套思路搭。

授权范围内的漏洞挖掘 skill。以远端 Kali 与 `chrome-devtools` 为两条主通道。

**用法、配置、流程、判定标准 —— 全部见 [`SKILL.md`](SKILL.md)。本文件只讲怎么把它跑起来。**

---

## 依赖

| | |
|---|---|
| **必需** | Python 3.10+ · 支持 `ssh-mcp` 与 `chrome-devtools-mcp` 的 MCP 客户端 · 一台装了工具链的 Kali · 本机 Chrome |
| **可选** | HTTP 代理（测国外目标时）· Clash（节点切换）· mitmproxy（微信小程序抓包） |

## 快速上手

```bash
cp .env.example .env          # 按文件内的逐项注释填写
python scripts/preflight.py   # 自检：缺什么会直接告诉你
```

然后在 MCP 客户端里加载 `SKILL.md`，**主动调用**。

> 改动本仓库的文档或脚本后，跑一次 `python scripts/check_consistency.py`。

> ⚠️ 「默认已授权」是使用者的自我声明，不产生任何法律授权。实际授权由使用者负责。
