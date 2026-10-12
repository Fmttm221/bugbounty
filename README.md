# bugbounty

授权范围内的漏洞挖掘 skill。

以 `ssh-mcp`（远端 Kali 工具链）与 `chrome-devtools-mcp`（本机浏览器）为两条主通道，覆盖
**资产收集 → 攻击面分析 → 漏洞发现 → 验证利用 → 影响评估 → 报告** 全流程。

> ⚠️ 本 skill 带一组默认假设（默认已授权、默认全域、默认无禁止项）。
> **默认值不产生任何法律授权**，实际授权由使用者负责。

---

## 依赖

### 必需

| 依赖 | 说明 |
|---|---|
| Python 3.10+ | 所有脚本只用标准库 |
| MCP 客户端 | 能加载 `SKILL.md`，并提供 `ssh-mcp` 与 `chrome-devtools-mcp` |
| 远端 Kali（或任意 Linux） | 装了渗透工具链，检查项见 `scripts/preflight.py` |
| 本机 Chrome | 供 `chrome-devtools-mcp` 驱动 |

### 可选

| 依赖 | 用途 | 没有也能用吗 |
|---|---|---|
| HTTP 代理 | 测国外目标 | ✅ 只测国内目标时不需要 |
| Clash | `clash.py` 节点切换 | ✅ 检测不到就静默跳过 |
| mitmproxy | 微信小程序抓包 | ✅ 不抓小程序就不需要 |
| provider API key | 资产收集 | ✅ crtsh / wayback / certspotter 免费无需 key |

---

## 快速上手

```bash
# 进入本仓库目录后
cp .env.example .env          # Windows: copy .env.example .env
# 按下方表格编辑 .env
python scripts/preflight.py   # 自检，缺什么会直接告诉你
```

然后在 MCP 客户端里加载 `SKILL.md`，**主动调用**（本 skill 已设 `disable-model-invocation`，不会自动触发）。

---

## 每个人必须自己配的

**下面这些是环境相关的，没有通用值，必须自己填。**

| 变量 | 是什么 | 怎么找 |
|---|---|---|
| `KALI_HOST` | 你的 Kali IP | Kali 上 `ip -4 addr` |
| `KALI_USER` | Kali 用户名 | Kali 上 `whoami` |
| `KALI_KEY_PATH` | SSH 私钥（供需要直连 ssh 的脚本） | 通常 `~/.ssh/id_ed25519` |
| `BB_PROXY_OS_LOCAL` | **本机**的 HTTP 代理地址 | 代理软件的监听地址；Clash 默认 `http://127.0.0.1:7890` |
| `BB_PROXY_OS_KALI` | **Kali 视角**看本机代理 | VMware NAT 网段通常是 `192.168.x.1`。<br>验证：在 Kali 上跑 `curl -x http://192.168.x.1:7890 https://api.ipify.org` |
| `CDP_PORT` | chrome-devtools 调试端口 | 默认 `9222` |
| `BB_PHONE_A/B`、`BB_EMAIL_A/B` | 注册 / 登录用 | 越权测试需要 **≥ 2 个**身份 |
| `MITMDUMP_PATH` | mitmdump 完整路径 | 留空自动探测；探测不到时再填 |
| `WECHAT_LISTEN_PORT` | 抓包监听端口 | 默认 `8082` |

### 代理是可换的 —— 本 skill 不绑定 Clash

`BB_PROXY_OS_LOCAL` / `BB_PROXY_OS_KALI` 就是两个**普通 HTTP 代理地址**：
Clash / v2ray / mihomo / mitmproxy / 公司代理都能填。

`scripts/clash.py` 的节点切换是**可选增强** —— 只在检测到 Clash 时可用，检测不到会打印提示并以退出码 0 跳过，**不阻塞主流程**。

---

## Provider 说明

每个 provider 的可用性取决于**你自己的账号**。先跑一次验证：

```bash
python scripts/provider/verify.py          # 全部
python scripts/provider/verify.py shodan   # 单个
```

`verify.py` 区分三种状态：`OK`（可用）、`LIMIT`（**认证通过但额度/权限不足**）、`FAIL`（key 无效）。

| Provider | 归属 | 需要 key | 出口 | 状态 | 说明 |
|---|---|---|---|---|---|
| quake | 国内 | 是 | 直连 | ✅ | 每账号 5 次/月；多账号自动轮换；免费额度为 0 时**拒绝查询**以防误扣 credit |
| crtsh | 国外 | **否** | **需代理** | ✅ | 站点不稳定，脚本自带重试 |
| certspotter | 国外 | 否（可选带 key 提额） | 直连 | ✅ | |
| wayback | 国外 | **否** | **需代理** | ✅ | CDX 极慢，脚本已加 `fastLatest=true` |
| netlas | 国外 | 是 | 直连 | ✅ | |
| urlscan | 国外 | 是（可免费注册） | 直连 | ✅ | search 1000/日 |
| abuseipdb | 国外 | 是 | 直连 | ✅ | 1000/日 |
| ipinfo | 国外 | 是（可选 token 提额） | 直连 | ✅ | |
| censys | 国外 | 是 | 直连 | ✅ | 走 **v3 平台 API**；旧版已于 2026-09-30 下线 |
| shodan | 国外 | 是 | 直连 | ✅ | `query_credits` **不反映 host 查询配额**，别被它误导 |
| otx（IP 情报） | 国外 | **否** | 直连 | ✅ | indicator 查询是**公开端点** |
| otx（被动 DNS） | 国外 | 是 | 直连 | ⛔ **已停用** | 该端点需认证，当前 key 无效 |
| zoomeye | 国外 | 是 | **需代理** | ⛔ **已停用** | 账号无额度（`credits_insufficient`） |
| hunter | 国内 | 是 | 直连 | ⛔ **已停用** | API 需付费账号 |
| github | 国外 | 是 | — | ⛔ **已停用** | token 无效 |

> **已停用** = 默认跳过，不会在真实使用时报错。
> 修好 key 或升完额度后，删掉 `scripts/provider/domains.py` 里 `DISABLED` 对应的项即可恢复；
> 也可用 `--source <名字>` 显式指定强制运行（便于验证修好的 key）。

---

## 目录结构

```
bugbounty/
├── SKILL.md                 skill 正文（配置 / 人机协作 / 经验库 / 渗透测试）
├── .env                     私密配置（gitignored）
├── .env.example             配置模板（逐项注释）
├── assets/                  报告模板，按平台命名
├── references/experience/   经验库：INDEX.md + 每条一个 .md
├── runs/                    运行产物（gitignored）
└── scripts/                 全部脚本
```

运行产物布局（`runs/<target>/<时间戳>/`）：

```
├── scope.md      L0 授权假设
├── state.md      进度
├── assets/       L1 资产清单
├── recon/        L1 原始输出
├── surface/      L2 指纹 / L3 测试矩阵
├── sessions/     人机协作回灌的会话
├── findings/     L4 每条漏洞一个 .md
├── evidence/     证据
├── wechat/       小程序抓包
└── report.md     L6 报告
```

---

## 脚本一览

| 脚本 | 作用 |
|---|---|
| `scripts/preflight.py` | 开工前本机自检 |
| `scripts/env.py` | `.env` 读取入口（`--list` 只列变量名，不返回值） |
| `scripts/clash.py` | Clash 节点查看 / 切换 / 轮换（可选） |
| `scripts/wechat_capture.py` | 小程序抓包控制器（起停 mitmdump、备份恢复系统代理） |
| `scripts/wechat_addon.py` | mitmproxy addon（**采集期就脱敏**） |
| `scripts/wechat_parse.py` | 抓包日志 → 端点清单 |
| `scripts/provider/base.py` | provider 通用：HTTP / 代理 / 配额 / 脱敏 |
| `scripts/provider/verify.py` | 验证全部 provider key |
| `scripts/provider/domains.py` | **域名资产枚举**：crtsh / certspotter / otx / wayback / netlas |
| `scripts/provider/ip_intel.py` | **IP 情报**：ipinfo / abuseipdb / shodan / censys / otx |
| `scripts/provider/quake.py` | 360 Quake（双账号轮换 + 额度保护） |
| `scripts/provider/urlscan.py` | urlscan.io |

---

## 已知限制

- `runs/` 与 `.env` 已在 `.gitignore` 中，**不会提交**。
- 微信小程序抓包依赖**人类在电脑版微信上操作** —— agent 只负责起停代理与解析流量。
- 遇 SSL Pinning 的小程序抓不到，记录为限制项即可。
- 报告中的 Burp 复现步骤由 **agent 描述、人类执行** —— agent 不声称自己在 Burp 里验证过。
- 部分 provider 额度极小（如 Quake 每账号 5 次/月），脚本会在额度耗尽时拒绝调用而非静默消耗付费额度。
