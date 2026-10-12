---
name: bugbounty
description: 一个漏洞挖掘skill
disable-model-invocation: true
---

# bugbounty

## Goal

你所做的一切，都是为了挖出**高价值**的漏洞。

> 判定标准见 §4 —— **影响分级 I1 / I2，或能构成完整漏洞链**。

---

## 1. 配置模块

### 1.1 workspace

工作区固定在 `./runs`（已被 `.gitignore` 排除，不进版本库）。

**目录结构**

```
runs/
└── <target>/                      # 主域名，去掉 www
    └── <YYYYMMDD-HHMM>/           # 本次任务
        ├── scope.md               # L0 授权假设 —— 后续所有阶段读它
        ├── state.md               # 进度：当前到哪层、卡在哪
        ├── assets/                # L1 资产清单（去重）
        ├── recon/                 # L1 原始扫描输出（原样落盘，不改写）
        ├── surface/               # L2 指纹与暴露面、L3 测试矩阵
        ├── sessions/              # 人机协作回灌的会话（Cookie / Token）
        ├── findings/              # L4 每条漏洞一个 .md
        ├── evidence/              # 证据：请求/响应/截图
        ├── wechat/                # 小程序抓包流量（按需）
        └── report.md              # L6 报告
```

**创建规则**：目录**按需创建**，不要一上来铺满空目录。

**命名规范**

| 类型 | 格式 | 例子 |
|---|---|---|
| 原始输出 | `<工具>-<目标>.<ext>` | `nmap-10.0.0.1.xml`、`httpx-subs.json` |
| 证据 | `<类型>-<序号>-<简述>.<ext>` | `sqli-01-login-id.txt` |
| 漏洞条目 | `<类型>-<序号>-<简述>.md` | `idor-02-order-api.md` |

**落盘规则**

1. **所有命令的原始输出必须落盘**。
2. **`.env` 的值禁止落盘**，需要引用时只写变量名。
3. 证据保留**原文**；需要打码时另存副本，不要直接改原件。

### 1.2 mcp

| MCP | 角色 | 运行位置 | 职责边界 |
|---|---|---|---|
| `kali` | 主执行通道 | 远端 Kali | 所有命令行工具：侦察、扫描、爆破、验证 |
| `chrome-devtools` | 浏览器通道 | **本机** Windows Chrome | 真实浏览器交互、登录态、前端漏洞验证 |
| 指纹浏览器 | 搁置 | — | — |

**分工原则**

1. 能命令行做的 → `kali`。批量、可重复、可落盘。
2. 需要真实 JS / 登录态 / 反爬的 → `chrome-devtools`。

**连接参数一律走 `.env`**（见 1.3），不写死在本文档。

### 1.3 .env

**变量清单**（模板见 `.env.example`）

| 分组 | 变量 | 说明 |
|---|---|---|
| 授权 | `BB_SCOPE` / `BB_EXCLUDE` | 留空 = 全域 / 无排除 |
| 身份 | `BB_PHONE_A/B`、`BB_EMAIL_A/B` | 注册登录用；**越权测试需 ≥ 2 个** |
| 网络 | `BB_PROXY_OS_LOCAL` | 国外出口，本机脚本视角 `127.0.0.1:7890` |
| 网络 | `BB_PROXY_OS_KALI` | 国外出口，Kali 视角（填法见 README） |
| 网络 | `BB_USER_AGENT` | 必须与 `chrome-devtools` 实际 UA 一致 |
| Kali | `KALI_HOST` / `KALI_PORT` / `KALI_USER` / `KALI_KEY_PATH` | |
| 浏览器 | `CDP_PORT` | |
| provider | 见下表 | |
| provider | `URLSCAN_KEY` | 额度见 `scripts/provider/urlscan.py` |

**国内 / 国外出口**

| 出口 | 实现 |
|---|---|
| 国内 | Kali 直连，不设代理变量 |
| 国外 | `BB_PROXY_OS_LOCAL` / `BB_PROXY_OS_KALI` —— **任意 HTTP 代理均可** |

> **不绑定 Clash**：Clash / v2ray / mihomo / mitmproxy / 公司代理都能填。
> `scripts/clash.py` 的节点切换是**可选增强**，检测不到 Clash 时静默跳过，不阻塞主流程。

**provider 与出口对应**（"注意使用正确的 ip"）

| provider | 归属 | 出口 |
|---|---|---|
| FOFA / QUAKE / HUNTER | 国内 | **直连** |
| SHODAN / CENSYS / VIRUSTOTAL / GITHUB | 国外 | `BB_PROXY_OS_LOCAL` |
| URLSCAN | 国外 | 直连可通，亦可走 `BB_PROXY_OS_LOCAL` |

**读取约定**

1. **代码**（`scripts/provider/*`）：`from env import load` → `load()["FOFA_KEY"]`
2. **Agent 取单值**：`python scripts/env.py FOFA_KEY`
3. **Agent 查可用项**：`python scripts/env.py --list` —— **只列变量名，不返回值**
4. **Kali 侧不共享 `.env`** —— 需要时显式传参注入 ssh 命令

### 1.4 环境自检

开工前跑一遍，**任何 FAIL 先修再打**。

**本机侧** —— `python scripts/preflight.py`

**Kali 侧** —— 经 `kali` MCP 执行

| 检查 | 命令 |
|---|---|
| 可达 | `hostname` |
| 国内出口 | `curl -s -o /dev/null -w '%{http_code}' https://www.baidu.com` |
| 国外出口 | `curl -s -x <BB_PROXY_OS_KALI 的值> https://api.ipify.org` |
| 工具链 | `command -v nmap httpx nuclei ffuf sqlmap dalfox` |

> Kali 侧**不共享 `.env`**，上面用到的值需**显式注入** ssh 命令。

---

## 2. 人机协作模块

### 2.1 什么时候求助

遇到以下情况**立即停手求助**，不要反复重试：

| 信号 | 例子 |
|---|---|
| 滑块 / 点选验证 | 登录、注册、频繁访问触发 |
| 图形 / 短信 / 邮箱验证码 | 注册、找回密码 |
| 实名 / 人脸 | 无法自动化 |
| 风控拦截 | 持续 403/429、行为验证 |
| 需要线下动作 | 扫码、物理设备、电话确认 |
| 需要管理员权限 | 提权验证需要真实 admin |

**判据**：同一动作**连续失败 2 次**就转人机协作。

### 2.2 交接格式

停下后，一次性说清四件事：

```
【卡点】   <在哪个阶段的哪一步>
【已尝试】 <试过什么，为什么不行>
【需要你】 <具体动作，可操作>
【做完后】 <我会接着做什么>
```

### 2.3 人的输入如何回灌

人类完成后，把会话（Cookie / Token / localStorage）**固化落盘**到
`runs/<target>/<ts>/sessions/`，后续阶段直接复用，避免重复求助。

### 2.4 微信小程序抓包

**触发条件**：L1 发现目标存在小程序，**且** L4 漏洞发现已完成。

**三件套**

| 脚本 | 作用 |
|---|---|
| `scripts/wechat_capture.py` | 控制器：起停 mitmdump、备份 / 恢复系统代理 |
| `scripts/wechat_addon.py` | mitmproxy addon：落盘 JSONL，**采集期就脱敏** |
| `scripts/wechat_parse.py` | 解析 flows.jsonl → 端点清单 |

**执行**

1. `python scripts/wechat_capture.py start --target <target>`
   —— 启动 mitmdump 并把系统代理指向它（**改前备份**），上游串接 `BB_PROXY_OS_LOCAL` 保证出口不变
2. 人类在**电脑版微信**打开目标小程序并正常点击
3. `python scripts/wechat_capture.py stop`
   —— 停掉 mitmdump，**原样恢复**系统代理
4. `python scripts/wechat_capture.py parse --mini-only`
5. 把新端点**回灌**到 L3 测试矩阵，重跑 L4

**产出**（全部落在 `runs/<target>/<ts>/wechat/`）

```
wechat/
├── flows.jsonl          原始流量（已脱敏）
├── endpoints.json       解析后的端点与资产
└── .capture_state.json  运行状态（stop 后自动删除）
```

**前置条件**

- mitmproxy CA 证书已安装并被微信信任
- 遇 SSL Pinning → 记录为限制项，不死磕

---

## 3. 经验库模块

位置：`references/experience/` —— 总索引 `INDEX.md` + 每条一个 `.md`。

### 3.1 什么时候读

- **陷入停滞**时按关键词检索
- **命中熟悉问题**时主动检索
- 平时**只看索引**，不加载正文

**读取规则**

1. 先读 `INDEX.md`（只有表格，不加载正文）
2. 命中关键词才读正文，**单次最多 2 条**
3. 超期条目（`last_verified` 超过 90 天）需重新验证再用

### 3.2 什么时候写

| 类型 | 来源 | 要求 |
|---|---|---|
| **A 类** | 本次挖出的漏洞 | 必须已复现（有证据） |
| **B 类** | 操作性知识（工具坑、环境事实、provider 现状） | 无 source_finding，`source` 标 `(manual)` |

**写入前必须用户过目**，用户不同意的不写。

### 3.3 条目格式（四段式）

```markdown
---
keywords: SSRF 打云元数据
confidence: high
last_verified: 2026-03-01
source: PI-XX-001
hint: SSRF 优先试云元数据
---

## 现象
...

## 原因
...

## 解法
...

## 验证
...
```

**硬要求**：四段非空 + `confidence` 显式（`high` / `medium` / `low`）。

### 3.4 索引格式

`references/experience/INDEX.md` 是一张表，每行一条：

| 关键词 | 文件 | confidence | last_verified | source | 提示 |
|---|---|---|---|---|---|

---

## 4. 渗透测试模块

> **行事风格**
>
> L0–L6 只是**大致框架**，不是逐条执行的清单。具体细节自己判断，保持自主与灵活 ——
> 该深挖就深挖，该回头就回头，发现更高价值的方向就果断调整。
>
> **最高准则：挖出高价值漏洞。** 流程服务于这个目标，不是反过来。

**流程**

```
L0 授权
 → L1 资产收集
 → L2 攻击面分析与指纹识别
 → L3 建模与测试矩阵
 → L4 漏洞发现
 → L5 验证与漏洞链
 → L6 报告与提交
```

每层有**门禁**（不满足不许进下一层）与**产出**（落盘到 `runs/<target>/<ts>/`）。

### 判定标准

三个正交维度，互相不能替代。

**① CVSS 3.1 —— 技术定级**

- 向量：`AV / AC / PR / UI / S / C / I / A`
- 分数段 → 报告字段 8：`9.0–10.0 严重 / 7.0–8.9 高 / 4.0–6.9 中 / 0.1–3.9 低 / 0.0 不提交`
- 每条 finding 必带 `cvss_vector` 与 `cvss_score`

**② 影响分级 I1–I4 —— 投入与提交策略**

| 级 | 判据（**能证明**的影响） | 提交策略 |
|---|---|---|
| **I1 完全控制** | 代码执行、服务器控制、云凭证、任意文件读写 | STANDALONE |
| **I2 横向 / 权益** | 批量访问他人数据、接管他人账户、访问管理功能、批量获取资金或权益（支付绕过、无限优惠券、退款欺诈、积分薅取） | STANDALONE |
| **I3 单点影响** | 只能读 / 改有限数据，或需特殊条件才能触发 | STANDALONE / CHAIN_ONLY |
| **I4 无实际影响** | 无数据、权限或权益影响 | CHAIN_ONLY / DISCARD |

**I4 不是垃圾** —— 配置问题（开放重定向、CORS、目录列举、版本泄露）都是 I4，
但它们是链的入口，走 CHAIN_ONLY。

**③ 信息公开性 —— 泄露类硬门禁**

见 L5.1。不通过 → **强制降为 I4**。

#### 三者如何配合

**判据全部是"能证明什么"，不是"可能能干什么"。证明不了的一律 I4。**

| 情形 | CVSS | I 级 | 处理 |
|---|---|---|---|
| 一致 | 高 | I1 / I2 | 正常提交，字段 8 按 CVSS |
| **CVSS 虚高** | 高 | I4 | **不单独提交**，降为链组件 |
| **CVSS 低估** | 低 | I1 / I2 | **提交**；字段 8 可上调，须在字段 9 / 10 说明业务影响 |
| 一致低 | 低 | I4 | DISCARD |

**判定顺序**：信息公开性 → 影响分级 → 自定义规则 → 输出四元组
`cvss_vector` + `cvss_score` + `impact_level` + `submission_strategy`

**自定义规则**挂在"影响分级"之后，覆盖模型输出。已有规则：

- 配置问题不单独作为漏洞，只能作为跳板 → `I4 → CHAIN_ONLY`

### L0 授权模块

**默认假设**（用户补充优先）

| 维度 | 默认 |
|---|---|
| 授权状态 | 已获授权 |
| 测试范围 | 全域 |
| 禁止操作 | 无 |
| 防护假设 | 存在 WAF |

**动作**

1. 分辨资产归属（国内 / 国外）—— 依据 ICP 备案、TLD、DNS 落地 IP、CDN 分布
2. 按归属选择出口：
   - **国内** → Kali 直连，不设代理变量
   - **国外** → Kali 设 `http_proxy` / `https_proxy` = `BB_PROXY_OS_KALI`
3. 需要**换出口 IP**（被封 / 区域限制 / provider 429）→ `python scripts/clash.py next`（可选，需 Clash）

**产出**：`scope.md`

**门禁**：范围明确；出口已选；用户补充已记录

### L1 资产收集

**被动优先** —— 先查第三方数据，不碰目标。

1. **provider 一律用 `scripts/provider/` 下的脚本，不要手搓请求**
   - `domains.py <domain>` —— 域名资产枚举：crtsh / certspotter / otx / wayback / netlas
   - `ip_intel.py <ip>` —— IP 情报：ipinfo / abuseipdb / shodan / censys / otx
   - `quake.py search '<query>'` —— 360 Quake 空间测绘（额度受限，双账号轮换）
   - `verify.py` —— 先验证自己的 key 哪些可用
   - **已停用的源默认跳过**（见 README），不会在真实使用时报错
2. **Kali 主动收集**
   - 子域：`subfinder` + 字典爆破（定向词表优先 `app` / `oa` / `his`）
   - 探活：`httpx`
   - 端口：`nmap` / `masscan`
   - 爬虫：`katana` / `gau`
3. **小程序探测** —— 首页出现 `mp.weixin.qq.com` / `wx.` 前缀 / `<wx-open-launch-weapp>` / 微信二维码时，
   把小程序提升为**一等资产**，记入 `state.md`，待 L4 后抓包（见 §2.4）

**产出**：`assets/`、`recon/`

**门禁**：至少一个存活资产；已去重；小程序已登记（如有）

### L2 攻击面分析与指纹识别

回答：这资产活着吗、入口是什么、技术栈是什么、**登录前后有什么差异**。

#### 2.1 未登录态

- **指纹**：技术栈、框架、CMS、中间件、WAF、CDN、云厂商
- **暴露面**：管理后台、Swagger/OpenAPI、GraphQL、Actuator、Jenkins、云存储、CI/CD、测试环境
- **已知漏洞线索**：版本 → CVE、默认口令、子域接管
- **接口枚举**：从 JS、Source Map、网络面板提取 API 端点 —— **最高产区**

#### 2.2 身份准备

注册 / 登录身份 A、B，会话落盘到 `sessions/`。

- 目标是 **≥ 2 个会话**（水平越权必须两个身份）
- 只拿到 A 也能推进 2.3；B 可在 L4-A2 之前补齐
- 遇滑块 / 验证码 / 实名 / 风控 → 转人机协作（§2.1）

**拿不到会话时**（人类也不在）：

- 2.3 跳过
- `state.md` 记 `sessions: 不可用` + 原因
- L3 的 `auth_state` / `role` 留空
- **L4-A1 ~ A4 全部标记「阻塞」** —— 不得静默跳过

#### 2.3 登录态

重复 2.1，**用同一套方法**，然后做双态对比。

| 通道 | 未登录态 | 登录态 |
|---|---|---|
| `kali` | 匿名扫描、目录爆破、参数 fuzz | 带 Cookie / Token 重放 |
| `chrome-devtools` | 匿名浏览、JS 审计、接口枚举 | 登录后功能遍历、多角色对比 |

**双态差异就是突破口** —— 同一接口在两种状态下的响应差异 → 未授权访问 / 越权。

**产出**：`surface/`（指纹 + 暴露面 + 目标卡片）、`sessions/`

**门禁**：存活 + 有技术栈 + 至少一个入口或暴露面

### L3 建模与测试矩阵

把入口变成矩阵：`endpoint × 参数 × 角色 × 认证状态 × 数据敏感度`。**只建模，不挖洞。**

- **接口来源**：爬虫、SPA 路由、XHR/Fetch、WebSocket、代理历史、JS 提取、历史 URL
- **参数**：URL、POST、JSON 字段、Header、Cookie、隐藏参数、GraphQL 字段
- **角色**：匿名 / A / B / admin
- **Token 与会话**：Cookie、JWT、OAuth、CSRF token
- **API 专项**：Swagger、GraphQL introspection、gRPC 反射、Webhook、旧版 API

**产出**：`surface/matrix.jsonl`

**门禁**：每个 endpoint 至少有参数、角色、认证状态

### L4 漏洞发现

**顺序**：L4-U 未登录 → L4-A1 单账号 → L4-A2 双账号越权 → L4-A3 提权 → L4-A4 差分

> 会话已在 **L2.2** 准备好，本层只消费，不重新登录。

| 层 | 重点 |
|---|---|
| **L4-U** 未登录 | 未授权 API、预认证 IDOR、SQLi、RCE、SSTI/XXE、SSRF 打云元数据、上传/穿越/LFI、密码重置逻辑、默认口令 |
| **L4-A1** 单账号 | 存储 XSS、CSRF、上传、API 越权、业务逻辑、支付/改价/退款、优惠券、竞态、试用绕过 |
| **L4-A2** 双账号 | IDOR/BOLA、水平越权、多租户绕过、邀请/拉新、重复领取、账号绑定、订单越权 |
| **L4-A3** 提权 | BFLA、批量赋值、JWT 篡改、IDOR 打管理员、隐藏后台、链式提权 |
| **L4-A4** 差分 | A→B 重放；匿名→用户；普通→管理员接口 |


**产出**：`findings/`（每条一个 `.md`）、`evidence/`

**门禁**：STANDALONE + 证据完整 → L5；CHAIN_ONLY 进链候选；DISCARD 停止

### L5 验证与漏洞链

#### 5.1 信息公开性核验（硬门禁）

**触发**：`info_disclosure` / `pii_leak` / `secret_leak` / `auth_bypass` / `idor` / `bola` / `bfla`，
或描述含"未授权 读取/下载/枚举/批量获取"。

**铁律：「未授权」≠「非公开」。** 先证明信息本非公开，再谈泄露。

**六项核验**：A 会话无关性 / B 游客可见性 / C 权限墙对照 / D 数据来源 / E 敏感字段抽样 / F 跨账号差分

| 结论 | 处理 |
|---|---|
| `public` | 禁止按数据泄露定级 |
| `semi_public` | 降级，不单独提交 |
| `private` | 保留数据泄露定级 |
| `unknown` | 禁止 ≥ 高定级与提交 |

#### 5.2 可复现与最小 PoC

- **可复现**：重放、换会话/账号/租户再验证，排除缓存与时间偶然；失败标 `NEED_RETEST`
- **最小 PoC**：只留必要请求，不拖库、不批量下载、不删改，**只证明影响，不扩大影响**

#### 5.3 漏洞链

节点 = finding / asset，边 = `chain_role`，终点 = 影响。

`chain_role`：`initial_access` `info_leak` `auth_bypass` `privilege` `pivot` `persistence` `client_exec` `money` `cloud`

**链必须证据关联，不能靠类型硬拼**

1. 节点绑定具体 `finding_id`；链上**不写裸类型名**
2. 同一条链的节点落在**同一注册域**（或显式声明的 pivot），否则是假链
3. `evidence_refs` = 成员 finding 证据的并集
4. 缺口要输出 `missing`（缺哪个 role）与 `next_actions`
5. `chain_role` 必须诚实：只在绕过**真正成功**时才写 `auth_bypass`

**产出**：`findings/`（验证后）、`chains.md`

**门禁**：可复现 + 影响清楚；泄露类必过信息公开性核验

### L6 报告与提交

**去重检查**：同一根因 / 同一 endpoint + 参数 / 同一修复方案 / 历史报告 → 标 `DUPLICATE`

**先问平台，再读模板**

1. **询问用户目标平台**（补天 / HackerOne / Bugcrowd / …）
2. 读 `assets/report_<平台>.md` 作为格式依据
3. **模板不存在时**：不要套用别的平台格式 —— 先向用户要该平台的字段要求，
   生成 `assets/report_<平台>.md` 之后再写报告

**提交策略**：`I1` / `I2` + 可复现 → 提交；`I3` 视条件依赖；`I4` 不单独提交（进链或丢弃）

**证据打包**：原始请求/响应、复现步骤、截图、差分对比、账号角色、时间戳、最小 PoC、脱敏

**提交前人工复核**：是否在授权范围、是否重复、是否会造成破坏、是否补充证据、是否调整等级

**经验回流**：收尾时起草四段式经验 → 用户过目 → 写入 `references/experience/`（见 §3）

**产出**：`report.md`、`submission_<id>.md`、`evidence/`

**门禁**：影响分级 `I1` / `I2` + 可复现 + 证据完整 + 无重复 + 人工复核通过 + 平台字段合规
