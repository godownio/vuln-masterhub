---
id: web-generic-ssrf-publiccms-method-gethtml-apptoken
title: PublicCMS /api/method/getHtml SSRF：appToken 调用任意 HTTP 并回显页面/时延探测内网端口
type: scenario
domain: web
path: web/generic/ssrf
technique: publiccms-method-gethtml-apptoken-ssrf
aliases:
- PublicCMS SSRF
- /api/method/getHtml
- GetHtmlMethod
- PublicCMS API 方法
- appToken 接口
- PublicCMS 应用授权
- 时延端口探测
tags:
- java
- publiccms
- ssrf
- api
- apptoken
- portscan
- cms
- httpclient
affected_versions: PublicCMS V4.0.202302.e（原文源码版本）
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V276
  verified_at: '2026-11-07T23:50:37+08:00'
  notes: 已对照原文与 17 张图核对：img02-03 MethodController 分发、img06 @RequestMapping(/method/{name}) 与 appToken 校验/authorizedApis、img08 GetHtmlMethod 的 url/parameters/body/headers 与 GET/POST 分支、img09 /api/appToken 换 token（appToken 93bcd6b2...、expiryDate 1699458910219）、img10/11 127.0.0.1:3306 7ms、8888 2055ms 的时延探测均一致；affected_versions 为原文源码目录 V4.0.202302.e（img01），保留。
---

## 一句话结论

PublicCMS 的 API 方法框架把 `/api/method/{name}` 暴露为通用方法调用入口，其中 `getHtml` 方法接收 url/parameters/headers，用 HttpClient 发起 GET/POST 并返回页面文本；攻击者用后台创建应用的 appKey/appSecret 调 `/api/appToken` 换取 token 后，可让服务器访问任意 URL（内网 HTTP、云元数据等）并把响应回显，还能根据响应时延判断内网端口是否开放。

## 原理

- **API 方法分发**：`MethodController` 映射 `@RequestMapping("/method/{name}")`，从 `methodMap` 取 `BaseMethod`；若 `method.needAppToken()` 为真，则校验 `appToken` 是否存在、过期，以及对应应用 `authorizedApis` 是否包含该方法名；随后把请求参数 `parameters[]` 包装成 `TemplateModel` 列表传给 `method.execute(request, list)`。
- **getHtml 方法**：`url = getString(0)`、`parameters = getMap(1)`、`body = getString(1)`、`headers = getMap(2)`；用 `HttpClients.custom().setDefaultRequestConfig(...)` 构造客户端：
  - `parameters` 非空或 `body` 非空 → `HttpPost`，`parameters` 作为 `UrlEncodedFormEntity`、否则用 `StringEntity`；
  - 否则 → `HttpGet`；
  - `headers` 中的键值逐个 `request.addHeader`；
  - 执行请求并把响应的 HTML 文本作为 `result` 返回。
  代码中没有目标 host 白名单、私网地址拦截或协议限制，url 完全由调用者控制。
- **appToken 获取**：`AppTokenDirective`（`/api/appToken?appKey=&appSecret=`）用 `appService.getEntity(appKey)` 查应用，比较 `appSecret`（`equalsIgnoreCase`），成功后生成 `SysAppToken(UUID, appId, now)` 并保存，返回 `appToken` 与 `expiryDate`；错误返回 `secretError`。后台“应用授权”页面可添加应用、查看/修改授权密钥并配置 `authorizedApis`。
- **为什么需要 token**：`getHtml` 的 `needAppToken()` 返回 true，未带有效 token/应用未授权该方法会返回 `NEED_APP_TOKEN_MAP`。因此攻击前提是拿到 appKey/appSecret（后台管理员、配置泄露、弱密钥或已泄露的 token）。
- **回显与探测**：`getHtml` 返回 `{"result": "<页面文本>"}`（或 null），可直接读取内网 HTTP 服务内容；对非 HTTP 端口，响应时延差异明显（原文 3306 约 7 ms、8888 约 2055 ms），可据此做内网端口探测。
- 该场景是“功能型 SSRF”：不是 URL 参数过滤疏漏，而是系统主动提供的通用 HTTP 客户端 API，且鉴权只到应用级，不限制目标网络位置。

## 触发条件

- 目标为 PublicCMS（原文源码版本 V4.0.202302.e），API 方法与 `MethodController` 启用。
- 后台已存在一个应用，`authorizedApis` 包含 `getHtml`，且攻击者获得其 appKey/appSecret 或有效 appToken（管理员权限、配置/前端泄露、弱密钥）。
- 服务器可出网或能访问目标内网地址；目标未对 API 方法做 host/私网白名单。
- 目标内网存在可访问的 HTTP 服务或需要探测的端口。

## 利用步骤

1. 获取凭据：登录后台“系统维护 → 应用授权”，添加/查看应用，记录 appKey、appSecret，并确认 `getHtml` 在授权方法列表中（或找到已泄露的 appToken）。
2. 换取 token：`GET /api/appToken?appKey=<key>&appSecret=<secret>`，响应中取 `appToken`、`expiryDate`。
3. 发起 SSRF：`GET /api/method/getHtml?appToken=<token>&parameters=http://<target>/<path>`；可加 `parameters=` 指定 POST 表单、`body=` 指定 POST 体、headers 作为第三参数（按接口的参数序列化方式）。
4. 读取回显：响应 `result` 即目标页面文本；访问 `http://127.0.0.1:<port>/` 等内网地址判断服务与内容。
5. 端口探测：对多个内网端口发起请求并比较响应时间/错误类型；开放但非 HTTP 的端口通常表现为连接成功后的等待/超时，关闭端口快速拒绝。
6. 扩展：对云环境尝试元数据地址（如 169.254.169.254）读取实例信息/临时凭据；对内部管理面板、Redis HTTP 接口等做进一步利用。

## PoC

```http
GET /api/appToken?appKey=<appKey>&appSecret=<appSecret> HTTP/1.1
Host: target:8080
```

```json
{"appToken":"<uuid>","expiryDate":1699458910219}
```

```http
GET /api/method/getHtml?appToken=<uuid>&parameters=http://127.0.0.1:8888/ HTTP/1.1
Host: target:8080
```

```json
{"result":"<内网页面 HTML>"}
```

```text
# 时延探测（原文实测）
parameters=http://127.0.0.1:3306  -> 约 7 ms   （端口关闭/快速拒绝）
parameters=http://127.0.0.1:8888  -> 约 2055 ms（端口开放，等待 HTTP 响应超时）
```

## 变体与关联

- 方法变体：同一 API 框架下的 `getUrl`、`getTextFromHtml`、`getSiteFile` 等方法可能也具备 URL 访问/文件读取能力，审计时应逐个检查 `views/method` 下的实现。
- 参数变体：`parameters`（表单）、`body`（原始体）、`headers` 可控，可模拟内网服务的 POST 请求或带特定 Host/Authorization 访问。
- 凭据变体：appToken 过期后需重新换取；appSecret 可能在后台页面、前端 JS、配置文件、日志、备份中泄露；`equalsIgnoreCase` 比较不引入安全问题，但弱 secret 可被猜解。
- 关联卡片：[[web-generic-ssrf-redirect-gopher-localhost-portscan-omi]]（时延/重定向端口探测思路）、[[web-generic-ssrf-ip-notation-blacklist-bypass]]（私网绕过，本场景无过滤不需要）、[[cloud/metadata]] 相关云元数据卡、[[web-generic-ssrf-avatar-urlopen-internal-service]]（功能型 SSRF 对比）。
- 边界：拿不到 appKey/appSecret 或 appToken 时无法调用；应用未授权 `getHtml` 时返回 `NEED_APP_TOKEN_MAP`；服务器出站被防火墙限制、或目标内网服务需非 HTTP 协议时效果受限；该接口只回显文本，二进制协议需另找 sink。

## 检测与防御

- 检测：短时间大量 `/api/method/getHtml` 请求，`parameters` 指向 localhost、RFC1918、169.254.169.254 等地址；请求间响应时间差异异常；同一 appToken 高频调用不同内网端口；`/api/appToken` 异常换取行为。
- 防御：对 API 方法的 url 做严格允许列表（域名/协议/端口），拒绝私网与元数据地址；限制 `authorizedApis` 最小权限，`getHtml` 默认不授权给普通应用；appSecret 强随机、定期轮换、不在前端/日志中泄露；限制服务器出站与内网访问。
- 加固：关闭不需要的 API 方法；对 API 调用做审计与速率限制；云环境启用 IMDSv2 并限制跳数；监控异常 URL/响应时延。
