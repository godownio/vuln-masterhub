---
id: web-java-component-landray-ekp-redirectservlet-uiext-unauth-file-read
title: '蓝凌 EKP RedirectServlet `/ui-ext/**` 匿名路径未授权文件读取：`/./ui-ext/./` 绕过前缀判断，拼接 file: URL 读 resource 目录与请求日志'
type: scenario
domain: web
path: web/java/component
technique: landray-ekp-redirectservlet-uiext-unauth-file-read
tags:
- java
- landray
- ekp
- oa
- unauth
- file-read
- path-traversal
- redirectservlet
- spring-security
- tomcat
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: V15 等（原文标注）
verification:
  verified_by: verifier-V676
  verified_at: '2026-11-13T12:12:13+08:00'
  notes: '已对照原文与全部6张截图核对：img01 GET /./ui-ext/./behavior 200 返回 request.log/request.log.2023-01-08/01-09/03-26 等列表（Server: Apache-Coyote/1.1、Content-Type: application/octet-stream）、img02 spring.xml anonymousPaths 含 /ui-ext/**、img03 web.xml uiredirect→com.landray.kmss.web.servlet.RedirectServlet 的 forwardPath=file:${kmss.resource.path}/ui-ext/、requestPath=/ui-ext/、anonymous=true、img04 service() 分支 if (!url.endsWith(".theme.css") || !url.startsWith("/ui-ext/") && !url.startsWith("//ui-ext/"))、img05 调试值 req=/./ui-ext/./behavior、requestPath=/ui-ext/、forwardPath=file:c:/landray/kmss/resource/ui-ext/、img06 GET //ui-ext/ 列出 business_blackGold/gov_blue/gov_ink/gov_red/iced/initpackage/sky_blue_for_BigFontSize/sky_orange，均与原文一致；getFileName 代码逐字一致，替换拼接结果 file:c:/landray/kmss/resource/ui-ext//././behavior 按 img05 调试值与代码正确（原文正文写的 /ui-ext//../behavior 与其自身调试值有出入，卡内按截图/代码描述）。affected_versions『V15 等』逐字对应原文『V15等』。dedup：与同产品 sysUiComponent replaceExtend（V16 目录复制）、dataxml s_bean BeanShell RCE 的入口/组件/利用结果均不同，非同链。未验证点：未在本机复跑；具体目录/文件随部署变化。'
url: /docs/web/java/component/web-java-component-landray-ekp-redirectservlet-uiext-unauth-file-read/
draft: false
kb_aliases:
- 蓝凌 EKP 未授权文件读取
- Landray EKP ui-ext
- RedirectServlet 文件读取
- /./ui-ext/./behavior
- //ui-ext/ 绕过
- EKP request.log 读取
---

## 一句话结论

蓝凌 EKP（V15 等）在 spring.xml 把 `/ui-ext/**` 配成匿名路径，对应 web.xml 的 `RedirectServlet`（`anonymous=true`、`forwardPath=file:${kmss.resource.path}/ui-ext/`、`requestPath=/ui-ext/`）；由于 `service()` 用字符串 `startsWith("/ui-ext/")` 判断分支，请求 `/./ui-ext/./behavior` 会绕过该判断进入 `redirect()`，`getFileName` 把 URI 里的 `/ui-ext/` 替换掉后拼进 `file:` URL 并用 `new URL(fileName).openConnection()` 读取，结果可未授权列出/读取 resource 目录下的文件（实测列出 `request.log` 系列请求日志）；`//ui-ext/` 还能直接列出 ui-ext 目录。

## 原理

- **匿名路径与 Servlet 配置**：spring.xml 的 `anonymousPaths` 包含 `/ui-ext/**`、`/resource/**` 等；web.xml 中 `uiredirect` 映射到 `com.landray.kmss.web.servlet.RedirectServlet`，init-param 为 `forwardPath=file:${kmss.resource.path}/ui-ext/`、`requestPath=/ui-ext/`、`anonymous=true`。
- **分支判断被 `/./` 绕过**：`service()` 中 `url = request.getRequestURI().replaceFirst(request.getContextPath(), "")`，随后 `if (!url.endsWith(".theme.css") || !url.startsWith("/ui-ext/") && !url.startsWith("//ui-ext/"))` 才走 `redirect()`，否则走 `ThemeUtil`。`/./ui-ext/./behavior` 既不以 `/ui-ext/` 也不以 `//ui-ext/` 开头，条件成立，进入 `redirect()`；而 Spring Security 的匿名匹配按规范化后的 `/ui-ext/**` 放行，因此未授权即可到达。
- **路径拼接与读取**：`getFileName` 为 `req = URI - contextPath; req.replaceFirst(requestPath, ""); return forwardPath + req`。调试值：`req=/./ui-ext/./behavior`、`requestPath=/ui-ext/`、`forwardPath=file:c:/landray/kmss/resource/ui-ext/`；替换并拼接后为 `file:c:/landray/kmss/resource/ui-ext//././behavior`，URL/文件层归一化后落到 `resource/ui-ext/behavior`，返回目录下的 `request.log`、`request.log.2023-*`；结合 `..` 段可穿越到 resource 其他目录读取文件。
- **`//ui-ext/` 变体**：Spring MVC 默认把连续多个 `/` 视为一个，`//ui-ext/` 仍匹配匿名规则并在 `requestPath` 替换后残留一个 `/`，拼成 `.../resource/ui-ext//`，直接列出 ui-ext 目录（观察到 `business_blackGold`、`gov_blue`、`gov_ink`、`gov_red`、`iced`、`initpackage`、`sky_blue_for_BigFontSize`、`sky_orange` 等子目录）。
- **过滤缺口**：`redirect()` 只检查 `.ini`、`%c0`、`%00`，不处理 `.`/`..` 与多重斜杠；安全检查基于原始字符串前缀，实际资源定位在 URL/文件系统归一化之后，两者不一致即形成穿越/越权读取。
- **危害**：request.log 记录请求 URL 与参数，可能包含会话、账号、内网地址等敏感信息；resource 目录还可能有配置与业务文件，为后续登录/横向提供素材。

## 触发条件

- 目标为受影响蓝凌 EKP（V15 等），`/ui-ext/**` 为匿名路径，`RedirectServlet` 配置如上。
- 攻击者可访问 Web 端口；前置代理/WAF 未对 `/./`、`//`、编码点段做规范化或拦截。
- `kmss.resource.path` 指向的 resource 目录存在可读文件（日志/配置/业务静态资源）。

## 利用步骤

1. 指纹识别蓝凌 EKP 与版本（登录页、静态资源路径、`/ui-ext/` 资源）。
2. 发送 `GET /./ui-ext/./behavior`，观察是否 200 且返回目录列表或文件内容。
3. 根据返回的目录结构，用 `..` 或已知目录/文件名继续读取 resource 下其他文件（如配置、日志、备份）。
4. 另试 `GET //ui-ext/` 直接列举 ui-ext 目录，确认多重斜杠变体。
5. 从 request.log 中提取请求参数、会话标识、内网地址等线索，用于后续认证绕过/横向。

## PoC

```http
GET /./ui-ext/./behavior HTTP/1.1
Host: target
Accept: text/plain, */*; q=0.01
Connection: close
```

```text
HTTP/1.1 200 OK
Content-Type: application/octet-stream
...
request.log
request.log.2023-01-08
request.log.2023-01-09
request.log.2023-03-26
...
```

```http
GET //ui-ext/ HTTP/1.1
Host: target
```

```text
HTTP/1.1 200 OK
business_blackGold
gov_blue
gov_ink
gov_red
iced
initpackage
sky_blue_for_BigFontSize
sky_orange
```

（请求与响应取自原文截图；未在本机复跑，具体目录/文件随部署变化。）

## 变体与关联

- [[web-java-component-landray-ekp-dataxml-sbean-beanshell-rce]]、[[web-java-component-landray-ekp-sysuicomponent-replaceextend-directory-copy]]：同产品其他未授权/RCE 链，可组合利用。
- [[web-java-framework-spring-ghost-bits-path-traversal]]、[[web-java-component-openfire-cve-2023-32315-authcheckfilter-u002e-traversal]]：同为“过滤器/框架按字符串判断路径、容器再归一化”的解析差异类问题。
- 变体：`/./` 段可换 `//`、多点段、URL 编码变体；目标目录可换 resource 下任意子目录；结合 `..` 可跨出 ui-ext。
- 边界：前置代理统一 canonical 化、WAF 拦截 `/./`/`//`、官方补丁修复前缀判断后失效。

## 检测与防御

- 检测：请求路径出现 `/./`、`//` 等非规范段并访问 `/ui-ext/`；短时间内大量访问 `request.log*` 或 resource 目录；响应为 `application/octet-stream` 的目录列表；访问日志与文件读取异常。
- 防御：联系官方打补丁（原文修复方式）；前置代理对路径做规范化并拒绝点段/重复斜杠；对 `/ui-ext/**` 增加鉴权而非匿名；限制 resource 目录下敏感文件（日志、配置）可读性；日志脱敏并避免记录敏感参数。
