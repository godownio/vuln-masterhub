---
id: web-generic-file-inclusion-crm-jsp-include-forward-param-read
title: MetaCRM JSP include/forward 参数未过滤导致任意文件读取（限 Tomcat 目录）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: crm-jsp-include-forward-param-file-read
tags:
- java
- jsp
- file-read
- file-inclusion
- path-traversal
- crm
- unauth
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:23:36+08:00'
  notes: 已对照原文与26张图核对：toviewspecial.jsp view→jsp:include、download-new.jsp page→jsp:forward、未登录可读 WEB-INF/web.xml、受 Tomcat 目录限制无法穿越系统根目录，均与图06-09一致。dup-scan pair#5 报与 crm-download-jsp-aes 为 likely_duplicate，按原文裁决为误报：本卡是前台 JSP include/forward 参数（无需登录，限 Tomcat 目录），另一卡是后台 download.jsp AES 加密 p 参数+JSON file 路径穿越 FileInputStream（需登录，可读 dbinfo.prop），端点/鉴权/读取方式均不同，两卡并列保留；pair#8/41/44/59/63 均 related。affected_versions 原取自 classpath 的测试环境版本，已按 brief clear。未复跑 PoC。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-crm-jsp-include-forward-param-read/
draft: false
kb_aliases:
- toviewspecial.jsp 文件读取
- download-new.jsp 文件读取
- JSP include 任意文件读取
- JSP forward 任意文件读取
- MetaCRM 前台文件读取
- view 参数文件包含
---

## 一句话结论

MetaCRM7 前台的 `toviewspecial.jsp` 把请求参数 `view` 直接传入 `<jsp:include page="...">`，`download-new.jsp` 把参数 `page` 直接传入 `<jsp:forward page="...">`；两个 JSP 都没有对参数做路径/资源白名单校验，未登录即可读取 `WEB-INF/web.xml` 等 Tomcat 应用目录内文件，但受容器解析限制无法穿越到系统根目录。

## 原理

- **toviewspecial.jsp**：页面先设置默认视图 `/business/common/view/nullView.jsp`，然后 `String strView = request.getParameter("view"); if (strView != null && strView.length() > 0) strURL = strView;`，最终 `<jsp:include page="<%=strURL%>" />`。`<jsp:include>` 在请求处理时把 page 属性当作 Web 资源路径解析并包含其输出；参数完全可控时，攻击者可以指定 `/WEB-INF/web.xml` 等受保护路径。
- **download-new.jsp**：页面取 `filename` 与 `page`，设置 `Content-Disposition: attachment; filename="..."`，随后 `<jsp:forward page="<%=strPage%>" />`。`<jsp:forward>` 把请求转发到 page 指定的资源，响应体即为该资源的内容；`page=/WEB-INF/web.xml` 时返回完整 web.xml。
- **为什么无需登录**：两个 JSP 位于 `/business/common/` 前台目录，代码中未做 session/用户校验；攻击者直接请求即可触发。
- **为什么只能读 Tomcat 目录**：`<jsp:include>`/`<jsp:forward>` 的 page 路径由 Servlet 容器按 Web 应用上下文解析，通常拒绝或规范化跳出应用根目录的 `../`，因此能读 Web 应用与 Tomcat 配置目录内文件（如 `WEB-INF/web.xml`、`WEB-INF/classes`、`META-INF`、Tomcat conf），但难以直接读 `C:\Windows\...` 或 `/etc/passwd`。原文实测读到了 web.xml，但无法穿越到系统根目录。
- **危害**：web.xml 暴露 servlet 映射、数据库/JNDI 配置、框架版本；结合 `WEB-INF/classes` 下的配置文件可进一步获取数据库口令、密钥与内部接口，为后续 SQL 注入、反序列化或后台利用提供情报。单独看是“有限文件读取”，不是直接 RCE。

## 触发条件

- 目标部署 MetaCRM7，`/business/common/toviewspecial.jsp` 与/或 `/business/common/download-new.jsp` 可从攻击面访问。
- `view` 或 `page` 参数未被 WAF/过滤器拦截，且容器允许 include/forward 到 `WEB-INF` 下资源（Tomcat 默认对 JSP include/forward 允许）。
- 目标文件位于 Web 应用或 Tomcat 可解析范围内；攻击者知道相对路径。
- 无需登录；若前面有统一网关鉴权，则该链被阻断。

## 利用步骤

1. 探测两个 JSP 是否存在：请求 `/business/common/toviewspecial.jsp?view=/WEB-INF/web.xml` 与 `/business/common/download-new.jsp?filename=1&page=/WEB-INF/web.xml`。
2. 观察响应：`toviewspecial.jsp` 的响应体应包含 web.xml 内容（可能被包在页面 HTML 中）；`download-new.jsp` 会以附件形式返回 web.xml，响应头 `content-disposition: attachment; filename="1"`。
3. 按需调整路径读取 `WEB-INF/classes/` 下的配置文件、`WEB-INF/` 下的 Spring/CXF 配置、Tomcat `conf/server.xml` 等（是否可达取决于容器工作目录与 include 解析规则）。
4. 从 web.xml 提取 servlet 映射、数据库配置、JNDI/数据源、CXF 端点等，转入其他漏洞（SQL 注入、XXE、后台弱口令）继续利用。
5. 若被 `../` 过滤，尝试 URL 编码、双重编码、`..%2f`、`..;/` 等容器解析差异；若只能读应用内文件，优先读配置而非盲目穿越。

## PoC

```http
GET /business/common/toviewspecial.jsp?view=/WEB-INF/web.xml HTTP/1.1
Host: target
```

```http
GET /business/common/download-new.jsp?filename=1&page=/WEB-INF/web.xml HTTP/1.1
Host: target
```

```http
HTTP/1.1 200 OK
Content-Type: application/xml;charset=utf-8
Content-Length: 13647
content-disposition: attachment; filename="1"

<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0" ...>
  ...servlet-mapping / druid / CXFServlet...
</web-app>
```

## 变体与关联

- 变体：`<jsp:include>` 与 `<jsp:forward>` 两个 sink；同一应用内其他 JSP 若把请求参数传给 include/forward/`RequestDispatcher`，同样可读。
- 变体：若容器允许 `file://` 或绝对路径，可能扩大读取范围；多数 Tomcat 版本会限制在 Web 应用上下文。
- 关联：[[web-generic-file-inclusion-crm-getfile-filename-folder-traversal]]（同产品另一条 AES 参数 + 路径穿越的任意文件读取，需登录/不同 servlet）、[[web-generic-file-inclusion-hanvon-eface-filepath-fileinputstream]]（JSP 参数直入 FileInputStream 的同类文件读取）。
- 边界：只读文件、不执行代码；受 Tomcat 目录限制；若 WAF 拦截 `WEB-INF` 或 include/forward 参数则失效。

## 检测与防御

- 检测：请求 `toviewspecial.jsp`/`download-new.jsp` 且参数含 `/WEB-INF/`、`META-INF`、`../`、`..%2f`、`file://`；响应体出现 XML 配置/class 内容或附件下载非业务文件；同一 IP 短时间枚举多个 JSP 路径。
- 修复：不要把请求参数直接传给 `<jsp:include>`/`<jsp:forward>`；改为服务端白名单视图 ID 到固定 JSP 的映射；对路径做规范化并校验必须位于允许目录；禁止 include/forward 到 `WEB-INF` 下非预期资源。
- 加固：统一鉴权覆盖 `/business/common/*`；WAF 拦截 `WEB-INF`、`META-INF`、路径穿越特征；Tomcat 升级到对 include/forward 路径做严格校验的版本；最小化 web.xml 中的敏感信息。
