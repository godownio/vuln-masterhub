---
id: web-generic-file-inclusion-monitoring-platform-downloadfile-filepath-traversal
title: 在线监控信息管理平台 downloadFile.action 的 filePath 直接拼接导致 ../ 路径遍历任意文件下载（实测读取 /etc/passwd）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: monitoring-platform-downloadfile-filepath-traversal-read
tags:
- java
- struts2
- path-traversal
- arbitrary-file-read
- file-download
- spring-security
- code-audit
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V509
  verified_at: '2026-11-11T04:56:19+08:00'
  notes: 已对照原文 content.md 与 9 张截图核对：图01 applicationContext-security.xml 中 login.jsp* 匿名放行；图02 login.jsp openApplyFrame 以 iframe 加载 /recordApply/applyPage.action；图03 备案申请页含模板下载/上传；图04 file1=123.jsp 上传返回 statusCode 200 但回显路径未知；图05 实测 GET /recordApply/downloadFile.action?filePath=/recordApplyTemplate/../../../../../../etc/passwd 返回 200、Content-Disposition attachment;filename=passwd 与 /etc/passwd 内容（请求携带 JSESSIONID，属登录会话）；图06/07 changePassword.action 前端与实测 fail；图08 默认口令 addOrganizationUser；图09 SMTP 明文凭据（打码）。已按要求将“原理”中的背景说明改写为“仅停留在代码层、未验证最终利用，此处仅作背景”，并同步知识库与 staging，不改变原意、不新增结论。去重：与 mee-admin filePath、LuckyFrameWeb、cmsv6 等为不同产品/端点，属同类 sink 单独立卡，非同链。非组件漏洞，无 affected_versions。原文仅短说明+截图，PoC 按图05 请求整理。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-monitoring-platform-downloadfile-filepath-traversal/
draft: false
kb_aliases:
- downloadFile.action 任意文件下载
- filePath 路径遍历下载
- recordApplyTemplate 穿越
- 监控信息管理平台文件下载漏洞
- Java 下载接口 ../ 读文件
---

## 一句话结论

在线监控信息管理平台的 `/recordApply/downloadFile.action` 把请求参数 `filePath` 直接用于文件读取且未做路径规范化或根目录约束，已登录用户（或经被匿名放行的前端页面触达该功能时）用 `/recordApplyTemplate/../../../../../../etc/passwd` 即可下载服务器任意文件；源码审计同时发现 Spring Security 将 `/WEB-INF/views/jsp/login.jsp*` 设为匿名访问、login.jsp 内嵌备案申请等业务页面，放大了该功能的可达面。

## 原理

- **参数直入文件路径**：下载接口接收 `filePath` 参数，业务代码按“模板目录 + filePath”定位文件后交给下载逻辑，没有 `getCanonicalPath`/`normalize` 校验，也没有限制结果必须位于模板根目录内。`../` 序列在文件系统解析时逐级回退，最终指向模板目录之外的任意路径。
- **模板目录是穿越起点**：请求 `filePath=/recordApplyTemplate/../../../../../../etc/passwd` 时，前缀为合法的模板目录，后续 `../` 把路径抬到根并落到 `/etc/passwd`；服务端以应用进程权限读取并回写响应，`Content-Disposition: attachment; filename=passwd` 表明文件被当作下载附件原样返回。
- **Spring Security 白名单放大可达面**：`applicationContext-security.xml` 中另有 `intercept-url pattern="/WEB-INF/views/jsp/login.jsp*" access="IS_AUTHENTICATED_ANONYMOUSLY"`，login.jsp 本身匿名可访问；login.jsp 里的前端函数（如 `openApplyFrame`）把 `/recordApply/applyPage.action` 等业务页以 iframe 加载，说明 part 业务功能与登录页耦合，攻击者可以从公开页面进入申请/下载相关功能，减少“需要先登录”的门槛（实际是否未授权可下载取决于对应 action 的拦截配置，实测请求携带了登录会话）。
- **为什么是完整危害**：任意文件读取可直接拿到系统账号（/etc/passwd 用户名列表）、应用配置文件（数据库/SMTP/第三方凭据）、源码、日志、密钥与证书；若与其他漏洞（如配置中的明文 SMTP 凭据、文件上传）组合，可进一步横向或持久化。本文实测已读出 /etc/passwd，属于已验证的任意文件下载。
- **同功能点的其他审计发现**（仅停留在代码层、未验证最终利用，此处仅作背景）：该模块还存在任意文件包含与任意文件上传的迹象，但上传回显路径未知、文件包含缺少可复现细节；login.jsp 的 `changePassword.action` 存在未授权改密逻辑，但参数为 userId 且实测返回 fail（无法映射用户）；代码中另有默认口令与配置文件明文 SMTP 凭据，均未证明实际危害。

## 触发条件

- 目标为 Java Web（Struts2 `.action` 路由）的在线监控信息管理平台，存在 `recordApply` 备案申请模块与 `downloadFile.action`。
- 攻击者能访问登录页/业务页面并持有有效低权限会话（或目标对相关 action 的拦截缺失，可未授权访问）。
- `filePath` 参数可控且未做规范化/白名单；应用进程对目标文件有读权限。
- 目标未被反向代理/WAF 拦截 `../`、`%2e%2e` 等穿越特征（编码变体见关联卡）。

## 利用步骤

1. 登录系统（或从匿名可访问的 login.jsp 及其 iframe 业务页进入申请/备案功能），抓取模板下载请求，确认参数名 `filePath` 与模板目录前缀（如 `/recordApplyTemplate/`）。
2. 将 `filePath` 改为 `/recordApplyTemplate/../../../../../../etc/passwd`，发送 GET，确认响应为文件内容且 `Content-Disposition` 为附件下载。
3. 按需读取：`/etc/passwd`（用户名枚举）、应用配置文件（如 `applicationContext-*.xml`、`jdbc.properties`、`web.xml`）、日志、`/proc/self/environ`、SSH 配置等；Windows 目标改读 `C:\Windows\win.ini` 与配置文件。
4. 若 `../` 被过滤，尝试 URL 编码（`%2e%2e%2f`）、双重编码、反斜杠（Windows）等变体；通过响应长度/错误差异判断命中。
5. 使用读取到的凭据/路径信息评估横向影响；全程仅限授权测试。

## PoC

```http
GET /recordApply/downloadFile.action?filePath=/recordApplyTemplate/../../../../../../etc/passwd HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
Connection: close
```

```http
HTTP/1.1 200
Content-Type: application/octet-stream
Content-Disposition: attachment;filename=passwd

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
...
```

说明：实测响应成功返回 `/etc/passwd` 内容；不同部署的模板目录前缀与 `../` 层数需按实际调整。

## 变体与关联

- **编码/变形绕过**：`../` 被简单过滤时可尝试 `%2e%2e%2f`、`%252e%252e%252f`、`..\`（Windows）等（[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]、[[web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal]]）。
- **同类 Java 下载接口**：`new File(base + filePath)` 型路径拼接是该类漏洞的典型根因（[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]）；产品化案例如 [[web-generic-file-inclusion-jhsoft-downloadbgimage-path-read]]、[[web-generic-file-inclusion-cmsv6-downloadlogger-filename-read]]。
- **时间/权限放大**：下载接口若同时支持删除或写操作，可升级为任意文件删除（[[web-java-oa-download-servlet-followup-delete-arbitrary-file]]）。
- **Spring Security 白名单**：`login.jsp` 匿名放行本身是正常登录页配置，但当登录页内嵌业务 action 时可造成未授权触达；单独的白名单问题需结合 action 拦截配置验证，不宜直接判为认证绕过。

## 检测与防御

- **代码修复**：下载接口用 `Paths.get(templateRoot, fileName).normalize()` 后校验 `startsWith(templateRootCanonical)`，或只允许从数据库/映射表按 ID 取文件；禁止 `filePath` 含 `..`、绝对路径与路径分隔符；对文件扩展名做白名单。
- **鉴权**：下载接口统一接入认证与对象级授权；不要仅依赖前端按钮隐藏；Spring Security 对业务 action 的最小放行范围逐条核对，登录页放行不应波及其内嵌业务接口。
- **部署加固**：应用进程最小权限运行，敏感配置/密钥目录只读且与 Web 目录隔离；反向代理/WAF 对 `../`、`%2e`、`..\` 解码后统一规范化再匹配。
- **检测**：访问日志中 `filePath`/`filename` 参数含 `../`、`/etc/`、`C:\`、`%2e` 的请求；同一会话批量请求系统文件与配置文件；响应头 `Content-Disposition: attachment` 对应的异常路径；结合 EDR/inotify 发现应用进程异常读取敏感目录。
- **应急**：确认泄露文件范围，轮换配置中出现的数据库/SMTP/第三方凭据；审计异常下载记录与来源 IP；修复后回归模板下载与权限控制。
