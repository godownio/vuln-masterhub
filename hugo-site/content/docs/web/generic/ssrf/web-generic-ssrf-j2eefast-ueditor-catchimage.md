---
id: web-generic-ssrf-j2eefast-ueditor-catchimage
title: J2eeFAST 集成 UEditor catchimage：source[] URL 未限制，十进制 IP 绕过 catcherLocalDomain 触发 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: ueditor-catchimage-source-ssrf
tags:
- ssrf
- java
- ueditor
- catchimage
- decimal-ip
- internal-network
- j2eefast
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:59:16+08:00'
  notes: 已对照原文及25张图核对：图17-19确认ImageHunter.captureRemoteData→capture→ActionEnter.invoke case CATCH_IMAGE；图20确认action=catchimage映射；图21-22确认catcherFieldName=source、catcherLocalDomain=[127.0.0.1,localhost,img.baidu.com]；图23-24确认exec的callback正则校验；图25确认/file/ueditor/config入口。payload action=catchimage&source[]=http://2130706433:8080/admin&callback=test 与原文一致。核对时清除affected_versions：1.6.0仅为原文审计版本，非原文标注的受影响区间。未验证点：原文未展示catcherLocalDomain主机校验代码与实际响应/抓取结果，十进制IP绕过为结合配置与payload的推断；frontmatter无source_url；未本机复跑。
url: /docs/web/generic/ssrf/web-generic-ssrf-j2eefast-ueditor-catchimage/
draft: false
kb_aliases:
- UEditor catchimage SSRF
- 百度富文本 SSRF
- source[] SSRF
- catcherLocalDomain 绕过
- 2130706433 SSRF
- J2eeFAST SSRF
---

## 一句话结论

J2eeFAST 1.6.0 的 UEditor 接口 `/file/ueditor/config` 支持 `action=catchimage`，会把请求参数 `source[]` 中的 URL 交给 `ImageHunter.captureRemoteData` 发起服务端连接并保存响应；`source` 数组完全由客户端控制，配置里的 `catcherLocalDomain` 只做字符串级域名判断，使用十进制 IP `2130706433`（即 127.0.0.1）即可绕过并访问内网服务，形成 SSRF。

## 原理

- 入口：`SysUeditorController` 映射 `/file/ueditor/**`，`/config` 方法创建 `ActionEnter(request, rootPth, "config")` 并调用 `exec()`。
- `ActionEnter.exec()` 读取 `callback` 参数并用 `^[a-zA-Z_]+[\w0-9]*$` 校验；随后 `invoke()` 按 `actionCode` 分支。
- `action=catchimage` 映射到 `ActionMap.CATCH_IMAGE`：从 UEditor 配置取 `fieldName`（默认 `source`），`request.getParameterValues(fieldName)` 得到 URL 数组，交给 `ImageHunter.capture(list)`。
- `capture` 遍历数组，对每个 URL 调 `captureRemoteData(urlStr)`：打开连接、校验响应状态、MIME 后缀、Content-Length，最后 `StorageManager.saveFileByInputStream(connection.getInputStream(), physicalPath)` 把远端内容写入服务器上传目录。
- 配置中的 `catcherLocalDomain` 为 `["127.0.0.1","localhost","img.baidu.com"]`，说明本意是允许抓取这些“本地/可信”域；但校验按字符串匹配主机名，攻击者用十进制整数形式的 IP（`2130706433` 等价于 `127.0.0.1`）或其它等价表示即可绕过，让服务器访问回环/内网。
- 即使响应不是允许的图片类型、最终未落盘，连接和请求已经由服务器发出，因此 SSRF 原语成立；若响应为图片且大小符合限制，内容还会落盘到上传目录，可能通过返回 URL 读取，形成“SSRF + 任意远端文件抓取”。
- 根因：把用户提供的 URL 直接交给服务端 HTTP 客户端，且只用字符串黑名单限制目标，没有在解析后校验 IP、协议和端口。

## 触发条件

- 目标为 J2eeFAST 1.6.0（原文测试版本），UEditor 接口 `/file/ueditor/config` 可达（需确认 Shiro 是否放行该路径）。
- UEditor 配置启用 `catchimage`，`catcherFieldName` 为 `source`（官方默认）。
- 应用服务器可出站访问目标地址（回环、内网、云元数据或攻击者 HTTP 服务）。
- 目标未在网关/WAF 层拦截 `source[]` 参数或 `catchimage` action。

## 利用步骤

1. 访问 `/file/ueditor/config?action=config` 确认 UEditor 配置接口存在，返回 JSON。
2. 发送 `POST /file/ueditor/config`，`action=catchimage`、`callback=test`，`source[]` 填内部地址；先用可回显的地址（如攻击者 HTTP 服务或内网已知端口）确认请求到达。
3. 用十进制 IP `http://2130706433:8080/admin` 访问 127.0.0.1 的管理端口；也可尝试 `http://0177.0.0.1/`、`http://[::1]/` 等等价写法。
4. 若响应为图片且符合 MIME/大小限制，检查返回值/上传目录中是否出现抓取内容；非图片响应则通过响应时间、错误信息或外部 DNS/HTTP 日志确认 SSRF。
5. 将目标换成云元数据地址或内网敏感服务，评估可读取的数据。
6. 记录请求与出站请求证据；验证后停止。

## PoC

```http
POST /file/ueditor/config HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

action=catchimage&source[]=http://2130706433:8080/admin&callback=test
```

`2130706433` 是 `127.0.0.1` 的十进制表示；`callback=test` 满足 `^[a-zA-Z_]+[\w0-9]*$` 校验。原文给出该 payload 与完整调用链，但未展示实际响应/抓取结果截图。

## 变体与关联

- 变体：`source[]` 传多个 URL 可批量探测；UEditor 的 `catcherLocalDomain` 若被改为空/包含内网域名，限制更弱。
- 变体：使用 `http://0x7f000001/`、`http://017700000001/`、`http://127.1/` 等等价 IP 形式绕过字符串黑名单。
- 变体：`action=uploadfile`/`uploadimage` 等其他 UEditor action 也可能存在文件写入/路径问题，可结合审计。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]（等价 IP 表示绕过 SSRF 黑名单的通用原理）。
- 关联：[[web-generic-ssrf-cloud-metadata]]（SSRF 读取云元数据获取临时凭证）。
- 关联：[[web-generic-file-upload-ueditor-filepathformat-traversal]]（同一 UEditor 组件的文件路径穿越问题）。

## 检测与防御

- 防御：不要允许 UEditor 抓取任意 URL；对 `source` 做协议（仅 http/https）、主机白名单和解析后 IP 校验，拒绝回环、私有、链路本地与云元数据地址。
- 防御：连接时固定已校验的 IP（防 DNS rebinding），并限制端口；禁止跟随到内网的重定向。
- 防御：升级/加固 UEditor 配置，关闭不必要的 `catchimage`，或把抓取功能放到独立出站代理并做网络隔离。
- 检测：审计 `captureRemoteData`、`getInputStream`、`source[]` 参数；对 `source[]` 中出现十进制/十六进制 IP、`127.0.0.1`、`169.254.169.254`、内网网段等特征告警。
- 检测：应用服务器异常出站连接、上传目录出现来源不明的远程图片；UEditor 接口被大量不同 `source` 参数调用。
