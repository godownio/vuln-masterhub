---
id: web-generic-file-upload-upload1-filename-traversal-jsp-webroot
title: 上传接口不校验内容与类型且原始文件名含 ../：穿越写 JSP 到 Tomcat webapps
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-filename-traversal-jsp-webroot
aliases:
- upload1.do 路径穿越
- 文件名穿越写 JSP
- 未授权上传 Tomcat webapps
- attachment 目录穿越
tags:
- file-upload
- path-traversal
- jsp
- tomcat
- webshell
- java
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:39:57+08:00'
  notes: 已对照图03/08/10核对；upload1.do表单字段file、未校验内容类型、filename含../../../../../../datahome/tomcat8_case/webapps/case/test11111.jsp并按Base64 url回显一致；原文仅文字称1+1 JSP可解析，未见访问返回2的截图；PoC未复跑
---

## 一句话结论

上传接口只接收 `file` 参数、不校验文件内容与类型，且保存时使用客户端原始文件名而不取 basename；把 `filename` 写成 `../../../../datahome/<app>/webapps/<app>/shell.jsp`，文件就会跳出上传目录落到 Tomcat Web 根，访问该 JSP 即执行。

## 原理

- multipart 请求的 `Content-Disposition: form-data; name="file"; filename="..."` 中，`filename` 完全由客户端控制。
- 服务端通常把“上传根目录 + 原始文件名”直接拼接后写文件；若没有 `FilenameUtils.getName()`、`Paths.get(...).normalize()` 或 `startsWith(uploadDir)` 校验，`../` 会按操作系统路径语义跳出上传目录。
- 上传目录（如 `/datahome/attachment/`）通常禁止脚本解析，但 Web 根（如 `/datahome/<app>/webapps/<app>/`）由 Tomcat 部署，目录内的 `.jsp` 会被编译执行；路径穿越把文件送到“可解析且可访问”的位置，绕过“上传目录不可执行”的加固。
- 响应常回显上传后的相对路径或 Base64 编码的 URL；解码后可确认实际落盘位置（含穿越片段），也便于构造访问 URL。
- 该接口若未授权或仅需低权限账号，攻击者无需登录后台即可写 WebShell；即使需要登录，也可用作后台到 RCE 的升级。

## 触发条件

- 上传接口可达（未授权或低权限），接收 multipart `file`。
- 服务端不校验文件内容/后缀，或校验可被 JSP 后缀绕过。
- 保存路径由上传目录与客户端原始文件名拼接，未取 basename、未规范化校验前缀。
- 进程对 Web 根目录有写权限（与上传目录同文件系统或可跨目录写入）。
- 目标为 Tomcat/JBoss 等会解析 JSP 的容器，且 Web 应用目录可访问。

## 利用步骤

1. 从 source map/前端 JS/接口文档找到上传路由（如 `/common/upload1.do`）与参数名（`file`）。
2. 先上传一个普通文件，解码响应中的 URL，确认默认落盘目录（如 `/datahome/attachment/<date>/<uuid>/<name>`）与访问方式。
3. 通过任意文件读取/报错/历史记录获取 Web 应用的绝对路径（如 `/datahome/<app>/webapps/<app>/`）。
4. 计算从上传目录到 Web 根的相对路径，构造 `filename` 前缀 `../../../../<app>/webapps/<app>/test.jsp`。
5. 上传一个最小 JSP（如 `<%= 1+1 %>`）验证解析，避免直接上传完整 WebShell；访问对应 URL 确认返回 `2`。
6. 验证成功后替换为哥斯拉/冰蝎 JSP 或命令执行 JSP，获取服务器权限；注意上传目录与 Web 根可能不在同一分区，必要时改用绝对路径或软链接。

## PoC

```bash
# 最小验证：上传计算 1+1 的 JSP，filename 直接带穿越路径
curl -s -X POST "https://target/common/upload1.do" \
  -F 'file=@test.jsp;filename=../../../../../../datahome/tomcat8_case/webapps/case/test11111.jsp;type=application/octet-stream'
```

```jsp
<%-- test.jsp --%>
<%= 1 + 1 %>
```

```text
# 响应示例（Base64 URL 解码后）：
# /datahome/attachment/2025-02-19/<uuid>/../../../../../../datahome/tomcat8_case/webapps/case/test11111.jsp
# 访问 https://target/case/test11111.jsp 返回 2，说明穿越与 JSP 解析均成功。
```

## 变体与关联

- 变体：`filename` 用绝对路径 `/datahome/tomcat8_case/webapps/case/shell.jsp`；Windows 用 `..\..\` 或盘符。
- 变体：过滤 `../` 时用 `..%2f`、`....//`、`..././`、双重编码或反斜杠绕过（取决于解码位置）。
- 变体：落点不一定是 Web 根，也可写 `authorized_keys`、cron、systemd、应用配置或覆盖已有 JSP/模板。
- 关联：[[web-generic-file-upload-spring-temppath-original-filename-traversal-jsp]]（同类原始文件名拼接穿越，Spring 版本）、[[web-generic-file-upload-multipart-filename-traversal-ssh-key]]（落点改为 SSH 公钥）、[[web-generic-file-upload-single-replace-dotdot-bypass]]（过滤绕过）。
- 边界：保存前取 basename、使用服务端随机文件名、规范化后校验前缀、上传目录与 Web 根跨文件系统且不可写、容器禁止解析上传后缀时，利用失败。

## 检测与防御

- 检测：multipart `filename` 中出现 `../`、`..\`、绝对路径、编码后的 `%2e%2e`；上传响应 URL 含穿越片段；Web 根目录出现新增 `.jsp/.jspx` 文件；上传接口在短时间内收到大量不同后缀/内容的请求。
- 修复：保存前只取 basename，或完全使用服务端生成的随机文件名与白名单后缀；`Path.normalize()` 后校验 `startsWith(uploadDir)`。
- 加固：上传目录放在 Web 根之外并禁止脚本解析；上传服务以最小权限运行，不能写 Tomcat webapps、cron、systemd；对 Web 目录新增脚本文件做完整性监控与告警。
