---
id: web-generic-file-inclusion-jiuyin-httpcombiner-css-read-overwrite
title: 九垠赢系统 HttpCombiner css 参数任意文件读取并覆盖 StaticCss.css
type: scenario
domain: web
path: web/generic/file-inclusion
technique: httpcombiner-css-read-write-static-file
tags:
- dotnet
- aspnet
- arbitrary-file-read
- file-write
- path-traversal
- code-audit
- httpcombiner
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 九垠赢系统 前端 6.8.0.46149 / 后端 6.8.0.8666（原文标记）
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:08:11+08:00'
  notes: 已通读原文并逐张核对23张图：HttpCombiner.ProcessRequest 取 css/js/type 后 MapPath('/')+file 调 FileHelper.ReadFile，BuildFile 固定写 /Styles/StaticCss.css，WriteFile 在 !append && File.Exists 时 File.Delete 后 FileMode.Append 写入（已放大核对 if 条件为 !append）；实测 GET /Application/HttpCombiner.ashx?css=/web.config 后 /Styles/StaticCss.css 回显 web.config（含 User Id=WRM;Password=jiuyin916;），与卡一致。注意原文代码截图为 Request.Form['css'] 而复现用 GET 查询串，两者取参方式不一致，卡内已如实注明'查询串/表单均可尝试'。受影响版本原文明确，已设置。frontmatter 无 sources/source_url；未在本机复跑。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-jiuyin-httpcombiner-css-read-overwrite/
draft: false
kb_aliases:
- 九垠赢 任意文件读取
- HttpCombiner 文件读取
- StaticCss.css 覆盖
- css 参数路径拼接
- HttpCombiner.ashx
---

## 一句话结论

`HttpCombiner.ashx` 把 `css` 参数按逗号拆成文件路径，直接拼到 `Server.MapPath("/")` 后调用 `FileHelper.ReadFile` 读取，未做任何路径校验；读取到的内容随后被写入 Web 可访问的 `/Styles/StaticCss.css`，攻击者用 `css=/web.config` 即可让该 CSS 返回 web.config 内容（含数据库账号密码），同时覆盖原静态文件可能导致前台页面异常。

## 原理

- `HttpCombiner.ProcessRequest` 从请求中取 `css` 参数，按 `,` 分割；`path = context.Server.MapPath("/")` 得到站点根目录，然后对每个 `file` 执行 `FileHelper.ReadFile(path + file)`，没有 `Path.GetFullPath`/前缀校验/扩展名白名单。
- 拼接后的内容经 `BuildFile(sb.ToString(), "/Styles/StaticCss.css", context)` 写入；`BuildFile` 内部 `context.Server.MapPath(fileName)` 得到固定路径 `站点根/Styles/StaticCss.css`，再调用 `FileHelper.WriteFile(content, file, false)`。
- `FileHelper.WriteFile` 在 `append=false` 且目标已存在时先 `File.Delete(fileName)`，随后用 `FileStream(fileName, FileMode.Append)` + `StreamWriter` 写入内容，因此原 `StaticCss.css` 被删除并替换为拼接后的文件内容。
- 攻击链：`css=/web.config` → 读取 web.config → 写入 `StaticCss.css` → 浏览器访问 `/Styles/StaticCss.css` → 得到 web.config 明文。原文截图显示泄露了 Oracle 连接串（`User Id=WRM;Password=jiuyin916;`）和 `customErrors=Off` 等配置。
- 同一逻辑还存在于 `js` 参数：读取 `js` 列表后写入 `/Scripts/StaticJs.js`；`type=replace` 分支还接收 `path` 参数并对目录下 `*.html` 做处理，属于同一 Handler 的额外攻击面。

## 触发条件

- 目标为受影响版本的九垠赢系统，`/Application/HttpCombiner.ashx` 可访问。
- `css`（或 `js`）参数可控，且运行时对 `Server.MapPath("/") + file` 的拼接没有额外过滤；Windows 路径分隔符/`..\` 可用于跨目录。
- 站点存在可写的 `Styles/StaticCss.css`（通常存在）且该路径可被 Web 访问。
- 读取的文件对 IIS 工作进程账号可读（web.config、源码、配置文件通常可读）；写入操作会覆盖原 CSS，可能影响前台样式。

## 利用步骤

1. 确认 `HttpCombiner.ashx` 可达，记录站点根路径与 `/Styles/StaticCss.css` URL。
2. 发送 `css` 参数指向目标文件，例如 `/web.config`；原文 POC 使用 GET 查询串，代码从 `Request.Form` 读取，实际以目标部署的取参方式为准（查询串/表单均可尝试）。
3. Handler 读取文件内容并覆盖 `StaticCss.css`；请求本身可能返回 200/空响应。
4. 访问 `/Styles/StaticCss.css`，在返回的 CSS 中查找 `/* /web.config */` 标记后的原文内容。
5. 重复读取其他文件（`/Global.asax`、连接字符串配置、源码等）；用 `..\..\` 尝试读取站点根之外的文件。
6. 注意：覆盖 `StaticCss.css` 可能导致前台页面崩溃，测试后需恢复原文件。

## PoC

```http
GET /Application/HttpCombiner.ashx?css=/web.config HTTP/1.1
Host: 127.0.0.1:9096
```

```http
GET /Styles/StaticCss.css HTTP/1.1
Host: 127.0.0.1:9096
```

```text
/* /web.config */
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="OracleServerConnectionString"
         connectionString="Data Source=127.0.0.1/jybizsys;User Id=WRM;Password=jiuyin916;" />
```

## 变体与关联

- 变体：`js` 参数读取任意文件后写入 `/Scripts/StaticJs.js`，同样可通过访问该 JS 取回内容。
- 变体：`css=/web.config,/Global.asax` 逗号拼接多个文件，一次读取多个目标。
- 变体：使用 `..\..\`、`....//` 等 Windows 路径穿越读取站点根之外的文件；具体受 `Server.MapPath` 规范化影响。
- 变体：`type=replace` 分支的 `path` 参数对目录内 `*.html` 进行操作，可能存在批量覆盖/删除风险，原文未展开。
- 关联：[[web-generic-file-inclusion-windows-backslash-download-traversal]]（Windows 路径穿越读取）、[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（路径拼接读取对比）、[[web-generic-file-upload-archive-symlink-extract-read-write]]（读写组合）。
- 边界：若 Handler 已下线、路径做了规范化/白名单、或 `Styles` 目录不可写，则链不成立；原文只演示读取 web.config，未演示读取系统文件。

## 检测与防御

- 检测：访问日志中出现 `HttpCombiner.ashx` 且 `css`/`js` 含 `/`、`..`、`web.config`、`Global.asax` 等；`StaticCss.css`/`StaticJs.js` 的修改时间/内容异常变化（文件完整性监控）；前台 CSS 返回 XML/配置内容。
- 修复：对 `css`/`js` 的每个路径做 `Path.GetFullPath` 后校验必须位于允许的静态资源目录内，拒绝 `..`、绝对路径、非白名单扩展名；不要把读取内容写入 Web 可访问文件，改为直接返回或写入临时非 Web 目录。
- 加固：删除/禁用不必要的 `HttpCombiner` 或限制为认证管理员；`Styles` 目录设置为 IIS 工作进程不可写；关闭详细错误；限制上传/写入权限与站点目录权限。
