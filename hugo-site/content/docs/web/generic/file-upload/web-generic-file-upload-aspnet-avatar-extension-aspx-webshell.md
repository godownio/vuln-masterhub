---
id: web-generic-file-upload-aspnet-avatar-extension-aspx-webshell
title: ASP.NET 头像上传抓包改后缀：aspx 落地 Web 目录 GetShell（响应报路径错误仍可利用）
type: scenario
domain: web
path: web/generic/file-upload
technique: aspnet-avatar-extension-aspx-upload
tags:
- web
- file-upload
- aspnet
- aspx
- webshell
- iis
- extension-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:39:44+08:00'
  notes: 已对照 content.md 与图10-14核对：头像上传改 .aspx、响应 DirectoryNotFoundException 路径 D:\School(1)\School\Files\Student/1/...aspx、访问该路径并 AntSword 连接成功均一致；文件实际落地目录为 /Files/Student/1/。未验证点：原文实际 payload 为 JScript eval，卡内为无害验证 ASPX；PoC 未复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-aspnet-avatar-extension-aspx-webshell/
draft: false
kb_aliases:
- 头像上传改后缀 aspx
- ASP.NET WebForms 上传绕过
- 教务系统头像 GetShell
- 上传报路径错误但文件已落地
- aspx 图片马上传
---

## 一句话结论

ASP.NET WebForms 教务后台的学生头像上传只在前端/上传初期限制图片类型，抓包把文件名后缀改成 `.aspx` 后仍会写入 Web 可访问的 `/Files/Student/1/` 目录；即使保存流程返回“未能找到路径”，文件实际已落地，访问即执行，可直连 AntSword 获取 WebShell。

## 原理

- 头像上传接口通常接受 multipart 文件，按原文件名的扩展名保存。若服务端只做前端校验或只在初始上传时检查 Content-Type/扩展名，攻击者用 Burp 拦截请求、把 `filename="x.png"` 改为 `filename="x.aspx"`，就能把脚本写入上传目录。
- 上传目录位于站点根目录下（本例 `/Files/Student/1/`），IIS 默认将 `.aspx` 映射到 ASP.NET 处理程序，访问该文件即由 w3wp 进程编译执行。
- 本例的特殊现象：保存流程在 `File.Copy` 阶段抛出 `DirectoryNotFoundException`（提示“未能找到路径 .../2025122812201752676661.aspx 的一部分”），页面返回错误；但上传文件已经先写入目标目录，直接访问返回的路径仍然成功。说明“响应报错”不等于“文件未落地”，需要实际请求验证。
- 文件落地后可被 AntSword 等客户端连接；即使不连接，也可执行命令、读取配置或进一步横向。
- 根因是“客户端可控文件名/扩展名 + 上传目录在 Web 根内且允许脚本执行 + 保存异常未清理已写文件”，与具体 CMS 无关，ASP.NET/PHP/JSP 站点都可能出现。

## 触发条件

- 攻击者可登录后台并访问头像/图片上传功能（本例需管理员或教师权限）；
- 上传接口未对扩展名做严格白名单，或仅在前端/初始阶段校验；
- 上传目录位于 Web 根下且 IIS/容器解析 `.aspx`（或对应脚本后缀）；
- 应用池账户对目标目录有写权限；
- 上传后可通过已知/可枚举路径访问文件。

## 利用步骤

1. 登录后台，进入学生管理中的头像上传，先上传一张正常图片，确认上传成功并记录返回路径。
2. 重新上传并抓包，把 multipart 中的 `filename` 改为 `shell.aspx`，Content-Type 可保持 `image/jpeg`；文件内容替换为最小 ASPX 验证代码。
3. 转发请求。即使响应提示“未能找到路径”“保存失败”，也记录响应中或已知目录下的文件路径（如 `/Files/Student/1/<timestamp>.aspx`）。
4. 直接访问该 `.aspx` 路径，确认是否返回执行结果（如服务器时间）；若路径带时间戳，可从响应/目录枚举获得。
5. 将内容替换为命令执行/文件管理 WebShell，用 AntSword 等客户端连接；在授权范围内验证后删除文件并恢复。
6. 若直接 `.aspx` 被拦截，尝试 `.ashx`、`.asmx`、`.config`、双扩展名或修改 Content-Type 等变体。

## PoC

最小验证 ASPX（无害）：

```aspx
<%@ Page Language="C#" %><% Response.Write(DateTime.Now); %>
```

multipart 关键部分：

```http
POST /Student/Edit HTTP/1.1
Host: target.example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="ctl00$cphMain$fuPortrait"; filename="shell.aspx"
Content-Type: image/jpeg

<%@ Page Language="C#" %><% Response.Write(DateTime.Now); %>
------WebKitFormBoundaryX--
```

访问（路径以实际响应/目录为准）：

```http
GET /Files/Student/1/2025122812201752676661.aspx HTTP/1.1
Host: target.example.com
```

原文中保存请求返回 `DirectoryNotFoundException`，但该 ASPX 仍可访问并执行，随后 AntSword 连接成功。

## 变体与关联

- 变体：把后缀改为 `.ashx`/`.asmx`/`.config`，或使用双扩展名、大小写、末尾点/空格、`;` 参数等绕过 IIS 解析限制。
- 变体：若上传接口返回随机文件名，可通过目录枚举、上传响应、日志或前端回显获取路径。
- 关联：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]（另一 .NET 上传接口的无后缀校验 GetShell）、[[web-generic-file-upload-extension-zero-check]]（扩展名零校验）。
- 边界：服务端强制扩展名白名单 + 随机重命名 + 上传目录禁止脚本执行时，改后缀无法利用；保存异常若同时清理临时文件则无法访问。

## 检测与防御

- 检测：multipart 文件名后缀为 `.aspx`/`.ashx`/`.asmx`/`.config` 而 Content-Type 为图片；上传目录出现脚本文件；IIS 日志中对 `/Files/.../*.aspx` 的 GET/POST；w3wp 进程写入上传目录。
- 防御：服务端按文件魔数/内容校验图片类型，扩展名白名单并强制重命名（UUID + 固定后缀）；上传目录放到 Web 根之外或禁止脚本执行。
- 防御：保存失败时清理已写入的临时/目标文件，避免“报错但已落地”；不要用客户端文件名直接拼接路径。
- 加固：上传接口接入鉴权与配额；WAF 拦截脚本后缀与双扩展名；定期扫描上传目录中的可执行文件。
