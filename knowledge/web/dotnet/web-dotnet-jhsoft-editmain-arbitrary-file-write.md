---
id: web-dotnet-jhsoft-editmain-arbitrary-file-write
title: JHSoft OA EditMain.aspx 后台 add/id 参数控制路径：StreamWriter 任意文件写入 GetShell
type: scenario
domain: web
path: web/dotnet
technique: dotnet-aspx-backend-filepath-streamwriter-write
aliases:
- JHSoft 后台任意文件写入
- 金和 OA 任意文件写入
- EditMain.aspx 写文件
- add 参数路径控制
- id 参数写入 aspx
- StreamWriter 覆盖写
tags:
- arbitrary-file-write
- dotnet
- aspx
- backend
- webshell
- oa
- jhsoft
- streamwriter
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:31+08:00'
  notes: 已对照原文与 img/14/15/19 核对 Page_Load 的 add 参数 |→\、id 拼 JHSoft.Web.Portal\Default\、btn_save 先 File.Delete 再 StreamWriter(Content.Value) 覆盖写。未验证点：原文仅展示“应用程序异常”错误页，未展示成功落地 WebShell；需后台会话与有效 __VIEWSTATE/__EVENTVALIDATION，卡内 confidence medium。
---

## 一句话结论

JHSoft OA 后台页面 `JHSoft.Web.Portal/EditMain.aspx` 用请求参数 `add` 或 `id` 直接决定文件路径（`id` 会拼到 `JHSoft.Web.Portal\Default\` 下），保存时先 `File.Delete` 再用 `StreamWriter` 覆盖写入编辑器内容；攻击者在后台构造 `id=shell.aspx` 并提交恶意内容即可在 Web 目录落地 ASPX WebShell，构造 `add=...` 还能指向系统其他可写目录，属于后台任意文件写入到 RCE。

## 原理

- `Page_Load` 的路径计算：
  - 若 `Request.QueryString["add"] != null`：`FilePath = Request.QueryString["add"].ToString().Replace("|", "\\")`——`add` 可传绝对路径或跨目录相对路径，`|` 被替换成反斜杠，未做路径规范化与权限边界检查；
  - 若 `Request.QueryString["id"] != null`：`FileName = Request.QueryString["id"].ToString()`；
  - 若 `FileName != ""`：`FilePath = AppDomain.CurrentDomain.BaseDirectory + "JHSoft.Web.Portal\\Default\\" + FileName`——`id` 直接拼到应用目录下，未限制扩展名，`id=webshell.aspx` 即生成可执行脚本路径；后一个判断会覆盖 `add` 指定的路径。
- 保存逻辑 `btn_save_ServerClick`：`if (File.Exists(FilePath)) { File.Delete(FilePath); }`，随后 `using StreamWriter streamWriter = new StreamWriter(FilePath, append: false, Encoding.Default); streamWriter.WriteLine(ToDBC(Content.Value));`——目标文件存在则先删再覆盖写，内容来自页面编辑器控件 `Content.Value`，完全由请求提交。
- 为什么能到 RCE：`JHSoft.Web.Portal\Default` 位于 Web 应用目录内，IIS 会把 `.aspx` 当作 ASP.NET 页面编译执行；写入 `<%@ Page Language="C#" %>` 之类的脚本即落地 WebShell。`add` 参数还可把文件写到站点根目录、其他虚拟目录或系统可写目录，用于覆盖配置或写入计划任务/启动项（取决于进程权限）。
- 该页面属于后台功能，通常需要有效管理员会话与合法 ViewState/EventValidation；文章的复现截图只显示了“应用程序异常”错误页，未展示成功落地文件，因此利用前需自行确认会话与回发参数。

## 触发条件

- 目标存在后台页面 `C6/JHSoft.Web.Portal/EditMain.aspx`，且当前会话具有访问/编辑权限（通常为管理员）。
- 请求能提交 ASP.NET 回发（携带有效 `__VIEWSTATE`、`__EVENTVALIDATION`，触发 `btn_save` 服务端事件），`Content` 控件值可控。
- 目标目录可写（应用池身份对 `JHSoft.Web.Portal\Default` 或 `add` 指定目录有写权限）。
- 写入 `.aspx` 的目录在 IIS 中映射为 ASP.NET 应用且允许执行脚本。

## 利用步骤

1. 登录后台，打开 `EditMain.aspx`，抓取包含 `__VIEWSTATE`、`__EVENTVALIDATION` 的正常保存请求作为模板。
2. 在请求中加 `id=shell.aspx`（或 `add=C:\inetpub\wwwroot\shell.aspx`）控制落盘路径；保持回发参数中的 `__EVENTTARGET` 指向保存按钮。
3. 把 `Content` 字段替换为最小 ASPX 脚本内容，提交后访问生成的 `.aspx` 路径验证执行。
4. 若目标使用相对路径，尝试 `add=..\..\..\站点目录\shell.aspx`；`|` 会被替换为 `\`，可用于传递反斜杠。
5. 若 `id` 路径写入失败，改用 `add` 指向其他可写目录或覆盖现有配置/模板文件（覆盖前先确认影响面）。

## PoC

```http
POST /C6/JHSoft.Web.Portal/EditMain.aspx?id=shell.aspx HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Cookie: ASP.NET_SessionId=<后台有效会话>

__EVENTTARGET=<保存按钮 ClientID>&__VIEWSTATE=<有效ViewState>&__EVENTVALIDATION=<有效EventValidation>&Content=<%@ Page Language="C#" ... %>&...
```

```text
# 原文无完整 PoC：文章只给出 Page_Load 与 btn_save 的源码，以及一张“应用程序异常”错误页截图
# 触发要点：id 或 add 控制 FilePath；btn_save 回发时 Content 值被写入该路径
```

## 变体与关联

- 变体：`add` 传绝对路径可跨目录写入；`id` 传入 `..\..\` 前缀可做相对路径穿越（若未规范化）；`|`→`\` 的替换可用于构造 Windows 路径。
- 变体：覆盖现有 `.aspx`/`.config`/模板文件可造成持久化后门或配置篡改；写入 `.aspx` 是最直接的 GetShell 方式。
- 关联：[[web-generic-file-upload-aspnet-avatar-extension-aspx-webshell]]（ASP.NET 上传落 aspx 的同类 GetShell）；[[web-generic-file-inclusion-jhsoft-downloadbgimage-path-read]]（同一 OA 的路径处理缺陷，可用于读取写入结果）。
- 边界：文章未给出成功写入的响应或 WebShell 执行截图，且该功能在后台、需要合法回发参数；`Content` 控件名与保存按钮的 `__EVENTTARGET` 需按实际页面确认。原文未标注受影响版本。

## 检测与防御

- 检测：`EditMain.aspx` 请求的 `add`/`id` 出现盘符、`..`、`.aspx`、`|`、`\` 等特征；后台会话在 `JHSoft.Web.Portal\Default` 下生成新脚本文件；保存接口的 `Content` 含 `<%@ Page`、`<%`、`eval` 等脚本特征；Web 目录新增/修改时间异常的可执行文件。
- 修复：文件路径改为服务端白名单 ID 映射；`id` 只允许固定文件名并强制安全扩展名，`add` 禁止由客户端传入；最终路径 `Path.GetFullPath` 规范化后校验必须位于允许目录内。
- 加固：后台功能增加二次鉴权与操作审计；Web 目录禁止应用池写入 `.aspx/.ashx/.config`；上传/编辑目录关闭脚本执行权限；定期扫描新增脚本文件。
