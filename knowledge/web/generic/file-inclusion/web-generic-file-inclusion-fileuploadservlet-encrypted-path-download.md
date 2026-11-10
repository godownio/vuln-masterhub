---
id: web-generic-file-inclusion-fileuploadservlet-encrypted-path-download
title: FileUploadServlet 的加密 path/filename 解密后直接拼进 File：后台任意文件下载与删除
type: scenario
domain: web
path: web/generic/file-inclusion
technique: java-servlet-encrypted-param-file-stream-read
aliases:
- /components/fileupload/upload 任意文件读取
- 加密参数文件下载
- PubFunc.decrypt 路径
- deleteflag=false&down=true
- FileUploadServlet 文件读取
- SafeCode.decode
tags:
- java
- servlet
- file-read
- arbitrary-file-download
- encrypted-parameter
- path-traversal
- file-delete
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T09:15:34+08:00'
  notes: 已对照原文核对：图31/32/33 反编译 FileUploadServlet.doPost，deleteflag=true 走 PubFunc.decrypt(path/filename)+new File(dir).delete()，down=true 走 decrypt 后 new File(path,fileName)+FileInputStream 回写响应；图34 为同一路由的实际响应，Content-Disposition attachment + win.ini 内容，任意文件下载已实测。affected_versions 留空正确，原文未标注产品版本。未验证点：删除分支仅代码可见、原文未实测；down 分支前置的 safariORFoxType+datems 120s 票据校验原文未说明如何获取。
---

## 一句话结论

`FileUploadServlet` 把 `path`、`filename` 两个参数做 `PubFunc.decrypt` 解密后直接 `new File(path, fileName)` 并流式回写响应，加密只是编码而非鉴权/校验；拿到加密算法（源码或反编译）后即可把任意系统路径加密提交，从 Web 端下载 `c:/windows/win.ini`、`/etc/hosts` 等任意文件。

## 原理

- **加密参数 ≠ 安全参数**：参数用对称加密（`PubFunc.decrypt`）包裹，看起来"用户无法构造"，但算法与密钥都在客户端可分发的字节码里（`PubFunc.encrypt/decrypt`），攻击者用同一份代码即可离线生成任意密文。加密只提高了一点手工构造成本。
- **解密结果没有任何边界校验**：代码 `path = PubFunc.decrypt(path); fileName = PubFunc.decrypt(fileName); path = path.replace("\\", File.separator); File file = new File(path, fileName); InputStream inputstream = new FileInputStream(file);` 之后直接 `while ((len = inputstream.read(buf)) != -1) servletOutputStream.write(buf, 0, len)`。既没有 `getCanonicalPath()` 前缀校验，也没有扩展名/目录白名单，`new File(parent, child)` 允许绝对路径与 `..`。
- **"下载"分支的触发条件**：`doPost` 先取 session 里的 `userView`；若为空，则读取 `safariORFoxType` 与 `datems`，在 `nowTime - times <= 120000`（2 分钟）且 `PubFunc.decrypt(safariORFoxType)` 等于 `"true"` 时置 `sessionFlag = true`。随后 `down=true` 进入下载分支——即"有会话"或"两分钟内的可伪造票据"二选一，本质是弱鉴权而非文件校验。
- **为什么能读系统文件**：`new File("c:/windows", "win.ini")`、`new File("/etc", "hosts")` 都是合法组合，`FileInputStream` 以 Web 进程权限打开；响应头 `Content-Disposition: attachment` 把内容作为附件回传，读取结果直接可见。
- **同一入口还能删文件**：`deleteflag=true` 分支走 `File dirs = new File(path, path); if (dirs.exists()) dirs.delete();`，参数同样来自解密后的用户输入，构成任意文件删除；原文未实测删除，仅代码可见。
- **为什么这是"后台"而非"前台"**：入口要求 `userView` 会话或可伪造票据，因此通常需要先拿到低权限账号；但一旦进入，读取范围是整个文件系统（含配置、数据库连接串、其他租户数据）。

## 触发条件

- 目标暴露 `/components/fileupload/upload`（`com.hjsj.hrms.utils.components.fileupload.servlet.FileUploadServlet`）等同类上传/下载组件。
- 攻击者能获得 `PubFunc.encrypt` 的实现与密钥（源码泄露、反编译 jar、前端 JS 同算法）。
- 具备有效会话，或能构造 2 分钟内有效的 `safariORFoxType=true` 票据。
- Web 进程对目标文件有读权限。

## 利用步骤

1. 抓一次正常上传/下载请求，确认 `path`、`filename` 是密文以及密文长度特征。
2. 从源码/反编译得到 `PubFunc.encrypt(plain)`，本地加密目标路径，例如 `C:\windows\win.ini` 的目录部分与文件名部分分别加密。
3. 发送 `deleteflag=false&down=true&localname=<名字>&path=<密文目录>&filename=<密文文件名>`。
4. 观察响应头 `Content-Disposition` 与响应体，确认文件内容返回；Linux 目标改成 `/etc/hosts`、`/etc/passwd`、应用 `application.yml`。
5. 若目录分隔符被处理，注意代码会 `replace("\\", separator)`，Windows 路径用反斜杠或正斜杠均可尝试。
6. 进一步读取数据库配置、密钥文件，或改用 `deleteflag=true` 评估删除影响（谨慎，破坏性操作需授权）。

## PoC

```http
POST /components/fileupload/upload HTTP/1.1
Host: target
Cookie: <有效会话>
Content-Type: application/x-www-form-urlencoded
Content-Length: 114

deleteflag=false&down=true&localname=aaa&path=<encrypt("C:\\windows")>&filename=<encrypt("win.ini")>
```

```http
POST /components/fileupload/upload HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
Content-Type: application/x-www-form-urlencoded

deleteflag=false&down=true&localname=test&path=<encrypt("/etc")>&filename=<encrypt("hosts")>
```

响应体为文件原始内容，头中 `Content-Disposition: attachment;filename="test_hosts"`。

脆弱代码形态：

```java
path = PubFunc.decrypt(request.getParameter("path"));
fileName = PubFunc.decrypt(request.getParameter("filename"));
path = path.replace("\\", File.separator);
File file = new File(path, fileName);
InputStream in = new FileInputStream(file);
// 循环 read/write 到 response.getOutputStream()
```

## 变体与关联

- **变体（参数形式）**：加密的 `path`+`filename`、Base64 文件名、`~2e~2e` 之类自定义转义（同产品另一 Servlet `DisplayCustomerReportExcelFile` 用 `~2e~2e~5c` 表示 `..\`）。
- **变体（sink）**：`FileInputStream` 回显、`send_file`、`ZipOutputStream` 打包导出、`File.delete()` 删除、`FileOutputStream` 写文件。
- **变体（鉴权绕过）**：`safariORFoxType` + `datems` 的 2 分钟票据、`sessionFlag`、`userView.getHm().containsKey("isEmployee")` 判断缺失。
- **关联**：[[web-generic-file-inclusion-base64-filename-traversal-download]]（Base64 文件名穿越）、[[web-generic-file-inclusion-crm-download-jsp-aes-path-traversal]]（AES 加密路径穿越）、[[web-java-oa-download-servlet-followup-delete-arbitrary-file]]（下载接口衍生删除）。
- **边界**：解密后做 `getCanonicalPath()` 前缀校验、用 `send_from_directory`/`Path.normalize` 限制根目录、加密密钥每会话随机且服务端不泄露、进程无读权限时失效。

## 检测与防御

- **修复**：解密后不要直接拼接文件对象。用固定根目录 + `getCanonicalPath()` 前缀校验（或 `Path.normalize().startsWith(root)`），并只允许白名单扩展名；文件名取 `Paths.get(name).getFileName()` 去掉路径部分。
- **鉴权**：下载接口必须校验会话与文件归属（文件 id 映射到服务端记录），不要用"加密参数"代替授权。
- **删除风险**：删除操作单独做权限与归属校验，禁止用户指定绝对路径；关键目录只读挂载。
- **检测**：同一会话短时间内请求大量不同 `path` 密文；响应头 `Content-Disposition` 返回系统文件名（`win.ini`、`hosts`、`.yml`）；请求参数长度异常且高熵；`path` 解密后为绝对路径或含 `..`。
