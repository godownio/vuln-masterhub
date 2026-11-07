---
id: web-generic-file-upload-uploadpictureqt-rename-policy-jsp
title: uploadPicture_qt.jsp 未授权上传：RandomFileRenamePolicy 保留原始后缀写入 Web 目录
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-rename-policy-original-suffix
aliases:
- uploadPicture_qt.jsp 任意文件上传
- RandomFileRenamePolicyByKeyColumn
- FileRenamePolicy 后缀可控
- 学生平台 JSP 上传
- /sys/login/../ 上传
tags:
- java
- jsp
- file-upload
- webshell
- extension-bypass
- rename-policy
- unauthenticated
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:50:39+08:00'
  notes: 已对照原文核对：uploadPicture_qt.jsp在Action=Edit时用MultipartRequest+RandomFileRenamePolicyByKeyColumn，策略取原始文件名最后一个点后的后缀并在getBakName分支保留；PoC为POST /sys/login/../xgxt/formquery/uploadPicture_qt.jsp，字段file_photo、filename=test.jsp，与原文一致。未验证点：该节关键源码截图为外链未落盘，"上传目录由请求参数决定"原文文字未明确（keyvalue主要用作重命名键）；原文未展示上传响应/落地路径/执行结果；未本机复跑。
---

## 一句话结论

学生平台的 `uploadPicture_qt.jsp` 在 `Action=Edit` 时使用 `MultipartRequest` + 自定义 `RandomFileRenamePolicyByKeyColumn` 保存文件，重命名策略只取原始文件名最后一个点后的后缀并保留，未做扩展名白名单；攻击者通过 `LoginAdminFilter` 的 `/sys/login/../` 路径绕过直接访问该 JSP，上传 `test.jsp` 即可把 JSP WebShell 写入 Web 目录。

## 原理

- **入口**：`uploadPicture_qt.jsp` 通过 `request.getParameter("Action")` 判断，等于 `Edit` 时进入上传逻辑；上传目录由请求参数（如 `keyvalue`/业务参数）决定，不存在则创建。
- **重命名策略**：`new RandomFileRenamePolicyByKeyColumn(keyvalue)` 实现 `FileRenamePolicy`，容器/`MultipartRequest` 会自动调用 `rename(File)`：
  - 判断原始文件名是否包含 `.`，取最后一个点后的后缀；
  - 用业务键/随机值拼接新文件名，保留原始后缀；
  - 若目标文件已存在，`getBakName` 生成备份名时同样保留原始后缀。
- **保存**：`MultipartRequest` 以该 policy 写入上传目录，文件内容按字节原样落盘；代码未校验 MIME、文件头，也未重编码。
- **未授权入口**：`uploadPicture_qt.jsp` 位于受 `LoginAdminFilter` 保护的 `*.jsp` 范围，但攻击者可用 `/sys/login/../xgxt/formquery/uploadPicture_qt.jsp`：`getRequestURI()` 含 `login` 满足放行条件，容器再把 `..` 解析回目标 JSP（见关联卡）。
- **为什么成立**：上传安全依赖“扩展名由服务端决定”和“目录不可执行”；这里后缀完全由客户端文件名决定，落点又在 Web 根下，JSP 会被容器编译执行。原文 PoC 上传字段名为 `file_photo`，文件名为 `test.jsp`。
- **原文验证边界**：文章给出完整 POST PoC 与关键源码（外部图片），但没有展示上传响应、落地路径或 WebShell 执行结果；因此 confidence 记 medium。

## 触发条件

- 目标存在 `uploadPicture_qt.jsp` 且 `Action=Edit` 分支可进入。
- 上传目录位于 Web 根下且允许 JSP 执行（Tomcat 等）。
- `LoginAdminFilter` 的 `/login/../` 或 `sybz=WZQ` 绕过可用（或攻击者已有会话）。
- 重命名策略保留客户端后缀，未做白名单/内容校验。

## 利用步骤

1. 确认 `uploadPicture_qt.jsp` 路径与过滤器行为；尝试 `/sys/login/../xgxt/formquery/uploadPicture_qt.jsp` 直接访问。
2. 构造 `multipart/form-data` 请求，参数 `Action=Edit`，并按原文补齐 `table/keycol/keyvalue/zpcol/colName/xtbz` 等字段（可为 null/空）。
3. 文件字段 `file_photo` 使用 `filename="test.jsp"`，内容为 JSP WebShell。
4. 根据响应/目录枚举定位落地文件（重命名后的文件名），访问该 JSP 验证执行。
5. 若目录不可执行，尝试其他后缀（`.jspx` 等）或结合数据库写入/路径穿越改变落点（原文未展开）。

## PoC

```http
POST /sys/login/../xgxt/formquery/uploadPicture_qt.jsp?table=null&keycol=null&keyvalue=null&zpcol=null&Action=Edit&colName=null&xtbz= HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryidJdD1BawNiZHUGE
Cookie: JSESSIONID=<任意会话>

------WebKitFormBoundaryidJdD1BawNiZHUGE
Content-Disposition: form-data; name="file_photo"; filename="test.jsp"
Content-Type: image/png

<%@ page import="java.util.*,java.io.*" %><% out.println("ok"); %>
------WebKitFormBoundaryidJdD1BawNiZHUGE
Content-Disposition: form-data; name="xtbz"

------WebKitFormBoundaryidJdD1BawNiZHUGE--
```

原文 PoC 正文为 `{{webshell}}` 占位；未给出响应与执行截图。

## 变体与关联

- 变体：利用 `getBakName` 分支在目标同名时保留后缀；换 `.jspx`/`.jspf`；把 `keyvalue` 等业务参数用于目录穿越（原文未验证）；上传后结合数据库 `table` 参数注入（原文提到写入数据库时 table 可控，存在注入）。
- 关联：`[[web-generic-auth-loginadminfilter-sybz-param-bypass]]`（本 PoC 使用的未授权入口）；`[[web-generic-file-upload-extension-zero-check]]`（扩展名零校验的通用形态）；`[[web-generic-file-upload-user-controlled-filename-webshell]]`（保留原始后缀写 WebShell）。
- 与普通后台任意上传的区别：入口 JSP 本身可通过过滤器路径绕过未授权访问，攻击者不需要账号。

## 检测与防御

- 检测：`uploadPicture_qt.jsp` 的上传请求携带 `.jsp`/`.jspx` 后缀或 `Action=Edit`；`/login/../` 路径访问；Web 目录新增 JSP 文件；上传目录出现脚本访问与异常子进程。
- 修复：上传后缀由服务端白名单决定并重命名，不保留客户端扩展名；上传目录禁止 JSP 执行并移出 Web 根；修复 `LoginAdminFilter` 的请求参数放行与 URI 规范化问题。
- 缓解：WAF 拦截上传请求中的脚本后缀与 `login/..` 路径；文件完整性监控；容器禁止上传目录解析 JSP。
