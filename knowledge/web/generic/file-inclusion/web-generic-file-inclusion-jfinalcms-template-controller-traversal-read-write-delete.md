---
id: web-generic-file-inclusion-jfinalcms-template-controller-traversal-read-write-delete
title: JFinalCMS 后台 TemplateController 路径穿越三连：edit/save/delete 拼接 directory/fileName，读/写/删任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: jfinalcms-template-controller-directory-filename-traversal-rwd
aliases:
- jfinalcms 模板管理穿越
- TemplateController edit save delete
- 后台模板任意文件读写删
- directory fileName 拼接
- template/delete fileName 穿越
- 模板写入 GetShell
tags:
- java
- jfinalcms
- jrecms
- cms
- path-traversal
- arbitrary-file-write
- arbitrary-file-read
- arbitrary-delete
- code-audit
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:00:16+08:00'
  notes: 已对照原文与截图核对并修正：图 07 edit、图 08 save、图 10 delete 三处代码均为 directory.replaceAll(",", "/")（逗号转斜杠）、fileName 原样拼接，原稿误写为 replaceAll("\"","")（仅去双引号），已改正标题/正文/PoC 说明；delete 有完整实测请求（图 09/10，filePath=/default/../../.../1.txt 删除 1.txt）。edit/save 穿越由代码推出、原文未给完整请求，卡内标 medium。dedup 候选为同产品其它控制器及 MCMS/PublicCMS 等不同 sink，无同链。
---

## 一句话结论

JFinalCMS/JreCms 后台 `TemplateController` 的 `edit`、`save`、`delete` 三个方法都把请求参数 `directory`/`fileName` 拼成 `/templates/` 下的路径，对 `directory` 仅做 `replaceAll(",", "/")`（逗号转斜杠）、`fileName` 完全不处理，`../` 原样保留：管理员会话下可穿越读取任意文件、写入任意内容（覆盖模板/Web 根内外文件）、删除任意文件——写入模板再访问页面即可升级为 SSTI/RCE。

## 原理

- **同一段脆弱拼接**：三个方法都构造 `filePath = "/" + directory.replaceAll(",", "/") + "/" + fileName`（`directory` 为空时退化为 `"/"+fileName`）。只把 directory 中的逗号替换成斜杠、fileName 原样拼接，完全没有 `..`、分隔符、绝对路径校验，也没有 `getCanonicalPath()` 后判断是否仍在模板目录内。
- **三个 sink**：
  - `edit`：`setAttr("content", StringEscapeUtils.escapeHtml1(TemplateUtils.read(filePath))); render(getView("template/edit"))` → 模板编辑器里显示任意文件内容（读）。
  - `save`：`FileUtils.write(new File(PathKit.getWebRootPath()+"/templates/"+filePath), content)` → 以 Web 根下 `templates/` 为起点写文件；`../` 可越出模板目录、覆盖 Web 根内任意文件（如静态资源、其它模板），甚至继续向上写到应用目录（写）。
  - `delete`：`TemplateUtils.delete(filePath)` → 删除任意可写文件（删）。
- **为什么有效**：模板管理本是管理员功能，代码默认"管理员可信"，但没有把参数限制在模板目录；管理员会话一旦被 CSRF/会话劫持/弱口令获得，或攻击者通过其它漏洞拿到后台，就能把"模板管理"变成任意文件读写删 + RCE。
- **与 SSTI 的关系**：`save` 可以写入含 Enjoy/Freemarker 表达式的模板内容（或在 `edit`+`save` 里直接改现有模板），保存后访问对应页面即执行，见库内 Enjoy SSTI 卡；因此穿越写是 SSTI 的落地方式之一。

## 触发条件

- 攻击者拥有后台管理员会话（模板管理属于系统管理菜单），或能借助 CSRF/会话固定/弱口令等进入后台。
- 目标 `TemplateController` 为未修复版本（`directory`/`fileName` 直接拼接，仅把 directory 中的逗号转成斜杠）；不同版本方法名/路由可能为 `/admin/template/edit|save|delete`。
- 应用进程对目标文件有读/写/删权限；模板目录存在。
- 写入的路径在 Web 根可访问范围内时，可直接访问触发模板渲染（RCE）；写到 Web 根外则可用于覆盖配置/持久化。

## 利用步骤

1. 登录后台，确认模板管理路由与参数：`/admin/template?directory=default` 列表；编辑页 `/admin/template/edit?directory=default&fileName=search.html`。
2. 读文件：把 `directory` 或 `fileName` 换成 `../` 序列（如 `directory=../../../../..&fileName=etc/passwd` 或 `fileName=../../../../../../etc/passwd`），编辑页会回显文件内容。
3. 写文件：`POST /admin/template/save`，`content` 为要写入的内容（可以是恶意 Enjoy 模板），`directory`/`fileName` 用 `../` 指向目标路径（如覆盖某个模板或写入可访问路径）。
4. 删文件：`GET /admin/template/delete?fileName=../../../../../../../1.txt&directory=default`，删除任意文件（原文给出的实测请求）。
5. 写模板后访问对应页面触发渲染 → SSTI/RCE（如目标页面引用被改模板）。

## PoC

原文给出的任意文件删除请求（后台会话 Cookie 略）：

```http
GET /admin/template/delete?fileName=../../../../../../../../../../../../../../../../../1.txt&directory=default HTTP/1.1
Host: 127.0.0.1:8888
Referer: http://127.0.0.1:8888/admin/template?directory=default
Cookie: JSESSIONID=<admin-session>; _jfinal_captcha=...; listQuery=directory%3Ddefault
```

读取与写入的等价参数（按代码构造，原文未给完整请求）：

```text
GET  /admin/template/edit?directory=../../../../..&fileName=etc/passwd
POST /admin/template/save
directory=../..&fileName=xxx.html&content=<模板内容>
```

`filePath` 实际为 `"/"+directory.replaceAll(",", "/")+"/"+fileName`，写入时再拼到 `PathKit.getWebRootPath()+"/templates/"` 之后；穿越深度按部署路径调整。

## 变体与关联

- **同产品其它穿越点**：`/common/down/file?fileKey=` 前台任意文件读（库内已有卡）、`/ajax/html?html=` 模板渲染穿越（库内已有卡）、`/admin/database/delete` 备份名穿越删除（库内已有卡）、后台 FileManager 的 `path/currentpath` 读写下载（库内已有卡）；本卡补充 TemplateController 的读/写/删三方法。
- **跨产品同类**：MCMS `TemplateAction.delete` 的 `fileName` 穿越删除（库内已有卡）、其它 Java CMS 的模板编辑/保存接口；只要参数拼路径且无规范化即可套用。
- **升级链**：穿越写模板 + Enjoy SSTI（库内已有卡）→ 后台功能变 RCE；或写静态 HTML 做同源存储型 XSS。
- **权限前提差异**：本卡需要管理员会话，危害等级低于前台未授权读取；但与弱口令/CSRF/任意用户登录等组合后实际可达。

## 检测与防御

- **代码修复**：对 `directory`/`fileName` 做文件名白名单（`[A-Za-z0-9._-]+`，禁止 `.`/`..`/分隔符）；或 `Path.normalize()` 后校验 `startsWith(templateRoot)`；`save` 只允许写模板目录内已存在的模板名。
- **运行侧**：监控 `templates/` 目录及 Web 根的文件写入/删除事件（尤其管理员会话触发的批量变更）；模板内容出现 `#set(`、`${`、`::` 等表达式；后台模板编辑后紧跟页面访问。
- **访问侧**：WAF 拦截 `/admin/template/*` 参数中的 `../`、`..%2f`、绝对路径；审计后台操作日志，关联同会话的异常路径访问。
- **管理侧**：后台强制强口令 + MFA、CSRF token、限制后台来源 IP；该 CMS 长期未更新，建议下线或做二次开发修复。

## 备注

- 原文给出 delete 的完整请求与代码截图；edit/save 的穿越由代码拼接逻辑直接推出，未给出完整回显/写入请求，故 confidence 标 medium。
- 截图界面为 JreCms（jfinalcms 衍生），代码结构与 jfinalcms 一致；原文称漏洞已提交 CNVD 并通过。
