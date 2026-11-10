---
id: web-generic-file-inclusion-mcms-template-delete-traversal
title: MCMS 模板删除接口 fileName 未过滤 ../：TemplateAction.delete 可路径穿越删除任意目录
type: scenario
domain: web
path: web/generic/file-inclusion
technique: mcms-template-delete-traversal
aliases:
- MCMS 任意目录删除
- template/delete fileName 穿越
- TemplateAction.delete
- FileUtils.deleteDirectory 路径穿越
tags:
- java
- springboot
- cms
- mcms
- path-traversal
- arbitrary-delete
- file-delete
cve: []
severity: medium
confidence: medium
affected_versions: MCMS（MingSoft CMS）5.2.8（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V464
  verified_at: '2026-11-10T15:08:53+08:00'
  notes: 已通读原文并核对本地图：图48 TemplateAction#delete 源码含 RequiresPermissions(template:del)、fileName 拼接后 FileUtils.deleteDirectory；图49-50 HackBar POST /ms/template/delete fileName=2.txt 返回成功。原文仅演示删除模板内文件，../ 任意目录删除为原文文字声称，卡内 confidence=medium 与之一致。未验证点：目录穿越删除未演示；PoC 未复跑；无 sources/source_url。
---

## 一句话结论

MCMS 后台模板删除接口 `TemplateAction#delete` 把请求参数 `fileName` 直接拼到模板根目录后再交给 `FileUtils.deleteDirectory(new File(path))`，且不像上传接口那样检查 `../`/`..\`；把 `fileName` 写成 `../../<目录>` 即可穿越到模板目录之外，删除 Web 应用内任意可写目录（本案例先以 `fileName=2.txt` 删文件验证）。

## 原理

- **删除路径由用户拼接**：`delete(HttpServletRequest request)` 取 `fileName = request.getParameter("fileName")`，拼成 `BaseUtil.getRealTemplatePath(uploadTemplatePath + File.separator + appId + File.separator + fileName)`，然后 `FileUtils.deleteDirectory(new File(path))`。
- **缺少路径规范化**：拼接后没有 `getCanonicalPath()`/`normalize()` 校验是否仍位于模板根目录；`new File(parent, "../../x")` 在文件系统层解析 `..`，可跳出模板目录。
- **与上传接口的差异**：文中的上传点至少检查了 `../`（尽管可用绝对路径绕过），而删除接口连这个检查都没有；因此 `fileName=../`、`..\..\` 可直接穿越。
- **危害**：删除 Web 目录、模板、静态资源、配置目录等可导致页面不可用/配置丢失/业务中断，也可删除安全组件目录为后续攻击清障；若目录可写且应用会重新生成模板，还可能配合写入实现篡改。
- **权限**：接口带 `@RequiresPermissions("template:del")`，需要后台会话且具备模板删除权限；若存在未授权路由/弱口令则可被外部利用。

## 触发条件

- 已登录 MCMS 后台且账号具备 `template:del` 权限（或通过未授权路由/鉴权绕过访问）。
- `fileName` 参数可控且未做 `../` 过滤/规范化。
- 目标目录对应用进程可写/可删；Windows/Linux 路径分隔符都需考虑。
- 删除操作不可逆，测试时应使用可恢复环境。

## 利用步骤

1. 登录后台，进入模板管理，找到删除模板/文件的请求（本案例 `GET/POST /ms/template/delete`，参数 `fileName`）。
2. 先用 `fileName=2.txt` 删除模板目录内的测试文件，确认返回 `{"result":true,"code":200}`。
3. 把 `fileName` 改为 `../../<目标目录>`（按实际目录层级调整），发送请求删除目标目录。
4. 通过访问页面/文件系统确认目录被删除；不同版本对 `FileUtils.deleteDirectory` 的异常处理不同，删除不存在的路径可能仍返回成功或报错。

## PoC

```http
POST /ms/template/delete HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<后台会话>

fileName=../../upload
```

原文以 `fileName=2.txt` 在 HackBar 中验证删除模板文件；`../../` 穿越删除目录为原文文字描述的能力，具体层级需按目标部署路径调整。无破坏性 PoC 在本机执行。

## 变体与关联

- 其它 CMS/框架的删除穿越：`web-generic-file-inclusion-goldlib-file-controller-delete-traversal`、`web-generic-file-inclusion-whir-ezoffice-deletefile-traversal-delete`、`web-php-zentao-backup-editor-arbitrary-file-delete`。
- 同项目文件写入/穿越：`web-java-component-mcms-checkuploadpath-absolute-path-upload`、`web-java-component-mcms-template-unzip-zipslip`；删除点可与上传/解压组合，先写后删或删除防护目录。
- 通用修复：删除前对路径做 canonical 校验并限制在允许根目录；只允许删除白名单后缀/模板文件。

## 检测与防御

- 修复：删除接口只接受模板相对路径，规范化后必须位于模板根目录内；拒绝 `..`、绝对路径、盘符、UNC；删除对象限定为文件而非目录。
- 权限：收紧 `template:del` 权限，开启操作审计；后台高危操作二次确认。
- 检测：请求参数含 `../`/`..\`、绝对路径；删除接口返回成功但目标不在模板目录；Web 目录/模板文件异常消失。
- 加固：模板目录与业务目录隔离、定期备份、文件完整性监控（FIM）告警。
