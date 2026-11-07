---
id: web-generic-auth-zentao-file-delete-idor
title: 禅道 file::delete 缺少 checkPriv 对象权限校验：改 fileID 删除他人评论附件
type: scenario
domain: web
path: web/generic/auth
technique: zentao-file-delete-missing-object-authorization
aliases:
- 禅道任意附件删除
- 禅道 file-delete 水平越权
- ZenTao file delete IDOR
- 评论附件越权删除
- CWE-639
tags:
- php
- zentao
- idor
- horizontal-privilege-escalation
- missing-authorization
- arbitrary-file-delete
- comment-attachment
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:58:57+08:00'
  notes: 已对照原文核对：module/file/control.php delete() 在 confirm=yes 分支仅 getById(fileID)→dao delete→unlinkRealFile，未调用 checkPriv；对照 download() 调用 checkPriv；model.php checkPriv 对 objectType=comment 因 objectTables 无映射直接 return true，评论附件无归属校验；前端不提供删除他人评论附件入口，直接请求 /zentao/file-delete-{fileID}-confirm-yes.html 可删除，与原文及卡内一致。原文称该洞未申请 CVE，cve 留空正确。触发条件写“普通用户即可、不要求管理员”，原文表述为“拥有 file-delete 权限的其他用户”，卡内原理段已限定“有 file-delete 访问权”，属轻微措辞差异，不影响结论。原文仅给测试环境 21.7.6-85642、未给受影响区间，已按 brief clear affected_versions。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

禅道 `file` 模块的 `delete()` 在确认删除分支直接按用户提交的 `fileID` 删除文件记录与磁盘文件，完全没有调用 `checkPriv($file)`；任意已登录用户只要拿到他人评论附件的 fileID，请求 `/zentao/file-delete-{fileID}-confirm-yes.html` 即可删除该附件，而前端并不提供删除他人评论附件的入口。

## 原理

- 漏洞入口：`module/file/control.php` 的 `delete($fileID, $confirm='no')`。当 `confirm=yes` 时执行：
  ```php
  $file = $this->file->getById($fileID);
  $this->dao->delete()->from(TABLE_FILE)->where('id')->eq($fileID)->exec();
  $this->loadModel('action')->create($file->objectType, $file->objectID, 'deletedFile', '', $file->title);
  $this->fileZen->unlinkRealFile($file);
  ```
  `$fileID` 是攻击者可控参数，删除前没有检查当前用户是否对文件关联对象有权限，也没有检查文件是否属于当前用户。
- 对照：同模块 `download()` 会调用 `$this->file->checkPriv($file)`，`delete()` 缺少这一步，属于实现不一致导致的授权缺失。
- `checkPriv()` 本身对评论附件也不生效：`module/file/model.php` 中先按 `objectType` 查 `$this->config->objectTables`，`comment` 不在该映射中，`$table` 为空时直接 `return true`；因此「评论附件」在设计上没有任何归属校验。即使补上 `checkPriv()`，评论附件仍需单独处理。
- 结果是：有 `file-delete` 访问权的普通用户可删除任意 fileID 对应的附件，包括其他用户评论中的附件，破坏评论完整性、上下文与审计轨迹。

## 触发条件

- 目标为受影响的禅道 PMS（原文在 21.7.6-85642 测试）。
- 攻击者拥有有效登录会话，且可访问 `file` 模块的 `delete` 动作（普通用户即可，不要求管理员）。
- 攻击者已知或可枚举目标附件的 `fileID`（例如通过评论接口、附件列表或页面源码获取）。
- 目标文件在磁盘上存在且进程有删除权限。

## 利用步骤

1. 以普通用户登录禅道。
2. 在他人评论、附件列表或相关接口中找到目标附件的 `fileID`。
3. 直接请求删除接口（前端未提供该入口，需手工构造）：
   `/zentao/file-delete-<fileID>-confirm-yes.html`
4. 服务端返回成功并删除 `TABLE_FILE` 记录与真实文件；评论中的附件消失。
5. 可批量更换 `fileID` 删除同一实例内任意附件，破坏数据完整性。

## PoC

```http
GET /zentao/file-delete-123-confirm-yes.html HTTP/1.1
Host: target
Cookie: zentaosid=<普通用户会话>
```

返回成功即表示文件记录与磁盘文件被删除；原文以评论附件为例，前端不提供删除入口，但后端接口直接生效。

## 变体与关联

- 变体：对其他 `objectType`（bug/task/story 等）的文件，如果调用方未携带对象权限，同样可能被删除；核心是 `delete()` 完全缺少 `checkPriv()`。
- 变体：`fileID` 可枚举时，可编写脚本按 ID 批量删除，扩大完整性破坏范围。
- 关联：[[web-php-zentao-backup-editor-arbitrary-file-delete]]（同产品后台路径穿越任意文件删除，入口与根因不同）；其他 IDOR/缺失对象级授权卡。

## 检测与防御

- 检测：普通用户在短时间内请求大量不同 `fileID` 的 `file-delete-*-confirm-yes.html`；删除的附件 `objectType=comment` 或不属于请求者；删除动作缺少对应对象的访问记录。
- 防御：`delete()` 在删除前调用并强制执行 `checkPriv($file)`，校验当前用户对 `objectType/objectID` 的权限与文件归属；对 `comment` 等不在 `objectTables` 的类型显式实现归属校验，默认拒绝而不是默认放行。
- 防御：删除接口使用 POST + CSRF Token，避免 GET 触发状态变更；对 fileID 做归属查询与审计。
- 防御：`checkPriv()` 的默认分支改为 `return false`，仅对明确支持的对象类型返回授权结果。
