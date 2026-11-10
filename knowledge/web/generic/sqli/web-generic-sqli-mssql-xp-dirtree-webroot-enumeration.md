---
id: web-generic-sqli-mssql-xp-dirtree-webroot-enumeration
title: xp_cmdshell 被拦时用 xp_dirtree 递归列目录定位 Web 站点绝对路径
type: scenario
domain: web
path: web/generic/sqli
technique: mssql-xp-dirtree-directory-enumeration
aliases:
- xp_dirtree 列目录
- MSSQL 找网站绝对路径
- xp_dirtree 递归 subdirectory
- 数据库列目录找 web.config
- xp_dirtree 1 1
tags:
- mssql
- sql-server
- recon
- directory-enumeration
- xp-dirtree
- webroot
- post-exploitation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:46:02+08:00'
  notes: 已对照原文与 10 张图核对：图01 Select IS_SRVROLEMEMBER(sysadmin) 返回 1；图02 xp_cmdshell whoami 报 [42000] SQL Server Native Client 10.0「调用 CreateProcess 失败，错误代码 5」；图04 exec xp_dirtree 列出 subdirectory/depth/file 三列并在结果中看到 web.config，与卡内原理/触发条件/PoC 一致。卡内把「权限模型/先在盘符根枚举再递归」写成通用判据，并明确 xp_dirtree 只需 T-SQL、不走 CreateProcess，与原文结论一致，无 CVE 与版本信息可填（原文未标注），保持空。未验证点：未在 MSSQL 实例复跑、xp_dirtree 默认 EXECUTE 授权范围未实测。
---

## 一句话结论

当已拿到 SQL Server 的 sysadmin 会话但 `xp_cmdshell` 执行失败（例如被策略/杀软拦在 `CreateProcess`）时，仍可用扩展存储过程 `xp_dirtree` 以数据库服务账户身份递归列出任意目录（含文件名），据此从盘符开始逐层缩小范围，定位 IIS/ASP.NET 站点的绝对路径与 `web.config` 所在目录，为后续落盘 webshell 提供精确路径。

## 原理

- **`xp_dirtree` 是文件系统 API 的代理**：它由 SQL Server 服务账户进程内调用 Win32 目录枚举，返回表结构 `(subdirectory, depth, file)`。`depth` 控制递归层数，`file` 为 1 时同时返回文件名、为 0 时只返回子目录名。因此即便命令执行通道被切断，只要还能执行 T-SQL，就仍能通过数据库进程「看」文件系统。
- **权限模型**：该扩展存储过程默认对 `public` 授予 EXECUTE 的场景很常见，但更稳妥的前提是 `sysadmin`/`CONTROL SERVER` 或显式被授予执行权限；它不需要 `xp_cmdshell` 的 `CreateProcess` 能力，所以不受「禁止调用系统命令」的策略影响。
- **为什么能定位 Web 根**：目录名与文件名会直接暴露应用布局（如 `Wuye`、`web.config`、`Global.asax`、`bin`、`App_Data` 等特征名）；先列盘符根目录拿到一级目录，再对可疑目录加大 `depth` 递归，即可在几轮内命中站点目录。相比盲猜路径，这一步把「写马需要绝对路径」的前置条件从猜测变成枚举。
- **与文件读取的配合**：找到 `web.config` 后可用 `OPENROWSET(BULK ...)` 读取其内容确认站点配置与数据库连接串，二者构成一套完整的「无命令执行条件下的落点侦察」组合。

## 触发条件

- 已获得 SQL Server 的 sysadmin（或对该扩展存储过程有执行权限）会话，`Select IS_SRVROLEMEMBER('sysadmin')` 返回 1。
- `xp_cmdshell` 不可用、被策略禁用或被安全产品拦截（`CreateProcess` 失败），无法直接执行 `dir` 一类命令。
- SQL Server 服务账户对目标磁盘有读取权限（通常为服务账户或 SYSTEM 级，能读大多数目录）。
- 目标为 Windows + IIS/ASP.NET 一类「需要绝对路径才能写马」的站点。

## 利用步骤

1. 确认权限：`Select IS_SRVROLEMEMBER('sysadmin');` 返回 1。
2. 列出盘符根下的一级目录：`EXEC xp_dirtree 'C:\', 1, 0;`（`file=0` 只看目录，减少噪声）。
3. 对可疑盘（Web 常部署在 `D:`、`E:` 或 `C:\inetpub`）逐层递归：`EXEC xp_dirtree 'd:\', 2, 1;`，观察结果中的 `subdirectory`/`depth`/`file` 三列。
4. 依据特征名（`web.config`、`bin`、`App_Data`、`Global.asax`、业务目录名）锁定站点根，记录完整绝对路径。
5. 用 `OPENROWSET` 读取该目录下的 `web.config` 验证（见关联卡），确认这就是目标站点且可写。
6. 把绝对路径交给落盘步骤（OLE 自动化写马、备份写马等）。

## PoC

```sql
-- 权限确认
Select IS_SRVROLEMEMBER('sysadmin');

-- 只列子目录
EXEC xp_dirtree 'C:\Temp', 1;

-- 递归列出目录与文件名（原文用此方式定位站点）
EXEC xp_dirtree 'd:\<业务目录>\', 1, 1;
```

原文输出（结果集三列，可据此逐层展开）：

```text
subdirectory        depth  file
<子目录名>            1     1
<子目录名>            1     0
<文件名 web.config>   1     1
```

`xp_cmdshell` 在本场景中失败的返回（作为改用 `xp_dirtree` 的直接原因）：

```text
exec master..xp_cmdshell 'whoami';
> [42000] [Microsoft][SQL Server Native Client 10.0][SQL Server]
  在执行 xp_cmdshell 的过程中出错。调用 'CreateProcess' 失败，错误代码: '5'。
```

PoC 未在本机执行。

## 变体与关联

- **变体**：`xp_dirtree` 只给名字不给内容；若需要读内容换 `OPENROWSET(BULK ...)`；若两者都被禁用，可用 `xp_fileexist` 判断单文件是否存在（低噪声探测）；也可用 `xp_subdirs` 只看子目录。
- **深度策略**：`depth` 越大越慢且结果量爆炸；实践中先 `depth=1` 逐层走，命中业务目录后再用 `depth=2/3` 精确展开。
- **关联**：[[web-generic-sqli-mssql-openrowset-bulk-arbitrary-file-read]]（同一前置条件下读文件内容）、[[web-generic-sqli-mssql-ole-fso-write-webshell]]（拿到路径后的落盘）、[[web-generic-sqli-mssql-backup-sp-makewebtask-webshell]]（同样需要绝对路径的另一类写马方式）。
- **边界**：数据库服务账户对目标目录无读权限、或该扩展存储过程被 `sp_configure`/策略禁用时不可用；结果集只含名字，不含权限与时间戳，判断可写仍需后续动作验证。

## 检测与防御

- **加固**：收紧 `xp_dirtree` 的 EXECUTE 权限（只授予必要角色），与 `xp_cmdshell`、`Ole Automation Procedures`、`Ad Hoc Distributed Queries` 一起纳入「默认全部关闭 + 白名单」策略。
- **检测信号**：SQL Server 审计日志/扩展事件中出现 `xp_dirtree`、`xp_fileexist`、`xp_subdirs` 调用，尤其是对盘符根或 Web 目录的递归调用；同一会话短时间内出现权限查询（`IS_SRVROLEMEMBER`）→ 目录枚举 → 文件读取的连续动作。
- **响应**：出现此类调用即视为数据库已被高权限控制，按凭据泄露处置并核查 Web 目录新增文件。
