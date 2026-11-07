---
id: web-dotnet-rest-auth-bypass-header-parameter-override
title: REST 管线鉴权开关短路与请求头参数覆盖导致未授权 SQL 注入
type: scenario
domain: web
path: web/dotnet
technique: rest-pipeline-auth-bypass
aliases:
- IsFree 鉴权绕过
- 请求头参数覆盖
- Authorization 头注入
- 未授权 SQL 注入
- 畅捷通 T+ 注入
tags:
- dotnet
- rest
- auth-bypass
- sqli
- header-injection
- waf-bypass
- mssql
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:08:42+08:00'
  notes: 已对照原文与20张图核对：IsFree=1 短路验签、Authorization 头 orgId 覆盖、内置密钥表、AccountBE 直拼 WHERE、InterceptService 不查 Authorization 头均一致；原文载荷脱敏，PoC 未执行
---

## 一句话结论

当 REST 框架用查询参数（如 `IsFree=1`）直接短路验签、又在管线里用 Authorization 头解析出的字段强制覆盖业务参数时，攻击者无需任何凭据即可把一个未校验的请求头字段送进 SQL 拼接点，形成未授权 SQL 注入。

## 原理

三个缺陷叠加：

1. **鉴权开关由客户端控制**：REST 主处理器只在 `!IsFree && !IsLocalSessionCall` 时调用验签；请求带 `IsFree=1` 就把整个验签与会话校验跳过。
2. **参数来源被请求头覆盖**：v2 管线对特定方法（如 `GetAnonymousTPlusToken`）有硬编码分支，把 `Arguments["orgId"]` 等参数改写为从 Authorization 头解析出的 `OrgId`。请求体里的同名参数被丢弃，真正进入业务方法的是请求头 JSON 中的值。
3. **头字段直拼 SQL**：业务层用该值查询账套，拼成 `CloudOrganizationID=N'<orgId>' AND ...`，没有参数化或转义；以高权限数据库账户执行。引号闭合后即可堆叠任意 SQL。

Authorization 头通常是 Base64 编码的 JSON，包含 `appKey`、`authInfo`、`orgId`。`appKey/authInfo` 只需通过结构解析；若产品内置的密钥对随安装包分发并被硬编码在程序集里，攻击者可直接取用，不需要任何真实凭据。

WAF/拦截组件只遍历查询串、表单参数、请求体原文和 URL，不读取 Authorization 头，因此载荷放在请求头里全程不被关键词规则检查；默认 IIS 日志也不记录请求头，常规日志里看不到载荷。

## 触发条件

- 目标暴露 REST v2 接口，且存在可由查询参数触发的鉴权短路（如 `IsFree`）；
- 管线对匿名方法存在“用 Authorization 字段覆盖业务参数”的硬编码分支；
- 请求头中的参数未经参数化直接拼接进 SQL；
- 数据库连接账户权限过高（如 sysadmin）；
- WAF 的检查范围不包含 Authorization 头。

## 利用步骤

1. 确认接口路径与匿名方法名，构造 `?IsFree=1` 跳过验签；
2. 收集/猜测产品内置的 `appKey` 与 `authInfo` 结构（可从安装包、程序集字符串、应用自身云端交互日志中观察）；
3. 构造 Base64 JSON，把注入载荷放入 `orgId` 字段，请求体放固定占位参数；
4. 先注入单引号观察是否返回 SQL 错误页，再用延时语句确认堆叠执行；
5. 在 `orgId` 中执行任意 SQL，进一步开启数据库命令执行能力。

## PoC

```http
POST /tplus/api/v2/collaborationapp/GetAnonymousTPlusToken?IsFree=1 HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Authorization: <base64({"appKey":"<内置key>","authInfo":"<结构合法值>","orgId":"x' ; WAITFOR DELAY '0:0:6'-- "})>

dummy=1
```

判定：单引号返回 HTTP 200 的 SQL 错误页；延时请求比对照组慢约 6 秒，说明 `orgId` 进入 SQL 且支持堆叠。

```
CloudOrganizationID=N'x' ; WAITFOR DELAY '0:0:6'-- ' AND OpenCloudAppState=1 AND cState<100
```

`--` 注释掉尾部条件；具体注释符与堆叠语法随数据库而定。

## 变体与关联

- 变体：其他匿名方法也可能存在参数覆盖分支；内置密钥对可能有多组，可逐组尝试；`IsFree` 之外还可能有 `IsLocalSessionCall` 等本地调用标志。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（拿到注入后的命令执行）；[[defense-forensics-iis-freb-header-payload-capture]]（请求头载荷的取证）。
- 修复注意：仅在 WAF 中增加正则但不接线（无调用方）无效；有效修复通常是让鉴权覆盖 `IsFree` 场景，在进入 SQL 前拒绝异常字符。

## 检测与防御

- 检测：匿名接口出现 `IsFree=1` 且响应 200；Authorization 头是 Base64 JSON 且 `orgId` 含引号、分号、注释符；同一 IP 短时间连续请求同一匿名方法。
- 防御：鉴权在业务分发前统一执行，不能让查询参数关闭验签；请求头字段与请求体字段同等校验；SQL 全部参数化；数据库账户降权，应用账户不使用 sysadmin；WAF 覆盖所有请求头；内置密钥不应随产品分发，支持轮换。
