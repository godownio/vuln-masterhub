---
id: web-generic-sqli-http-header-injection
title: HTTP 请求头作为 SQL 注入点：GET/POST 被过滤后的 User-Agent、X-Forwarded-For、Cookie、Referer 注入
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-http-header-injection
tags:
- sqli
- http-header
- waf-bypass
- user-agent
- x-forwarded-for
- cookie
- referer
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:24+08:00'
  notes: 原文无图片，已对照原文核对请求头注入思路：User-Agent/X-Forwarded-For/Cookie/Referer 值可进入日志落库或查询，GET/POST 过滤不覆盖请求头；卡中布尔/时间探测 payload 与数据库注释符差异正确，并注明头值落库后可能的二次注入。原文仅泛述，confidence=medium 合理。原文未涉及版本区间。未执行 PoC。
url: /docs/web/generic/sqli/web-generic-sqli-http-header-injection/
draft: false
kb_aliases:
- 请求头 SQL 注入
- Header 注入绕过 WAF
- User-Agent 注入
- X-Forwarded-For 注入
- Cookie 注入
- Referer 注入
---

## 一句话结论

当应用把 `User-Agent`、`X-Forwarded-For`、`Cookie`、`Referer` 等请求头的值拼进 SQL（常见于访问日志落库、真实 IP 记录、会话查询、来源统计），而这些头又不在 GET/POST 参数过滤或 WAF 的检查范围内时，攻击者可以把注入 Payload 放进请求头完成注入，绕过只看请求参数的防护。

## 原理

- HTTP 头的值同样是攻击者完全可控的字符串，和 GET/POST 参数没有本质区别。应用若把某个头当作“可信的元数据”直接拼接进 SQL，就产生了注入点。
- 常见落点：
  - 访问日志/审计表把 `User-Agent`、`Referer` 原样写入数据库；
  - 反向代理或业务用 `X-Forwarded-For` 获取客户端真实 IP，再用于查询、黑白名单或统计；
  - `Cookie` 中的会话标识、用户 ID、主题偏好被直接拼进查询；
  - 广告/渠道统计把 `Referer` 写入数据库。
- 很多 WAF 与自研过滤器只解析 URL 查询串和 `application/x-www-form-urlencoded`/JSON 正文，不检查或不完整检查请求头；有的只在特定头（如 Cookie）上做规则，遗漏 `User-Agent`、`X-Forwarded-For`。
- 引发注入的根因仍是字符串拼接 SQL，请求头只是绕过了输入侧过滤，不是新的数据库缺陷。

## 触发条件

- 目标存在 GET/POST 参数过滤或 WAF，但未覆盖请求头。
- 应用把至少一个请求头的值用于 SQL 拼接或写入后再拼接查询。
- 注入结果可通过报错、布尔差异、时间延迟或带外通道观察。
- 头值长度、字符集和代理链路允许 Payload 到达后端（部分代理会截断或规范化特定头）。

## 利用步骤

1. 枚举可能被记录或参与查询的头：`User-Agent`、`X-Forwarded-For`、`X-Real-IP`、`Referer`、`Cookie`、`Origin`、`X-Requested-With`。
2. 先在各头中放入单引号、双引号、括号等，观察是否出现 SQL 报错或页面差异。
3. 用布尔条件确认：`' AND '1'='1` 与 `' AND '1'='2` 的响应差异。
4. 用时间盲注确认：`' AND SLEEP(5)-- -`（MySQL）/ `'; WAITFOR DELAY '0:0:5'--`（SQL Server）。
5. 确认后按目标数据库语法提取数据；必要时对头值做 URL 编码，避免被代理或日志组件改写。
6. 若头会写入日志表，可先注入一条 Payload，再触发后台读取日志的功能形成二次注入。

## PoC

```http
GET / HTTP/1.1
Host: target
User-Agent: ' OR 1=1-- -
X-Forwarded-For: 127.0.0.1' AND SLEEP(5)-- -
Referer: http://target/' OR '1'='1
Cookie: uid=1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -
```

SQL Server 时间盲注头：

```http
X-Forwarded-For: 127.0.0.1'; WAITFOR DELAY '0:0:5'-- -
```

说明：

- 不同数据库注释符不同：MySQL 用 `-- `（后跟空格）或 `#`，SQL Server/Oracle 用 `--`，PostgreSQL 用 `--`。
- 头值中的空格、引号可能被代理或日志组件转义，必要时用 `/**/`、`+`、URL 编码替代。
- 若应用只记录头而不立即查询，需要找到后续使用该记录的查询点（日志检索、统计报表、后台审核）。

## 变体与关联

- 变体：`X-Forwarded-For` 同时用于 IP 白名单判断，注入可结合身份/权限绕过。
- 变体：`Cookie` 中的 Base64/JSON 值解码后拼接，需先构造合法外层编码。
- 变体：`X-Api-Version`、`Accept-Language`、自定义业务头同样可能进入 SQL。
- 关联：[[web-generic-sqli-second-order-injection]]（头值落库后在别处被拼接）。
- 关联：[[web-generic-sqli-exists-left-boolean-oracle]]（布尔 oracle 的构造方式）。

## 检测与防御

- 修复：所有 SQL 使用参数化查询/预编译，请求头与 GET/POST 参数一视同仁，不因来源是“头”而信任。
- 加固：WAF 与输入过滤覆盖全部请求头；对 `X-Forwarded-For` 只取可信代理链中最右侧的可信地址，并做格式校验。
- 加固：日志入库使用参数化写入；日志检索/统计功能对存储值再次参数化，避免二次注入。
- 检测：请求头中出现 SQL 关键字、注释符、`SLEEP`/`WAITFOR`/`BENCHMARK`；同一 IP 在短时间内对多个头做引号/布尔探测；数据库错误日志中出现由头值触发的语法错误。
