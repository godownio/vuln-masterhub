---
id: web-generic-sqli-postgres-waf-comment-quote-bypass
title: PostgreSQL 注入绕 WAF：关键字间插入 /*"*/ 注释与 JSON Unicode 转义
type: scenario
domain: web
path: web/generic/sqli
technique: postgres-waf-comment-quote-json-escape-bypass
tags:
- web
- sqli
- postgresql
- waf-bypass
- comment
- json
- unicode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:26:57+08:00'
  notes: 已对照原文与 img/05、06 核对：shareType=4-1 与 3 结果一致、order 注释对照（order/**/by 与 order/*123*/by 被 502，order 带引号注释通过）、union 注释与 JSON Unicode 转义均一致；核对时修正了 PoC 对照块重复行，已按原文四条测试结果重写；保留。
url: /docs/web/generic/sqli/web-generic-sqli-postgres-waf-comment-quote-bypass/
draft: false
kb_aliases:
- PostgreSQL 绕 WAF
- order/*"*/by
- union/*"*/select
- 注释绕过 WAF
- JSON Unicode 转义绕过
- openresty 502 WAF
---

## 一句话结论

在 PostgreSQL 数值型注入点上，当 WAF 用连续关键字正则拦截 `order by`、`union select` 等短语时，把带引号的块注释 `/*"*/` 插到两个关键字之间（`order/*"*/by`、`union/*"*/select`），PostgreSQL 把注释当空白、SQL 语义不变，而 WAF 的匹配规则失效；JSON 请求体里再用 `"`/`s` 等 Unicode 转义隐藏引号和字母，可进一步绕过只检查原始字符串的 WAF。

## 原理

- SQL 词法允许块注释 `/* ... */` 出现在 token 之间，解析器会把注释内容整体当作空白忽略。因此 `ORDER/*任意内容*/BY`、`UNION/*任意内容*/SELECT` 与 `ORDER BY`、`UNION SELECT` 在 PostgreSQL 中语义相同。
- 文章实测：`order/**/by` 和 `order/*123*/by` 被 WAF 拦截并返回 502，而 `order/*"*/by` 不拦截且查询成功。说明 WAF 的规则并非真正解析 SQL，而是用正则匹配“关键字+注释+关键字”的某种形态；注释里出现双引号会破坏其匹配模式，但对 SQL 解析器没有任何影响。
- JSON 请求体是另一层解析差异：`"` 解码后是 `"`，`s` 解码后是 `s`。WAF 若在 JSON 解码前检查原始字符串，就看不到真正的 `"` 和 `select` 关键字；后端 JSON 解析后再交给 SQL 引擎，payload 恢复正常。
- 目标参数是数值型注入：`shareType=4-1` 与 `3` 返回相同结果，说明值被拼进 SQL 表达式而不是被严格转成数字，给后续 `order by`/`union select` 提供了注入位置。
- WAF 返回 openresty 的 502 错误页，多次触发会封 IP，因此绕过不仅是语法问题，还要控制探测频率、逐字符试错。

## 触发条件

- 参数以数值/表达式形式进入 SQL（如 `shareType=4-1` 与 `3` 等价），且未被参数化查询处理。
- 后端为 PostgreSQL；WAF 基于正则/关键字匹配，而非完整 SQL 词法分析。
- 请求体为 JSON，且 WAF 与后端对 JSON Unicode 转义/注释的解析存在先后差异。
- 攻击者能观察成功/失败差异（数据返回、状态码、报错），且未被 IP 封禁策略立即阻断。

## 利用步骤

1. 确认注入：比较 `{"shareType":"3"}`、`{"shareType":"4"}`、`{"shareType":"4-1"}` 的返回，若 `4-1` 与 `3` 一致而 `4` 为空，说明值进入 SQL 表达式。
2. 用 `order/*"*/by 1 -- ` 逐步递增列数；被 502 拦截时更换注释内容/编码，避免触发同一规则和 IP 封禁。
3. 用 `union/*"*/select ...` 回显数据库信息，例如 `current_database()`、`version()`；关键字被拦时把字母写成 `select` 等 JSON 转义。
4. 对字符串常量做同等处理（引号写 `"`，或改用 `chr()`/`concat()`/`||` 生成），以绕过对 `'` 和 `{}` 的过滤。
5. 枚举表名和列名后查询目标数据；全过程控制请求频率，避免触发 502 后的 IP 封禁。

## PoC

概念上的 SQL 片段（注释插在关键字之间）：

```sql
ORDER/*"*/BY 1 --
UNION/*"*/SELECT current_database(), '2' --
UNION/*"*/SELECT tablename, '2' FROM pg_tables --
```

JSON 请求体中的实际编码（对引号和字母做 Unicode 转义，字符 `"` 写成 `\u0022`、`s` 写成 `\u0073`）：

```json
{"shareType":"4 order/*\u0022*/by 1 -- "}
{"shareType":"3 union/*\u0022*/\u0073elect current_database(),'2' -- "}
{"shareType":"3 union/*\u0022*/\u0073elect tablename,'2' FROM pg_tables -- "}
```

文章中的对照结果（为可读性按原始形态展示，实际放入 JSON 时需按上例转义）：

```text
{"shareType":"4 orderby 1 -- "}          -> 不拦截，查询失败
{"shareType":"4 order/**/by 1 -- "}      -> 拦截，502
{"shareType":"4 order/*123*/by 1 -- "}   -> 拦截，502
{"shareType":"4 order/*"*/by 1 -- "}     -> 不拦截，查询成功
```

## 变体与关联

- 变体：MySQL 用版本注释 `/*!50000union*/`；WAF 若把 `/*!...*/` 当普通注释忽略，MySQL 却会执行其中的关键字；见 [[web-generic-sqli-ai-waf-mysql-versioned-comment-bypass]]。
- 变体：在关键字中插入换行/制表符/`%0a` 拆断正则；见 [[web-generic-sqli-waf-newline-keyword-split-hex]]。
- 变体：利用数据库语义差异构造“对 WAF 无害、对后端有害”的表达式；见 [[web-generic-sqli-semantic-waf-layerwise-bypass]]。
- 关联：[[web-generic-sqli-postgres-json-column-enum]]（同一注入点后续用 JSON 函数取列名）。
- 边界：WAF 若先完整 JSON 解码再做 SQL 词法分析、或使用参数化查询/白名单，注释与转义手法失效。

## 检测与防御

- 检测：请求体中出现 `/*` 注释嵌在 SQL 关键字之间、`"`/`s` 等异常 Unicode 转义、同一参数短时间大量 `order by`/`union select` 变体；openresty 502 集中出现可作为 WAF 触发信号。
- 防御：对输入做 JSON 解码后再按 SQL 词法分析/规范化，而不是直接正则匹配原始字符串；数值参数强制类型转换并白名单。
- 加固：使用参数化查询/预编译语句；数据库账号最小权限；对重复触发 WAF 的源 IP 限速/封禁；记录被拦截的原始 payload 供规则迭代。
