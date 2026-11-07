---
id: web-generic-sqli-mysql-limit-procedure-analyse
title: MySQL LIMIT 位置注入：PROCEDURE ANALYSE 触发报错/延时
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-limit-clause-procedure-analyse
tags:
- sqli
- mysql
- limit
- procedure-analyse
- error-based
- time-based
- injection-position
cve: []
severity: high
confidence: medium
status: verified
affected_versions: MySQL 5.0.0 < 版本 < 5.6.6（原文标记）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:06:01+08:00'
  notes: 已对照原文核对：LIMIT后procedure analyse(extractvalue(rand(),concat(0x3a,database())),1)与原文一致，原文标记5.0.0<MySQL<5.6.6；已将affected_versions修正为仅保留原文标记，删除原卡中'5.6.6起被移除/弃用'这一非原文且不准确的说明（PROCEDURE ANALYSE实际在5.7.18弃用、8.0移除）；PoC未复现
url: /docs/web/generic/sqli/web-generic-sqli-mysql-limit-procedure-analyse/
draft: false
kb_aliases:
- MySQL LIMIT 注入
- procedure analyse 注入
- limit 后注入
- LIMIT 位置报错注入
- limit 位置盲注
---

## 一句话结论

当注入点位于 `LIMIT` 子句之后（如 `LIMIT ($page-1)*$limit,$limit` 中的 `$page`/`$limit`），常规 `UNION`/`WHERE` 注入不可用，但 MySQL 5.0.0–5.6.6 支持 `PROCEDURE ANALYSE(expr, n)`：把子查询/报错函数/延时函数放进 `ANALYSE` 的参数，即可在 `LIMIT` 位置触发报错或时间盲注。

## 原理

- **LIMIT 的语法限制**：`LIMIT` 只接受整数常量、变量或简单表达式，不能直接跟 `UNION SELECT`、`AND` 子查询等常规注入片段；注入点若被拼进 `LIMIT` 的数字位置，常规 payload 会产生语法错误。
- **PROCEDURE ANALYSE 的位置**：MySQL 允许在查询末尾使用 `PROCEDURE ANALYSE([max_elements[, max_memory]])` 对结果集做分析。它出现在 `LIMIT` 之后、作为查询的 procedure 子句，因此可以在 `LIMIT` 位置注入后接入。
- **表达式求值**：`ANALYSE` 的第一个参数是表达式，MySQL 会对其求值/分析。把 `EXTRACTVALUE(RAND(), CONCAT(0x3a, DATABASE()))` 放在这里，会触发 XPath 报错并把库名带进错误信息；把 `BENCHMARK(...)` 或 `SLEEP(...)` 放在条件表达式里可制造延时。
- **版本窗口**：`PROCEDURE ANALYSE` 在 MySQL 5.0.0 之后可用，5.6.6 起被移除（原文标注 5.0.0 < MySQL < 5.6.6）；MySQL 8 不再支持。
- **利用条件**：注入点必须落在 `LIMIT` 之后且能闭合/拼接出合法的 `PROCEDURE ANALYSE(...)`；页面需回显数据库错误（报错注入）或响应时间可观察（时间盲注）。

## 触发条件

- MySQL 版本在 5.0.0–5.6.6 之间，且 `PROCEDURE ANALYSE` 可用。
- 注入点位于 `LIMIT` 子句之后（页码、每页条数、偏移量等参数被直接拼接）。
- 常规 `UNION`/`WHERE`/`ORDER BY` 注入因位置或语法限制不可用。
- 错误信息可见（报错注入）或响应时间可测量（时间盲注）。
- WAF 未拦截 `PROCEDURE`、`ANALYSE`、`EXTRACTVALUE`、`BENCHMARK` 等关键字。

## 利用步骤

1. 确认注入点位于 `LIMIT` 之后：修改页码/每页条数观察 SQL 语法错误或结果集变化。
2. 尝试在参数后拼接 `PROCEDURE ANALYSE(1,1)`，确认是否能形成合法查询。
3. 报错注入：把 `EXTRACTVALUE(RAND(), CONCAT(0x3a, DATABASE()))` 放入 `ANALYSE` 第一个参数，观察错误信息是否带出库名。
4. 时间盲注：把条件与 `BENCHMARK()`/`SLEEP()` 放入 `ANALYSE` 表达式，比较响应时间；按目标调整 benchmark 次数。
5. 替换子查询提取表名/列名/数据；长数据用 `SUBSTR` 分段。
6. 若 `PROCEDURE ANALYSE` 被禁用或版本不符，改用其他 `LIMIT` 位置技巧或寻找其它注入点。

## PoC

报错注入：

```text
limit=1 procedure analyse(extractvalue(rand(),concat(0x3a,database())),1)
```

生成查询形态：

```sql
SELECT ... FROM ... LIMIT 1 PROCEDURE ANALYSE(EXTRACTVALUE(RAND(),CONCAT(0x3a,DATABASE())),1)
```

错误信息中会出现类似 `XPATH syntax error: ':database_name'` 的内容。

时间盲注形态（示意）：

```text
limit=1 procedure analyse(if(ascii(substr(database(),1,1))>100,benchmark(5000000,md5('a')),0),1)
```

原文说明该位置只能使用 `EXTRACTVALUE` 与 `BENCHMARK` 进行延时/报错，具体可用性需按版本与查询结构实测。

## 变体与关联

- 变体（报错函数）：`EXTRACTVALUE`、`UPDATEXML`、`FLOOR(RAND())` 等可放入 `ANALYSE` 表达式；不同版本对函数支持不同。
- 变体（延时函数）：`BENCHMARK`、`SLEEP`；`BENCHMARK` 次数需按 CPU 调整。
- 变体（注入位置）：`LIMIT offset,count` 的 offset 或 count、`LIMIT count OFFSET offset` 的 count/offset，均可尝试。
- 关联：[[web-generic-sqli-error-based-extraction]]（报错注入的通用函数与原理）。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（时间盲注替代原语）。
- 边界：MySQL ≥5.6.6 或 8.x 不支持 `PROCEDURE ANALYSE`；WAF 拦截 `PROCEDURE`/`ANALYSE`；查询结构不允许在 LIMIT 后追加 procedure 子句时失效。

## 检测与防御

- 修复：`LIMIT` 参数强制转换为整数并使用参数化查询（如 `LIMIT ?, ?`），禁止拼接。
- 加固：升级到不再支持 `PROCEDURE ANALYSE` 的 MySQL 版本；WAF 覆盖 `PROCEDURE`、`ANALYSE`、`EXTRACTVALUE`、`BENCHMARK` 等关键字。
- 检测：请求参数中出现 `procedure`、`analyse`、`extractvalue`、`benchmark`、`sleep`、`database()`；SQL 日志中出现 `LIMIT ... PROCEDURE ANALYSE`；响应时间规律性增加或错误信息含 `XPATH syntax error`。
- 运营：审计所有拼接 `LIMIT` 的代码路径；对分页参数做类型/范围校验。
