---
id: web-generic-sqli-blind-filter-bypass-functions
title: IF、SLEEP、AND、OR 被过滤时的 SQL 盲注替代原语
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-blind-filter-bypass
tags:
- sqli
- blind
- waf-bypass
- benchmark
- case-when
- get-lock
- mysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:30+08:00'
  notes: 原文无图片，已核对替代原语：CASE WHEN 等价 IF、BENCHMARK 造延迟、GET_LOCK 需他连接持锁、ELT/GREATEST/位运算/LIKE 可重建 oracle，均正确。核对时把 GREATEST 示例的 AND 改为 && 并修正小节标题，使其真正对应 AND/OR 被过滤的场景。原文未涉及版本区间。未执行 PoC。
url: /docs/web/generic/sqli/web-generic-sqli-blind-filter-bypass-functions/
draft: false
kb_aliases:
- SQL 盲注绕过过滤
- IF 被过滤
- SLEEP 被禁用
- BENCHMARK 盲注
- GET_LOCK 延时
- CASE WHEN 盲注
- 时间盲注替代函数
---

## 一句话结论

SQL 盲注只需要“条件判断 + 可观察差异”；即使 `IF()`、`SLEEP()`、`AND`、`OR` 被关键字过滤，仍可用 `CASE WHEN`、`BENCHMARK()`、`GET_LOCK()`、`GREATEST()`/`LEAST()`、位运算、`LIKE`、`HAVING` 等数据库原生能力重建布尔或时间 oracle。

## 原理

- 布尔盲注依赖“条件为真/假时页面不同”；时间盲注依赖“条件为真时执行一个耗时操作”。过滤关键字只是移除了常见写法，并没有移除数据库执行条件判断和耗时操作的能力。
- 可替代的原语：
  - `CASE WHEN cond THEN a ELSE b END` 与 `IF(cond,a,b)` 语义等价，多数数据库支持，且不包含 `IF` 关键字。
  - `BENCHMARK(count, expr)` 让 MySQL 重复执行表达式 `count` 次，可制造可控 CPU 延迟，替代 `SLEEP()`。
  - `GET_LOCK(name, timeout)` 在锁被其他会话占用时等待，可作为延时原语；需要事先用另一条连接持有同名锁，否则空闲锁会立即返回。
  - `GREATEST()`/`LEAST()` 可把比较运算改写为函数调用，例如用 `GREATEST(ASCII(...), 100) > 100` 判断字符是否大于某值。
  - `ELT()` 可按索引返回字符串，用于构造布尔输出或编码判断结果。
  - 位运算、`LIKE`、`RLIKE` 可用于逐字符/逐位猜解；`HAVING`、`LIMIT/OFFSET` 可用于逐行读取。
  - 笛卡尔积（大表交叉连接）和复杂正则回溯可作为无 `SLEEP`/`BENCHMARK` 时的耗时手段，但延迟不稳定，优先用前几种。
- 时间盲注的关键是让耗时操作只在条件为真时执行；若条件为假也执行，观察不到差异。

## 触发条件

- 存在 SQL 注入，且响应可观察（内容差异、状态码差异或响应时间）。
- WAF/过滤器屏蔽了 `IF`、`SLEEP`、`AND`、`OR` 等常见关键字或函数。
- 目标数据库支持至少一种替代原语（MySQL 的 `CASE WHEN`/`BENCHMARK`/`GET_LOCK`，SQL Server 的 `CASE`/`WAITFOR`，PostgreSQL 的 `CASE`/`pg_sleep`）。
- 数据库账号有执行相应函数的权限（`BENCHMARK`、`GET_LOCK` 通常无需特殊权限）。

## 利用步骤

1. 确认注入类型与数据库（报错、版本函数、时间函数差异）。
2. 用 `CASE WHEN` 替代 `IF`，构造布尔条件。
3. 需要时间盲注时，把 `SLEEP()` 替换为 `BENCHMARK()`（MySQL）或 `WAITFOR DELAY`（SQL Server）。
4. 若 `BENCHMARK` 也被过滤，尝试 `GET_LOCK()`（需另一连接持锁）或笛卡尔积/正则回溯制造延迟。
5. 提取数据时用 `SUBSTR`/`SUBSTRING`、`ASCII`、`HEX` 等函数逐字符或逐位判断。
6. 记录正常响应时间基线，设置阈值，避免把网络抖动误判为注入成功。

## PoC

MySQL：`IF` 被过滤，用 `CASE WHEN` 做时间盲注。

```sql
id=1 AND CASE WHEN (ASCII(SUBSTR(database(),1,1))=100) THEN SLEEP(5) ELSE 0 END
```

`SLEEP` 被过滤，用 `BENCHMARK` 制造延迟。

```sql
id=1 AND CASE WHEN (ASCII(SUBSTR(database(),1,1))=100) THEN BENCHMARK(5000000,MD5('a')) ELSE 0 END
```

`GET_LOCK` 延时（先在另一连接执行 `SELECT GET_LOCK('hack',0);` 持有锁）：

```sql
id=1 AND CASE WHEN (ASCII(SUBSTR(database(),1,1))=100) THEN GET_LOCK('hack',5) ELSE 0 END
```

`AND`/`OR` 被过滤，用 `&&`/`||` 连接，比较运算可用 `GREATEST` 改写：

```sql
id=1 && GREATEST(ASCII(SUBSTR(database(),1,1)),100)>100
```

布尔输出用 `ELT`：

```sql
id=1 AND ELT(1,'false','true')
```

SQL Server：`SLEEP` 不适用，用 `WAITFOR DELAY`。

```sql
id=1; IF (ASCII(SUBSTRING(DB_NAME(),1,1))=100) WAITFOR DELAY '0:0:5'--
```

说明：

- `BENCHMARK` 的 `count` 需要按目标 CPU 调整，太小观察不到、太大可能超时。
- `GET_LOCK` 方案依赖持锁连接，连接断开或锁超时会失效。
- 笛卡尔积/正则回溯延迟受数据量和版本影响，稳定性差，仅作备用。

## 变体与关联

- 变体：`RLIKE`/`REGEXP` 高回溯正则制造 CPU 消耗，但 MySQL 8 使用 ICU 正则引擎后行为可能变化，需实测。
- 变体：`HAVING` 子查询、`LIMIT/OFFSET` 逐行读取，适合无 `UNION` 的盲注。
- 变体：用 `CONV`/`HEX`/`BIN` 把数据转成可比较形式，减少请求次数。
- 关联：[[web-generic-sqli-exists-left-boolean-oracle]]（布尔 oracle 的响应差异构造）。
- 关联：[[web-generic-sqli-dnslog-oob-exfiltration]]（无回显时的带外通道）。

## 检测与防御

- 修复：参数化查询，消除注入入口。
- 加固：数据库设置语句超时（如 MySQL `max_execution_time`）、限制单用户查询资源；WAF 同时覆盖 `CASE`、`BENCHMARK`、`GET_LOCK`、`GREATEST`、`ELT` 等替代原语，而不只黑名单 `SLEEP`。
- 加固：监控异常长的查询和重复的相似查询；对同一参数的高频请求做速率限制。
- 检测：SQL 日志中出现 `BENCHMARK`、`GET_LOCK`、`CASE WHEN`、`GREATEST`、`ELT` 与 `SUBSTR`/`ASCII` 的组合；查询耗时呈规律性阶梯变化；同一会话连续测字符。
