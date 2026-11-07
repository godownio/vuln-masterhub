---
id: web-generic-sqli-sqlite-union-values-select-filter-bypass
title: SQLite UNION VALUES 绕过 SELECT 关键字过滤：无需 SELECT 生成 admin 行
type: scenario
domain: web
path: web/generic/sqli
technique: sqlite-union-values-select-filter-bypass
aliases:
- UNION VALUES
- VALUES 子句注入
- SELECT 关键字过滤绕过
- SQLite 登录绕过
- SQLite 注入
tags:
- sqli
- sqlite
- union
- values
- waf-bypass
- keyword-filter
- login-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V142
  verified_at: '2026-11-06T06:23:14+08:00'
  notes: '已对照原文 content.md 与 5 张图核对：SQLi 技术来自图 04 的 CTF 输出，注入点 username、正则 /SELECT/i 过滤、payload、生成的 SQL、is_admin 触发 include(''../flag.php'') 与 flag 均一致。已修正两处：①原文 payload 为 '' UNION VALUES(''admin'',1)--（两横线），卡片误写 #，而 SQLite 不把 # 当注释符（本机 sqlite3 验证 # 会报 unrecognized token，-- 正常返回 (''admin'',1)）；②flag 按截图逐字改为 KosenCTF{d0_y0u_kn0w_that_the_w0rd_valu35_can_b3_aft3r_un10n}。未验证点：仅图 04 的 writeup 输出，未在靶场复跑；原文未标受影响版本，未设置 affected_versions；frontmatter 无 sources/source_url。'
---

## 一句话结论

当应用用正则拦截 `SELECT` 关键字时，SQLite 仍允许 `UNION VALUES(...)` 直接生成行；在单引号字符串拼接的登录注入点构造 `' UNION VALUES('admin',1)--`，即可让查询返回 `is_admin=1` 的管理员行，绕过关键字过滤并触发后台的 admin/flag 逻辑。

## 原理

- SQLite 的 `VALUES(expr, ...)` 本身就是一个复合查询（compound SELECT），可以独立生成行，也可以与 `SELECT` 用 `UNION` 组合；因此 `SELECT username, is_admin FROM users WHERE username = '' UNION VALUES('admin',1)` 是合法 SQL，效果等价于追加一行 `('admin', 1)`。
- 应用的黑名单只匹配 `SELECT`（如正则 `/SELECT/i`），没有拦截 `VALUES`、`UNION` 或注释符；payload 中不含 `SELECT`，因此通过过滤。
- 注入点在单引号字符串拼接的 `username` 参数：`'` 闭合原字符串，`UNION VALUES('admin',1)` 追加一行，`--` 注释掉后面的 `AND password = '...'`（SQLite 中 `#` 不是注释符）。
- 查询返回 `username, is_admin` 两列，注入行第二列为 `1`；应用用 `if ($is_admin)` 判断管理员并 `include('../flag.php')` 或放行后台，攻击者无需知道密码即可获得管理员语义。
- 根本原因是黑名单过滤无法覆盖 SQL 方言的等价语法：只要存在另一种生成行的写法，关键字黑名单就可被绕过。

## 触发条件

- 后端为 SQLite（或支持 `VALUES` 复合查询的数据库；MySQL 8.0 用 `VALUES ROW(...)`，PostgreSQL 用 `VALUES (...)`，语法需调整）。
- 存在单引号字符串拼接的注入点（如登录 `username`），且未使用参数化查询。
- 过滤规则只拦截 `SELECT` 等少数关键字，未拦截 `UNION`/`VALUES`/注释符。
- 注入点所在查询的列数、列类型与 `VALUES(...)` 匹配，且结果中的管理员标志位/flag 逻辑可由注入行控制。

## 利用步骤

1. 确认注入与数据库：提交 `username='` 观察报错/登录行为变化；尝试 `' UNION SELECT ...` 确认被 `SELECT` 过滤拦截。
2. 确定列数与类型：用 `ORDER BY n`、报错信息或已知查询结构推断 `SELECT` 的列数（本例为 `username, is_admin` 两列）。
3. 构造无 SELECT 的注入：`username=' UNION VALUES('admin',1)--`，`password` 任意；`--` 注释掉后续条件。
4. 提交登录，观察是否以 admin 身份进入或直接输出 flag；必要时调整注入行的列值/列数（如 `VALUES('admin',1,'x')`）。
5. 若 `VALUES` 也被拦截，改用其它等价语法或双写/注释/十六进制等绕过（见关联卡）。

## PoC

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=' UNION VALUES('admin',1)--&password=x
```

生成的 SQL（SQLite）：

```sql
SELECT username, is_admin FROM users WHERE username = ''
UNION VALUES('admin',1) -- ' AND password = 'x'
```

返回行包含 `('admin', 1)`，应用判断 `$is_admin` 为真后输出 flag。本例实测 flag：

```text
KosenCTF{d0_y0u_kn0w_that_the_w0rd_valu35_can_b3_aft3r_un10n}
```

## 变体与关联

- **多行/多列变体**：`UNION VALUES('admin',1),('guest',0)`；列数不匹配时按目标查询补齐（如三列 `VALUES('admin',1,'x')`）。
- **方言变体**：MySQL 8.0 `UNION VALUES ROW('admin',1)`；PostgreSQL `UNION VALUES ('admin',1)`；SQL Server 用 `UNION SELECT` 或 `VALUES` 派生表。
- **过滤变体**：若同时拦截 `UNION`/`VALUES`，可用双写、内联注释、大小写/编码、`UNION ALL`、子查询等方式；黑名单越全，越应考虑参数化。
- **关联**：[[web-generic-sqli-keyword-double-write-bypass]]（SELECT 被替换为空时双写还原）、[[web-generic-sqli-waf-newline-keyword-split-hex]]（换行拆分关键字/十六进制）、[[web-generic-sqli-semantic-waf-layerwise-bypass]]（语义型 WAF 分层绕过）。

## 检测与防御

- **修复**：使用参数化查询/预编译语句，彻底分离 SQL 结构与数据；禁止字符串拼接用户输入。
- **过滤**：不要依赖单一 `SELECT` 关键字黑名单；至少覆盖 `UNION`、`VALUES`、注释符、引号等，但黑名单只能提高成本，不能根治。
- **检测**：WAF/日志关注登录参数中的单引号、`UNION`、`VALUES`、`--` 注释符组合；对返回行数/管理员标志异常、登录成功但密码错误的请求告警。
- **加固**：数据库账号最小权限、关闭详细报错、对登录接口限速与风控；SQLite 场景避免把敏感逻辑放在同一查询的返回值上。
