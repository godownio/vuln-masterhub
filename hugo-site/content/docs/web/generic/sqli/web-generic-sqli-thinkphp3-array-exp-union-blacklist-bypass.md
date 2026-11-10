---
id: web-generic-sqli-thinkphp3-array-exp-union-blacklist-bypass
title: ThinkPHP 3 数组参数 exp 逃逸 where 条件：union select 绕过关键字黑名单读表
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp3-array-exp-union-select-waf-blacklist-bypass
tags:
- php
- thinkphp
- thinkphp3
- sql-injection
- exp-operator
- array-parameter
- waf-bypass
- union-select
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:51:03+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。h_n 方法入口、waf() 返回 false 才走查询、黑名单正则逐条 preg_match /$value/i、name[0]=exp&name[1]=... 的 union select 回显 payload 均与正文一致；union 两侧列数需对齐 field('username,age') 两列为推断，本机未复跑。
url: /docs/web/generic/sqli/web-generic-sqli-thinkphp3-array-exp-union-blacklist-bypass/
draft: false
kb_aliases:
- name[0]=exp
- ThinkPHP 数组参数注入
- exp 绕过 WAF
- union select 绕关键字黑名单
- where(array()) 注入
- index.php/home/index 直接调方法
---

## 一句话结论

ThinkPHP 3 的 `where(array('username'=>$name))` 在 `$name` 以数组形式到达时，会把 `['exp', <值>]` 识别为「原始表达式」直接拼进 SQL；由于 PHP 会自动把 `name[0]=exp&name[1]=...` 解析成数组，而 WAF/黑名单通常只对「值是否为字符串」做 `preg_match`，所以用 `name[0]=exp&name[1]==\'x\' union select 1,flag from flag` 就能在绕过 `and|or|union 关键字`之外的黑名单后，把任意 SQL 片段注入 `WHERE`，一次查出目标表。

## 原理

- **数组参数是 ThinkPHP 的合法输入形态**：`I('name')` 默认允许数组，`name[0]=exp&name[1]=...` 会被解析成 `['exp', '...']` 并原样传给 `where()`。
- **`exp` 是「原样 SQL」标记**：TP3 的 `where()` 看到 `['exp', $v]` 时不再做参数绑定/转义，而是把 `$v` 直接拼进条件。因此 `$v` 的内容是纯 SQL 语法，等号、引号、`union`、子查询都可写。
- **黑名单为什么被绕**：本题 WAF 用 `preg_match("/$value/i", $vv)` 逐字符检查每个键值，规则集里有 `insert|update|delete|and|or|/*|*|../|./|into|load_file|outfile|dumpfile|sub|hex|...` 等关键字。payload 用 `union select` 与 `=` 拼接、不含 `and`/`or`/`into`/`/*`，因此逐条规则都不命中——黑名单只枚举了「常见注入关键字子串」，而不是检查「参数是否为数组 / 是否命中 exp 分支」。
- **为什么需要 union**：`exp` 片段落在 `WHERE username = <exp值>` 位置，原查询只 `field('username,age')`；用 `union select 1,flag from flag` 把想要的列直接接到结果集尾部，页面 `var_export($ret, true)` 回显整行，无需报错注入或盲注。
- **入口**：TP3 的 URL 路由形如 `index.php/home/index/<method>`，会调用 `IndexController` 里的 `<method>`；控制器里为测试/调试留下的方法（本例 `h_n`）同样会把 `I('name')` 传进 `where()`，形成不需要登录的注入点。
- **前提**：`waf()` 返回 false 才会走查询分支，即 payload 必须不在黑名单内；`name` 必须为数组（否则走字符串分支，被 `addslashes` 之类的处理拦下）。

## 触发条件

- 目标为 ThinkPHP 3.x 应用，控制器把用户输入的**数组**直接传入 `where()`/`field()` 链，且未对 `exp` 做拦截。
- 存在可达的控制器方法（正常业务方法或遗留调试方法），其参数经 `I()` 获取并进入查询。
- 前置 WAF/黑名单只做字符串关键字匹配，未拦截数组参数形态、未禁止 `exp`、未做参数绑定。
- 查询结果会被回显（`var_export`/`dump`/`print_r`/JSON 输出），或至少可布尔/时间判断。

## 利用步骤

1. 找到进入 `where()` 的参数名与控制器方法：地址形如 `index.php/home/index/<method>`，抓正常请求观察参数。
2. 确认参数支持数组：先发 `name[]=a`，看是否报数组相关错误或查询结果异常（说明数组被接受）。
3. 构造 `exp` 逃逸：让 `name[1]` 以 `=` 开头闭合原条件，再用 `union select` 追加目标列。
4. 逐步调整列数与前缀，使 union 两侧列数一致；用 `select 1,<目标列>` 对齐被 `field('username,age')` 选出的两列。
5. 读取目标表/列（如 `flag` 表的 `flag` 列），从页面回显中取结果。
6. 若被黑名单拦截，改用不含 `and`/`or`/`into` 的等价语法（`union select`、`where` 内联、`||` 视数据库而定），或换用 `=`/`like` 规避关键字。

## PoC

```http
GET /index.php/home/index/h_n?name[0]=exp&name[1]=%3d%27test123%27%20union%20select%201,flag%20from%20flag HTTP/1.1
Host: target
```

```text
解码后的 name 数组：
name[0] = exp
name[1] = ='test123' union select 1,flag from flag

拼出的条件近似：WHERE username = ='test123' union select 1,flag from flag
页面 var_export 回显结果集中出现 flag 列的值。
```

要点：整条 payload 不含黑名单里的 `and`、`or`、`into`、`/*`、`*`、`load_file`、`outfile` 等子串，因此逐条 `preg_match` 都不命中。

## 变体与关联

- 变体（三维数组）：`name[0]=<字段>&name[1]=exp&name[2]=<payload>`，适配把三元组当 `[field, op, value]` 解析的写法。
- 变体（报错/盲注）：union 列数不匹配或结果不回显时，在 `exp` 片段里用 `updatexml`/`extractvalue` 报错注入，或用 `sleep()` 时间盲注（注意 `and`/`or` 可能被黑名单拦截，可改用 `||`、`&&` 或 `where` 子句内联）。
- 变体（其他框架）：任何「数组形态用户输入被当作查询操作符/原始表达式」的 ORM 都有同类问题（Laravel 的 `whereRaw` 拼接、ThinkPHP 5 的 `exp`）。
- 关联：[[web-generic-sqli-thinkphp-where-exp-array-injection]]（同为 `exp` 数组 → 原始 SQL 的原语，那张卡是 ThinkPHP 5.1 + `wp_where()` + updatexml 报错注入的未授权接口；本卡是 ThinkPHP 3 + `where(array())` + `union select` 回显 + 关键字黑名单规避，注入点与取数方式不同）。
- 边界：若应用对参数做了 `is_array` 拒绝、`intval` 强转，或升级到已修复 `exp` 处理的版本，该链失效；若 `field()` 选出的列数与 union 不一致会直接报错。

## 检测与防御

- 代码修复：禁止用户输入进入 `exp`/`whereRaw` 一类原始表达式 API；查询条件只用参数绑定（`where('username = ?', [$name])`），并对数组参数显式拒绝。
- 输入层：统一把「参数是数组」视为异常（除明确设计为多选的字段），对查询参数做类型白名单。
- WAF 增强：拦截 `[0]=exp`、`[1]=exp`、`exp&` 等数组形态与 `union select` 组合；不要只做关键字黑名单，需解析参数结构。
- 运行时缓解：生产关闭 `var_export`/`dump` 类调试输出；数据库账号最小权限，禁用 `FILE`；错误页不回显 SQL。
- 检测：访问日志中出现 `name[0]=`、`%5B0%5D=exp`、`union%20select`；同一接口出现大量 `[0]`/`[1]`/`[2]` 数组参数；遗留调试方法（如 `h_n`、`test`）被外部访问。
