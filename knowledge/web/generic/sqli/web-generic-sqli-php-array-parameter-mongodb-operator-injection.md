---
id: web-generic-sqli-php-array-parameter-mongodb-operator-injection
title: PHP 数组参数注入 MongoDB 操作符：username[$ne]=1 登录绕过与 $gt 盲注枚举
type: scenario
domain: web
path: web/generic/sqli
technique: php-array-parameter-mongodb-operator-injection
aliases:
- PHP 数组注入
- username[$ne]=1
- MongoDB 操作符注入
- $ne 登录绕过
- $gt 盲注
- NoSQL 数组参数
tags:
- php
- mongodb
- nosql
- injection
- operator-injection
- auth-bypass
- blind
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:25:55+08:00'
  notes: 已对照原文与31张图核对：图02-07 PHP登录demo 正常/错误/[]/[]绕过与盲注对比（weiyh失败、weiyi成功）与原文逐条一致；图08 customer:{"$ne":"1"} 返回集合全部数据。卡内 PHP 数组语法→操作符文档、find(array(...)) 代码、 盲注边界、/ 变体均与原文一致；PoC 中 POST /api/query 为示意端点（原文图08 URL打码，正文只给 customer[]=1），其余 payload 为原文原样。与 Java JSON 拼接/ 盲注卡、Node 嵌套对象卡为不同入口/层，dedup top候选 new，非重复。原文未标组件/数据库版本，affected_versions 留空正确。未验证点：未在本机 Mongo 环境复跑数组注入；/api/query 端点名为示意。frontmatter 无 sources/source_url。
---

## 一句话结论

PHP 会把查询串/表单里的 `username[$ne]=1` 解析成数组；当后台把这个数组原样传给 MongoDB 的 `find()` 时，驱动会把它序列化成查询操作符 `{"$ne":"1"}`，于是 `username[$ne]=1&password[$ne]=1` 变成“用户名不等于 1 且密码不等于 1”，直接命中任意用户完成登录绕过；把 `$ne` 换成 `$gt`/`$lt`/`$regex` 还能按响应差异做盲注枚举，甚至用 `customer[$ne]=1` 拖出整集合数据。

## 原理

- **PHP 数组参数解析**：PHP 会把 `a[$ne]=1` 形式的参数解析为 `array('$ne' => '1')`，`$_GET/$_POST/$_REQUEST` 取到的就是数组而不是字符串；这是 PHP 的语言特性，不需要任何特殊字符绕过。
- **MongoDB 查询语义**：MongoDB 的字段值可以是操作符文档，`{"username": {"$ne": "1"}}` 表示 username 不等于 `"1"`。后端代码若直接 `find(array('username' => $_REQUEST['username'], 'password' => $_REQUEST['password']))`，就会把攻击者的数组当作操作符。
- **登录绕过**：`username[$ne]=1&password[$ne]=1` 生成 `{"username":{"$ne":"1"},"password":{"$ne":"1"}}`，示例系统中即返回 `login succeed` 并输出数据库中的用户名/密码；语义等价于 `username <> '1' AND password <> '1'`。
- **盲注枚举**：把 username 换成 `{"$gt":"weiyh"}` 时登录失败、`{"$gt":"weiyi"}`（按字典序）时成功，可据此判断目标用户名的边界；配合 `$lt`/`$gte`/`$regex` 可逐字符还原用户名或密码。
- **数据拖取**：同样的数组参数出现在其他查询接口（如 `customer[$ne]=1`）时，查询条件恒真，接口会返回该集合的全部数据。
- **语言无关性**：Python/Node 等后端只要允许把请求体解析成字典/对象并原样传入 NoSQL 查询，同样成立；PHP 的特殊之处是 query-string 语法就能构造嵌套数组。

## 触发条件

- 后端为 MongoDB（或其他支持操作符文档的 NoSQL），且把请求参数直接作为查询值传入 `find`/`findOne` 等。
- 未对参数做标量类型校验（`is_string`、强制 `(string)`、类型声明），允许数组/对象类型。
- 登录或查询接口的响应可区分命中/未命中（成功页、错误文案、耗时、返回数据量）。
- 攻击者可访问该接口；无需已登录。

## 利用步骤

1. 正常提交登录/查询请求，记录成功与失败的响应差异。
2. 发送 `username[$ne]=1&password[$ne]=1`；若返回登录成功或数据，说明数组被当作操作符。
3. 用 `$gt`/`$lt` 做边界测试（如 `username[$gt]=weiyi`），按响应差异判断用户名/密码的字典序范围。
4. 用 `$regex` 做前缀盲注逐字符还原凭据（`username[$regex]=^a.*`），或直接 `$ne` 在查询接口上拖取集合数据。
5. 结合 `$in` 快速尝试多个候选值（如 admin/root/administrator）。

## PoC

登录绕过：

```http
GET /nosql/login/login.php?username[$ne]=1&password[$ne]=1&login-submit=login HTTP/1.1
Host: target
```

解码后的查询：

```json
{"username":{"$ne":"1"},"password":{"$ne":"1"}}
```

盲注判断（示例：`weiyh` 失败、`weiyi` 成功，说明真实用户名在两者之间）：

```http
GET /nosql/login/login.php?username[$gt]=weiyh&password[$ne]=1&login-submit=login
GET /nosql/login/login.php?username[$gt]=weiyi&password[$ne]=1&login-submit=login
```

拖取集合：

```http
POST /api/query HTTP/1.1
Content-Type: application/x-www-form-urlencoded

customer[$ne]=1
```

## 变体与关联

- **操作符变体**：`$ne`、`$gt/$lt/$gte/$lte`、`$in`、`$exists`、`$regex`；`$where` 可执行 JS（见 [[web-generic-sqli-mongodb-where-javascript-injection]]）。
- **入口变体**：PHP query-string 数组；Node/Python 的 JSON 嵌套对象直接进入查询（见 [[web-nodejs-mongodb-json-operator-injection-prefix-oracle]]）；Java 字符串拼 JSON 后用 `$or/$regex`（见 [[web-generic-sqli-mongodb-java-json-concat-regex-blind]]）。
- **变体**：Strapi 密码重置接口把 code 当查询值，传 `{"$gt":0}` 命中任意 token（见 [[web-nodejs-strapi-password-reset-nosql-injection]]）。
- 边界：后端把参数强制转字符串、使用强类型查询构造器、或拒绝 `$` 开头键时，操作符注入不成立。

## 检测与防御

- **代码层**：对进入 NoSQL 查询的参数做严格标量校验（`is_string`/类型声明/白名单），拒绝数组与对象；统一使用查询构造器/ODM，不把原始请求数组传入查询。
- **接口层**：登录/查询接口统一错误消息，避免用响应差异做 oracle；限制请求体嵌套深度与 `$` 开头键。
- **检测信号**：请求参数出现 `[$ne]`、`[$gt]`、`[$regex]` 等方括号操作符语法；同一 IP 高频变更比较符；查询返回数据量异常增大。
- **兜底**：数据库账号最小权限、按集合隔离；WAF 只能拦已知语法，不能替代类型校验。
