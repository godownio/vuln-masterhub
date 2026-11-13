---
id: web-generic-sqli-mongodb-expr-function-json-injection-blind
title: MongoDB $expr/$function 盲注：登录接口字符串插值 JSON.parse 注入查询操作符，绕过仅查 $where 的黑名单与 class-validator 逐字符爆管理员口令
type: scenario
domain: web
path: web/generic/sqli
technique: mongodb-expr-function-json-parse-injection-blind
aliases:
- MongoDB $expr 注入
- MongoDB $function 注入
- NoSQL 盲注
- JSON.parse 字符串插值注入
- $where 黑名单绕过
- class-validator 绕过
tags:
- nodejs
- mongodb
- nosql
- injection
- expr
- function
- blind
- validation-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V551
  verified_at: '2026-11-11T22:46:54+08:00'
  notes: 已通读 content.md 并核对全部 3 张截图：图2 显示 getUser 中 JSON.parse(`{"username":"${username}", "password":"${password}"}`)、validation.hasOwnProperty('$where') 抛 401、findOne(validation)、!user→404、user.password!==validation.password→403，与卡内触发条件/oracle 一致；图3 显示 admin service 的 @Get('flag')，与'成为 admin 取 flag'目标一致；图1 为前文 DiceCTF 的 flag（对应被合并的 isAdmin 场景，非本卡）。原文 validate 段（plainToClass+validate，未知字段不拒绝）与卡内 class-validator 绕过描述一致；官方 PoC 使用 $expr.$function body/args/lang=js 对 $password 逐字符比较，与卡一致。核对中修正 PoC 错误：原卡改写脚本在顶层保留 password:'x'，它会作为额外查询条件使 admin 永不命中、403 oracle 失效；已按原文构造改回（username 注入嵌套 __proto__ 对象、由 password 字段注入 $expr 并重开 username，顶层无 password），并在原理/步骤补充该注意点。dedup 仅自身 exact，候选为 $where JS 注入、Java JSON 拼接 $regex、$regex 前缀 oracle、Strapi $gt 等其他操作符/入口，无同链重复。原文未标注软件版本，未设 affected_versions。未验证点：未对真实 MongoDB 实例复现（$function 需 MongoDB 4.4+ 且未禁用服务端 JS），置信度维持 medium。文章 skipped 项核对：isAdmin[user] 继承键绕过与既有 verified 卡 web-generic-auth-nodejs-prototype-chain-login-bypass 同根因已合并；viewtime XSS 题描述不完整未立卡，均合理。
---

## 一句话结论

登录接口把 `username`/`password` 直接插值进 JSON 字符串再 `JSON.parse` 时，攻击者可用 `"` 闭合字符串并注入任意 JSON 字段（如 `$expr`）；服务端只用 `hasOwnProperty("$where")` 拦 `$where`、class-validator 默认不拒绝多余字段，于是 `$expr` 里的 `$function` JS 函数会在 MongoDB 服务端对真实 `password` 字段执行，攻击者按字符比较并用 403/404 状态码差异作为 oracle，即可逐位盲注出管理员口令。

## 原理

- **JSON 字符串插值注入**：代码 `JSON.parse(\`{"username":"${username}", "password":"${password}"}\`)` 把用户输入直接拼进 JSON 文本。用户名或密码里带 `"` 即可提前闭合字段，注入新的键值，例如 `admin", "$expr": {...}, "x":"`，最终解析出的对象包含攻击者指定的查询操作符。
- **黑名单只挡 `$where`**：校验逻辑 `if (validation.hasOwnProperty("$where")) throw` 只检查这一个键；`$expr`、`$function` 等其他服务端可执行操作符不受限。`hasOwnProperty` 也只查自有属性，攻击者注入的是自有键，因此不触发。
- **class-validator 不剥离未知字段**：`plainToClass(LoginDto, data)` 会把所有自有属性（含 `$expr`）复制到 DTO 实例，`validate` 只校验装饰器声明的字段（username/password 为字符串即可通过），未知字段默认被忽略而非拒绝，因此恶意操作符随对象一起进入 `findOne(validation)`。
- **`$expr` + `$function` 服务端执行**：MongoDB 的 `$expr` 允许在查询中使用聚合表达式；`$function`（MongoDB 4.4+）用 `body` 指定 JS 函数、`args` 引用文档字段（如 `["$password"]`）、`lang: "js"`，服务端会对每个候选文档执行该函数。函数返回布尔值即作为查询条件。
- **盲注 oracle**：代码在查询命中用户后比较 `user.password != validation.password`，不匹配返回 403、无命中返回 404（或类似状态差异）。把 `$function` 写成 `function(pw){ return pw[i] == 'guess' }`，若 403 说明该位正确，逐位循环即可还原管理员密码；`username` 固定为 admin，使命中与否只取决于字符比较。注意顶层不能保留 `password` 键（原文 PoC 把 password 值藏进注入的 `__proto__` 对象中），否则它会作为额外查询条件把 admin 过滤掉、oracle 失效。
- **为什么可行**：字符串拼接 JSON 破坏了数据/代码边界；黑名单式防护天然漏操作符；服务端 JS 让攻击者能在数据库进程内做任意布尔运算，配合应用层状态码差异形成高带宽盲注信道。

## 触发条件

- 登录/查询接口用字符串插值构造 JSON 后 `JSON.parse`，且把解析结果（或其副本）直接传给 Mongoose/驱动查询。
- MongoDB 4.4+ 且未禁用服务端 JavaScript（`$function`/`$where` 可用）；应用只用 `$where` 黑名单或不校验 `$` 开头键。
- 存在可观测的状态码/响应差异（命中用户后密码不匹配 vs 完全无命中），能作为逐字符 oracle。
- DTO 校验只约束 username/password 类型，未开启 `forbidNonWhitelisted`/`whitelist`。

## 利用步骤

1. 确认登录接口接受 JSON 或表单用户名/密码，且错误响应能区分“用户不存在”（404）与“密码错误”（403）。
2. 构造 JSON 注入：用 `"` 闭合 username 字段，注入 `$expr: {"$function": {...}}`，再用重复的 `username` 键让 JSON 合法且最终 username 为 admin；password 键必须塞进注入的嵌套对象（如 `__proto__` 对象）中，使顶层不出现 password，避免它变成额外查询条件。
3. 在 `$function.body` 中写 `function(pw){ return pw[0] == 'a' }`，`args: ["$password"]`，`lang:"js"`。
4. 发送请求并观察状态码：403 表示该字符正确（查询命中 admin），404 表示不匹配；对每一位枚举字符集，拼出完整密码。
5. 用还原出的管理员口令正常登录，进入后台获取 flag/敏感功能。

## PoC

注入后的 JSON 形态（用户名/密码经 `"` 闭合注入）：

```json
{
  "username": "admin",
  "__proto__": {"a": "haha", "password": "testpw"},
  "$expr": {
    "$function": {
      "body": "function(pw) { return pw[0] == 'a' }",
      "args": ["$password"],
      "lang": "js"
    }
  },
  "username": "admin"
}
```

逐位盲注脚本（按 403 命中判定）：

```python
import requests

URL = "http://target/user/login"
admin_pw = ""
for pos in range(32):
    for ch in "0123456789abcdef":
        username = 'admin", "__proto__": {"a": "haha'
        password = ('testpw"}, "$expr": {"$function": {"body": '
                    '"function(pw){ return pw[%d] == \'%s\' }", '
                    '"args": ["$password"], "lang": "js"}}, "username": "admin'
                    ) % (pos, ch)
        r = requests.post(URL, data={"username": username, "password": password})
        if r.status_code == 403:      # 查询命中 admin 但密码不匹配
            admin_pw += ch
            print(admin_pw)
            break
```

（PoC 按原文构造：username 处注入嵌套的 `__proto__` 对象，password 处注入 `$expr` 并重开 `username`；`JSON.parse` 会把 `__proto__` 当作普通自有键，最终顶层不含 password 查询条件。）

## 变体与关联

- 变体：只用 `$where` 黑名单时可直接尝试 `$where` JS 注入；被拦截后改用 `$expr`/`$function`，或 `$jsonSchema`、`$regex` 等操作符做其他形式的注入/盲注。
- 变体：无 `$function` 时可用 `$regex` 前缀匹配、`$gt`/`$ne` 布尔条件等构造 oracle；已有专门卡片覆盖。
- 变体：若应用对 username 做了 `JSON.stringify` 但仍把整个对象传给 `findOne`，可尝试在 username 值里注入 `$ne`/`$gt` 等操作符（对象注入）。
- 关联：[[web-generic-sqli-mongodb-where-javascript-injection]]（`$where` JS 注入的基型）、[[web-nodejs-mongodb-json-operator-injection-prefix-oracle]]（`$regex` 前缀盲注）、[[web-generic-sqli-mongodb-java-json-concat-regex-blind]]（同样“字符串拼 JSON”的另一语言实现）、[[web-nodejs-prototype-pollution-merge-json-parse]]（JSON.parse 对 `__proto__` 键的处理差异）。
- 边界：MongoDB 版本低于 4.4 或禁用服务端 JS 时 `$function` 不可用；DTO 开启 `whitelist: true`/`forbidNonWhitelisted: true` 会剥离/拒绝 `$expr`；错误状态码统一时需改用时间/内容差异或其他 oracle。

## 检测与防御

- 修复：不要用字符串插值构造 JSON；先分别校验 username/password 为字符串，再用 `JSON.stringify`/对象字面量构造查询，绝不把用户输入拼进 JSON 文本。
- 查询侧：对查询对象做键白名单（只允许 `username`、`password` 等业务字段），递归拒绝 `$` 开头的键；DTO 开启 `whitelist` 与 `forbidNonWhitelisted`。
- MongoDB：禁用服务端 JavaScript（`security.javascriptEnabled=false`）或至少限制 `$function`/`$where`；数据库账号最小权限。
- 检测：登录请求中出现 `$expr`、`$function`、`$where`、`$regex` 等键或 JSON 结构异常（重复 username 键、引号闭合）；同一账号短时间内大量 403/404 交替请求（盲注特征）。
