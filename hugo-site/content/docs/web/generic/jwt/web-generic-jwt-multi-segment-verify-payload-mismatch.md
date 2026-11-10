---
id: web-generic-jwt-multi-segment-verify-payload-mismatch
title: JWT 自写校验的解析差异：验签用倒数第二段、返回用第二段，四段 token 伪造特权声明
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-multi-segment-verify-vs-return-payload-mismatch
tags:
- jwt
- parse-differential
- signature-bypass
- privilege-escalation
- custom-verify
- nodejs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:27:32+08:00'
  notes: 已对照原文 jwt.js 与图 07-10 核对：verifyToken 取 parts[1] 作 payload、parts[len-1] 作签名、对 parts[len-2] 验 HMAC，构造 header.evil.payload.signature 四段后验签仍过而返回 evil 声明；图 09/10 显示加入 is_d4rk_pr1nc3ss:1 后 /api/secret-note 返回 flag，链路打通。JWT_SECRET=uuid v4() 无法爆破，符合解析差异利用。与 unverified-signature、role-not-checked 等卡非同链。
url: /docs/web/generic/jwt/web-generic-jwt-multi-segment-verify-payload-mismatch/
draft: false
kb_aliases:
- 四段 JWT 绕过
- 验签与取值下标不一致
- parts[1] vs parts[length-2]
- JWT 多段解析越权
---

## 一句话结论

自写 `verifyToken` 用 `parts[1]` 作为解码返回的 payload、却用 `parts[parts.length-2]` 作为验签输入；构造 4 段 token `header.evilpayload.legitpayload.signature`（保持原合法签名不变），验签仍基于合法 payload 通过，而鉴权读到的却是插入的 `evilpayload`，从而无需密钥即可伪造任意声明越权。

## 原理

- 缺陷代码：`const parts = token.split("."); const payload = parts[1]; const signature = parts[parts.length-1]; const expectedSignature = HMAC(secret, parts[parts.length-2]); if (signature === expectedSignature) return JSON.parse(base64(payload));`
- 正常 3 段 token 时 `parts[1]` 与 `parts[len-2]` 指向同一段，缺陷不可见；一旦段数 > 3，验签对象（倒数第二段）与返回对象（第二段）指向不同数据。
- 为什么签名还能通过：把合法 token `header.payload.signature` 拆开，在 header 与 payload 之间插入一段，变成 `header.evil.payload.signature`。此时 `parts[len-2]` 仍是原来的合法 payload、`parts[len-1]` 仍是原签名，HMAC 校验通过；但 `parts[1]` 变成了攻击者控制的 evil payload。
- 为什么能越权：`/api/secret-note` 判断 `req.user.is_d4rk_pr1nc3ss`，该字段来自 `verifyToken` 返回的 payload；在 evilpayload 里加 `"is_d4rk_pr1nc3ss":1` 即被当成特权用户。密钥是 `uuid v4()` 随机生成、无法爆破，但解析差异让「不知道密钥也能改声明」。
- 完整链：登录拿一个合法 token → base64 解出 payload → 加特权字段重新编码 → 插回原 token 第 2 段 → 带该 Cookie 访问特权接口拿到目标数据。

## 触发条件

- 应用自行按 `.` 分段解析 JWT，且验签与解码取不同下标；
- 未校验 `parts.length === 3`、未校验 header 的 `alg`；
- 鉴权/授权依赖 token 内可自由声明的字段（如角色标志）；
- 攻击者能获得任意一个通过该校验的合法 token（注册/登录即可）。

## 利用步骤

1. 注册并登录，拿到合法 token `header.payload.signature`。
2. base64 解出 payload，加入特权声明（如 `is_d4rk_pr1nc3ss: 1`），重新编码。
3. 拼成 4 段：`header.<evil_payload>.<原payload>.<原signature>`。
4. 以该值作为 token Cookie 请求特权接口，读取返回数据。

## PoC

```python
import base64, json

def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

token = "<合法 token>"                       # h.p.s
h, p, s = token.split(".")
claims = json.loads(b64d(p))
claims["is_d4rk_pr1nc3ss"] = 1
evil = b64e(json.dumps(claims, separators=(",", ":")).encode())
forged = ".".join([h, evil, p, s])          # header.evil.legit.signature
print(forged)                                # Cookie: token=<forged>
```

## 变体与关联

- 变体：alg:none、jwk/jku 头注入、kid 路径穿越、签名用无密钥摘要（MD5/SHA1）可复算；段数/分隔符解析差异本质是「校验器与消费器对同一输入的解释不一致」，与 HTTP 请求走私、参数污染同源。
- 关联：JWT 硬编码/弱密钥伪造、客户端可复算签名越权；本例前置是 nginx alias 读到的后端源码与竞态登录拿到的合法 token。

## 检测与防御

- 防御：用成熟 JWT 库并固定算法白名单；自写解析时强制 `parts.length === 3`，且验签与解码使用同一段、同一 `alg`；对 header 做校验；特权判定不依赖客户端可声明字段，改查服务端会话/数据库角色。
- 密钥：密钥应稳定且保密，但本例说明「密钥再随机也挡不住解析缺陷」，修复重点是解析一致性。
- 检测：token 段数 != 3、Cookie 中出现多余 `.`；同一签名对应多个不同 payload；日志里出现带特权声明却非管理员签发的 token。
