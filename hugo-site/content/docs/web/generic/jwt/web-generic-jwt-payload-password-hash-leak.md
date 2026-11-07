---
id: web-generic-jwt-payload-password-hash-leak
title: JWT Payload 明文携带密码哈希：解码后离线破解并直接登录
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-payload-password-hash-leak
tags:
- jwt
- sensitive-data
- password-hash
- credential-leak
- offline-crack
- login
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V71
  verified_at: '2026-11-05T16:28:12+08:00'
  notes: 已对照原文与37张图片核对：payload含username=joe、password=2ac9cb7dc02b3c0083eb70898e549b63、level=admin；cmd5查询得Password1；Leaky Login显示Login success, welcome Joe。未实测破解/登录。靶场类无产品版本。
url: /docs/web/generic/jwt/web-generic-jwt-payload-password-hash-leak/
draft: false
kb_aliases:
- Leaky JWT
- JWT 泄露密码
- JWT payload password
- JWT 敏感信息
- token 解码拿口令
- JWT 明文密码哈希
---

## 一句话结论

JWT 的 Header/Payload 只是 base64url 编码而非加密，任何拿到 token 的人都能解码；若 payload 里直接放了用户的 `password`（文章为 MD5 `2ac9cb7dc02b3c0083eb70898e549b63`），解码后交给 cmd5/hashcat 离线破解得到 `Password1`，再用 `username` + 明文直接登录目标账号。

## 原理

- JWT 的结构是 `base64url(header).base64url(payload).signature`；签名只保证完整性/来源，不提供机密性。Payload 对任何持有 token 的人（客户端、代理、日志、浏览器扩展、XSS）都是可读的。
- 文章目标把 `username`、`password`、`level` 直接放进 payload；其中 `password` 是 32 位 hex（MD5），在 cmd5 查询得到明文 `Password1`。
- 拿到明文后回到登录页用 `joe:Password1` 登录成功；这说明 JWT 中泄露的是可直接复用的账号凭据，而不仅是随机 token。
- 即使密码是强哈希（bcrypt/argon2），payload 泄露仍提供了离线爆破目标；若是弱哈希/无盐哈希，破解成本极低。除密码外，payload 还可能包含身份证、手机号、角色、内部 ID 等 PII/权限信息，可用于越权或社工。
- 因此测试任何 JWT 时应先做“解码审计”：看 payload 是否包含口令、哈希、密钥、PII、角色/租户等；不要只关注签名绕过。

## 触发条件

- 目标使用 JWT 作为会话/认证 token，且攻击者能获取一个有效 token（登录自己的账号、抓包、日志、前端存储、XSS 等）。
- Payload 中包含 password/passwordHash/口令相关字段或可离线破解的凭据材料。
- 泄露的账号仍有效，登录入口未额外要求 MFA/设备绑定。
- 哈希可被字典/规则/在线服务破解，或 payload 直接是明文口令。

## 利用步骤

1. 登录自己的账号，抓取 Cookie/Authorization 中的 JWT。
2. 用 jwt.io、Burp 的 JSON Web Token 插件或 base64url 解码 Header 与 Payload。
3. 检查 payload 字段：`username`、`password`、`passwordHash`、`email`、`phone`、`idCard`、`role`、`tenant` 等。
4. 若 `password` 为 32 位 hex，先按 MD5 处理，用 cmd5/hashcat/rockyou 破解；记录哈希类型与明文。
5. 用 payload 中的 `username` + 破解出的明文尝试登录；若成功，确认账号接管。
6. 若目标是管理员/高权限账号，评估后台功能与数据影响；报告中给出脱敏 token 片段与字段。

## PoC

```text
# JWT Payload 解码结果（文章）
{
  "level": "admin",
  "password": "2ac9cb7dc02b3c0083eb70898e549b63",
  "username": "joe"
}
```

```bash
# MD5 离线破解（示例）
echo '2ac9cb7dc02b3c0083eb70898e549b63' > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
# 或在线 cmd5 查询 → Password1

# 用泄露凭据登录
curl -i -X POST 'https://<target>/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"joe","password":"Password1"}'
```

## 变体与关联

- 变体：payload 直接放明文口令；放无盐 MD5/SHA1；放 bcrypt/argon2 哈希（需离线爆破）；放密码提示/重置 token。
- 变体：payload 放身份证、手机号、邮箱、内部角色/租户 ID，可用于越权、账号枚举与社工，即使没有密码字段也有价值。
- 变体：token 存在 localStorage/URL/日志中，被 XSS、Referer、代理历史或第三方 SDK 收集。
- 边界：payload 只放随机 opaque ID、哈希为强慢哈希且口令高熵、账号启用 MFA 时，单靠 payload 泄露不一定能接管。
- 关联：[[web-generic-jwt-unverified-signature-payload-tamper]]（payload 可改）、[[web-generic-jwt-password-as-hmac-key-bruteforce]]（密码作为 HMAC 密钥的另一类泄露）、[[web-generic-jwt-alg-none-bypass]]（签名绕过）、[[web-generic-jwt-payload-pii-role-exposure]]（若 payload 泄露 PII/角色的同类审计思路）。

## 检测与防御

- 检测（测试方）：对每个 JWT 先 base64url 解码，列出所有字段；对 password/hash 字段做类型识别与离线破解；对 PII/角色字段评估越权。
- 检测（防御方）：审计 JWT 签发代码，确保 payload 只放最小必要声明（sub、iat、exp、jti、角色 ID），绝不放口令/哈希/身份证/手机号；检查日志与前端存储是否泄露 token。
- 修复：把敏感信息从 payload 移除，需要时由服务端按 sub 查库；使用短期 access token + refresh token；对高权限操作增加服务端二次校验/MFA。
- 加固：token 加密（JWE）只在确需机密性时使用；启用 token 撤销/版本号；监控异常登录与 token 重放。
