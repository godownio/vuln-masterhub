---
id: web-generic-token-client-supplied-public-key-forgery
title: 自定义令牌把验签公钥放进第 4 段：攻击者自带密钥对自签自验，冒充任意用户（含 admin）
type: scenario
domain: web
path: web/generic/jwt
technique: token-client-supplied-verification-key-forgery
tags:
- token
- jwt
- signature-forgery
- rsa
- pkcs1
- auth-bypass
- client-supplied-key
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:47:26+08:00'
  notes: 已对照原文核对：源码中 data_decode 在 len(all_data)==4 时 key=base64.b64decode(all_data[3])、verify_signature 的 RS 分支 RSA.import_key(key)+pkcs1_15.verify、data_encode 以 private_key 签名/public_key 作第 4 段，均与原文一致；4 段格式 base64(data).base64(sig).base64(alg).base64(pubkey) 与原文 encoded_data 拼接一致；GT 回显见 img/06。未验证点：原文未给出伪造令牌端到端成功的独立截图（回显中的 token 属原文作者生成），PoC 中 json.dumps 默认分隔符与原文一致但未实测复现。
url: /docs/web/generic/jwt/web-generic-token-client-supplied-public-key-forgery/
draft: false
kb_aliases:
- 令牌内嵌公钥伪造
- 自定义 token 公钥片段
- 自带密钥自签自验
- RS 令牌伪造 admin
- 验签公钥来自请求数据
---

## 一句话结论

当服务端把「验签公钥」和签名一起放在令牌里（原文格式为 `base64(data).base64(sig).base64(alg).base64(pubkey)`），解码函数在段数为 4 时用第 4 段覆盖默认密钥 `secret = uuid4()`，那么攻击者只要自己生成一对 RSA 密钥，用私钥对 `{"username":"admin",...}` 签 PKCS#1 v1.5 + SHA256，再把公钥塞进第 4 段，服务端就会用攻击者提供的公钥验证攻击者自己的签名并返回 `True`，从而冒充 `admin` 进入超级用户分支。

## 原理

- **签发与校验都允许"外部带入密钥"**：`data_encode` 里每次调用 `generate_keys()` 生成临时密钥对，把私钥用于签名、公钥作为第 4 段输出；`data_decode` 里先用 `key = secret`（进程启动时的随机 uuid 字符串）作为"默认密钥"，但只要 `len(all_data) == 4` 就执行 `key = base64.b64decode(all_data[3])` —— 即**验签公钥完全由令牌内容决定**。
- **验签语义被替换**：`verify_signature(key, data, signature, 'RS')` 内 `rsakey = RSA.import_key(key)` 后 `pkcs1_15.new(rsakey).verify(SHA256(json.dumps(data)), signature)`。由于 `key` 是攻击者公钥，攻击者用自己的私钥签出的签名必然通过；而原本"只有服务端签发者能生成合法令牌"的信任假设彻底失效。
- **篡改 payload 不受阻**：`data` 段是明文的 base64 JSON，任何人都能改成 `{"username":"admin"}`；签名段只需按新 payload 重算（用自己的私钥），公钥段换成自己的公钥。三个自由度全部由攻击者控制，故等价于"完全无验签"。
- **为什么还要 4 段**：段数为 3（HS 分支或省略公钥）时 `key = secret`（随机 uuid），攻击者无法预测，所以伪造必须凑齐 4 段并让 `alg` 解出来等于 `'RS'`（`verify_signature` 只在 `alg=='RS'` 时走 RSA 分支，`'HS'` 分支会用 `secret.decode()` 拼哈希，同样不可控）。
- **影响面上限**：一旦验签可自证，业务里所有"依赖令牌身份"的分支都失效；原文的 `/api/test` 正是先判 `username in super_user` 才继续执行 `exec(code)`，于是伪造 admin 令牌 = 拿到代码执行入口。

## 触发条件

- 目标使用自研/非标准令牌格式，且**验签密钥可以从令牌自身解析出来**（如把公钥/证书/JWKS 片段附带在令牌里）；
- 验签实现没有把"密钥来源"限制为服务端可信配置，也没有对令牌内容做指纹/白名单比对；
- 令牌 payload 是可直接 base64 解出的明文 JSON（或任何可离线重编码的序列化格式）；
- 攻击者能提交构造好的令牌到受影响的接口（原文 `request.params['token']`）。

## 利用步骤

1. 抓一个合法令牌，按分隔符切开，确认段数与各段含义（原文 4 段：data / signature / alg / public_key），解出 alg 段确认是 `RS`。
2. 本地生成 RSA 2048 密钥对，构造 payload `{"username":"admin","password":"x"}`，用私钥做 SHA256 + PKCS#1 v1.5 签名。
3. 按同样编码拼出 4 段令牌：`b64(payload).b64(sig).b64("RS").b64(public_key_pem)`；注意 URL 中 `+`/`=` 需正确编码（服务端会做 `.replace(' ', '+')`）。
4. 把令牌随请求提交（原文 `GET /api/test?code=...&token=...`），观察是否走到超级用户分支（响应差异、日志里的 `Welcome super_user!`）。
5. 进入特权分支后执行预期动作（原文此处为 `exec(code)`，即代码执行）。

## PoC

```python
import base64, json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

priv, pub = (lambda k: (k.export_key(), k.publickey().export_key()))(RSA.generate(2048))
data = {"username": "admin", "password": "x"}
data_str = json.dumps(data)                      # 与验签端保持同样的序列化格式
sig = pkcs1_15.new(RSA.import_key(priv)).sign(SHA256.new(data_str.encode()))
token = ".".join(base64.b64encode(x).decode() for x in
                 [data_str.encode(), sig, b"RS", pub])
print(token)
```

```http
GET /api/test?code=<payload>&token=<forged_token> HTTP/1.1
Host: <target>
```

## 变体与关联

- 变体：公钥段换成 `jwk`/`x5c`/`jku` 等标准 JWT 扩展参数（那类攻击见关联卡），原理同属"验签密钥由令牌提供"。
- 变体：若实现按 `alg` 段动态选择算法，还可尝试算法混淆（RS→HS 用公钥当 HMAC 密钥）或 `none`。
- 变体：段数判断（`len(all_data) == 4`）本身就是可利用点——若伪造 3 段会让 `key = secret`，说明该实现把"缺省密钥"当兜底，反过来也能用来判断伪造是否必需 4 段。
- 关联：[[web-generic-jwt-jwk-header-injection]]（JWT 标准格式下的同一类缺陷：服务端信任令牌内嵌公钥）。
- 关联：[[web-generic-jwt-rs256-hs256-confusion]]、[[web-generic-jwt-alg-none-bypass]]（同属"验签信任边界放错位置"）。
- 关联：[[web-python-framework-pyramid-runtime-route-memshell-commit]]（本卡伪造的 admin 令牌是进入该 Pyramid 靶场代码执行视图的前置条件）。
- 边界：若验签端把密钥固定为服务端配置（忽略第 4 段）、或对公钥做指纹白名单、或用 HMAC 且密钥不可预测，则不成立。

## 检测与防御

- 修复：验签密钥只能来自服务端可信配置（固定公钥/受控 JWKS），禁止从令牌里解析密钥；移除"令牌自带公钥"这条分支。
- 加固：用成熟的 JWT/JWS 库并固定算法白名单；对 payload 做规范化序列化（避免同一逻辑对象有多种 JSON 形式导致签名/验签不一致）；密钥轮换走受控流程。
- 检测：令牌中出现异常的第 4 段/`jwk`/`jku`/`x5u`/`x5c`；同一 `kid` 对应公钥指纹变化；令牌签发方与验签密钥指纹不匹配；特权接口出现外部令牌却通过验签的日志。
