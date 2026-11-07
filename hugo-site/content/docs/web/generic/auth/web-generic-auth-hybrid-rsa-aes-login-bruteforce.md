---
id: web-generic-auth-hybrid-rsa-aes-login-bruteforce
title: 前端 RSA+AES 混合加密登录接口复刻：硬编码公钥下自动化口令爆破
type: scenario
domain: web
path: web/generic/auth
technique: hybrid-rsa-aes-login-bruteforce
tags:
- auth
- rsa
- aes
- hybrid-encryption
- javascript
- login
- brute-force
- credential-testing
- frontend
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:44:31+08:00'
  notes: 已对照原文与图03核对：login.js 的 AES-128-CBC + RSA PKCS1_v1_5 混合加密、encryptedData/Key/Iv 字段与脚本复刻一致，爆破得到 admin:hotdog；附文中公钥与响应；未复跑
url: /docs/web/generic/auth/web-generic-auth-hybrid-rsa-aes-login-bruteforce/
draft: false
kb_aliases:
- 混合加密登录爆破
- RSA 包裹 AES 会话密钥
- encryptedData/encryptedKey/encryptedIv
- jsencrypt 登录加密复刻
- 前端登录加密自动化爆破
---

## 一句话结论

登录页把凭据用随机 AES-128-CBC 密钥加密、再用写死在前端的 RSA 公钥包裹该密钥时，攻击者可以完整复刻同一套加密逻辑，把任意口令加密成服务端能解开的合法请求，从而对登录接口做自动化口令爆破；前端加密只挡明文抓包，不构成任何认证强度。

## 原理

- 前端 `login.js` 的典型混合加密流程：生成随机 16 字节 AES key 与 IV → 用 AES-128-CBC + PKCS7 加密 JSON 凭据 `{"username":...,"password":...}` → 分别用 RSA 公钥（PKCS#1 v1.5）加密 Base64 后的 key 与 IV → 以 `encryptedData`、`encryptedKey`、`encryptedIv` 三个字段 POST 给登录接口。
- 服务端做相反操作：RSA 私钥解出被包裹的 key/IV，AES 解出凭据并校验。只要公钥和算法能从公开的 JS 静态资源中取得，任何人都能在本地生成同样的密文。
- 随机 key/IV 的作用是让同一口令每次的密文不同，只能防重放和简单流量比对，不能阻止攻击者逐条构造新请求；公钥本身不是秘密，RSA 加密的方向是“客户端→服务端”，不证明请求来自真实前端。
- 危害成立的关键不在加密本身，而在登录接口缺少速率限制、失败锁定或验证码：服务端会把每个可解密的口令尝试都当作正常登录校验，弱口令可被离线字典逐条试出。本案例中用户名 `admin` 可从后台页面/常见命名推断，口令字典命中了 `hotdog`，接口返回 `success: true` 与后续可用的 token。
- 该手法也可用于绕过只在前端做“密码加密后再提交”的 WAF 规则：WAF 看不到明文口令，无法按关键字拦截。

## 触发条件

- 目标登录页从公开静态资源加载了加密实现（如 `login.js`、`jsencrypt.min.js`、`crypto-js.min.js`）。
- RSA 公钥硬编码在前端 JS 中，或能从页面/接口获取。
- 登录接口接受 JSON/表单形式的密文字段，且服务端会解密后校验口令。
- 登录接口没有有效的速率限制、账号锁定、验证码或设备风控（或可被绕过）。
- 已知或可枚举出有效用户名。

## 利用步骤

1. 抓取登录页与全部 JS 静态资源，定位登录请求的字段名与加密函数；确认 AES 模式、填充、key/IV 长度、Base64 编码方式，以及 RSA 填充方式（PKCS#1 v1.5 或 OAEP）。
2. 提取硬编码的 RSA 公钥，在 Python 中用 PyCryptodome 导入。
3. 复刻加密：随机 16 字节 key/IV → AES-128-CBC/PKCS7 加密凭据 JSON → Base64；RSA 加密 Base64(key) 与 Base64(iv) → Base64。把结果与浏览器实际请求逐字段比对，确认顺序和编码一致。
4. 用 `dashboard.html`、错误提示或注册接口确认管理员用户名，准备口令字典。
5. 循环发送 POST，按响应中的 `success` 字段或 token 是否存在判定命中；命中后保存 token。
6. 用 token 访问后台，继续寻找上传、导入等高价值功能。

## PoC

```python
import os, json, base64, requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad

pub = RSA.import_key(open("rsa_public.pem").read())
URL = "http://target/api/login.php"

def encrypt(username, password):
    key, iv = os.urandom(16), os.urandom(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(
        pad(json.dumps({"username": username, "password": password}).encode(), 16))
    rsa = PKCS1_v1_5.new(pub)
    return {
        "encryptedData": base64.b64encode(ct).decode(),
        "encryptedKey": base64.b64encode(rsa.encrypt(base64.b64encode(key))).decode(),
        "encryptedIv": base64.b64encode(rsa.encrypt(base64.b64encode(iv))).decode(),
    }

for pw in open("wordlist.txt", encoding="utf-8"):
    pw = pw.strip()
    if not pw:
        continue
    r = requests.post(URL, json=encrypt("admin", pw), timeout=10).json()
    if r.get("success"):
        print("hit:", pw, "token:", r.get("token"))
        break
```

```text
# 成功响应形态（字段名随目标实现变化）
{"success":true,"token":"<session token>"}
```

## 变体与关联

- 变体：RSA 只加密口令本身、AES 只做参数签名；或使用 SM2/SM4、OAEP 填充、每次会话轮换的临时公钥。逆向时必须以目标 JS 为准，不要套用固定模板。
- 变体：不实现算法，直接用 Playwright/Selenium 打开登录页，调用页面自身的加密函数生成密文，再驱动表单提交。
- 变体：加密之外还有 CSRF token、时间戳、nonce 或设备指纹时，需一并复刻；可结合登录限速绕过技巧。
- 关联：[[web-generic-auth-cas-aes-cbc-login-encryption-reverse]]（单层 AES-CBC 登录加密逆向）、[[web-generic-auth-bastion-frontend-3des-login-forgery]]（3DES 前端加密）、[[web-generic-auth-login-bruteforce-response-payload]]（爆破响应判读与 payload 变换）、[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]（前端 JS 凭据提取）。
- 边界：服务端启用强速率限制/验证码/账号锁定时，单纯复刻加密不足以完成爆破；公钥来自服务端会话且频繁轮换时，脚本需先拉取新公钥。

## 检测与防御

- **认识边界**：前端加密不能替代传输安全，更不能作为认证强度；它能被任何能看到 JS 的人复刻。真正需要 HTTPS、服务端风控与强口令策略。
- **频率与锁定**：对登录接口按账号+IP+设备指纹做速率限制、失败计数、指数退避、验证码与临时锁定；对同一 IP 短时间内大量“格式合法但凭据错误”的请求告警。
- **口令策略**：禁用弱口令、检测撞库字典、强制管理员高强度口令与 MFA。
- **响应一致性**：成功/失败响应长度、状态码和耗时尽量一致，避免通过差异枚举用户名或加速爆破；成功后才返回 token。
- **监控**：静态资源被批量下载、登录请求中密文长度/结构高度一致、同一 IP 对单一用户名高频 POST、加密字段解密失败率异常。

