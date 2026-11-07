---
id: web-generic-auth-cas-aes-cbc-login-encryption-reverse
title: CAS 登录前端 AES-CBC 加密逆向与自动化登录参数构造
type: scenario
domain: web
path: web/generic/auth
technique: cas-frontend-aes-cbc-login-encryption
tags:
- cas
- sso
- aes
- cbc
- javascript
- auth
- automation
- credential-testing
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:18+08:00'
  notes: 已对照原文核对；原文未展示登录成功，加密复现需按目标实际密文编码比对，未复跑 PoC
url: /docs/web/generic/auth/web-generic-auth-cas-aes-cbc-login-encryption-reverse/
draft: false
kb_aliases:
- CAS 密码加密逆向
- saltPassword
- pwdEncryptSalt
- AES-CBC 登录加密
- 统一认证登录自动化
- CAS 登录参数构造
---

## 一句话结论

CAS 登录页把密码在浏览器端用 AES-CBC 加密后写入 `saltPassword` 隐藏域，密钥来自页面里的固定 `pwdEncryptSalt`、明文是 64 位随机前缀加真实密码、IV 随机并随密文一起返回；逆向 `encrypt.js` 后可在 Python 中完整复现加密，从而自动化构造登录请求（验证码与 IP 频率封锁仍需另行处理）。

## 原理

登录表单的关键字段：

- `username`：账号；
- `password`：只读输入框，真正的密码不直接提交；
- `saltPassword`：JS 加密后的密文；
- `pwdEncryptSalt`：页面下发的固定 salt（示例为 16 位字母数字），作为 AES 密钥；
- `execution`：CAS 的 CSRF/防重放 token，每次登录页刷新重新生成；
- `captchaSwitch`：验证码开关，示例 `2` 表示强制开启；
- `dllt`/`cllt`/`_eventId`：登录类型与提交事件。

前端 `encrypt.js` 的逻辑：

1. 用自定义字符集（去掉 `0/O/1/l/I` 等易混淆字符）生成随机串；
2. 明文 = `randomString(64) + password`，使同一密码每次密文都不同；
3. key = `CryptoJS.enc.Utf8.parse(salt)`；
4. IV = 16 位随机字符串；
5. AES-CBC + PKCS7 加密；
6. 返回 IV 与密文的组合（原文注释称 Base64，但示例 JS 代码用 `toString()` 拼接，实际编码需以目标页面为准）。

服务端用同一 salt 和 IV 解密，取后 64 位之后的真实密码。由于 salt 固定写在 HTML 中、不随会话轮换，攻击者拿到一次即可复用同一套加密逻辑；CAS 主要依赖 `execution` 防重放，而不是密钥轮换。`execution` 实测约 5–10 分钟有效，过期后 CAS 返回登录页并嵌入新 token，自动化脚本可解析新 token 后继续。

## 触发条件

- 目标 CAS 登录页使用前端 JS 加密密码（存在 `saltPassword`/`pwdEncryptSalt`/`encrypt.js` 一类结构）；
- 攻击者能访问登录页并解析 HTML/JS；
- 已获得目标账号（或进行授权内的弱口令/凭据测试）；
- 验证码、账号锁定、IP 频率限制等防护可被处理或绕过（否则加密复现本身不构成登录成功）。

## 利用步骤

1. 请求 `GET /authserver/login?service=<目标系统>`，保存 Cookie，解析 `execution`、`pwdEncryptSalt`、`captchaSwitch` 与登录表单字段。
2. 下载并反混淆登录页引用的加密 JS，确认随机字符集、随机前缀长度、key 派生、IV 生成、AES 模式/填充、输出编码（hex/Base64、IV 在前/在后）。
3. 在 Python/Java 中复现加密函数，与浏览器生成结果对比验证。
4. 构造 `POST /authserver/login`：`username`、`saltPassword=<密文>`、`execution`、`dllt`、`cllt`、`_eventId=submit`，携带同一 Cookie。
5. 解析响应：成功通常 302 到 `service` 并带 ticket；失败返回登录页与新 `execution`。
6. 处理验证码、账号锁定与 IP 频率限制；`execution` 过期时重新 GET 登录页刷新。

## PoC

```python
import random, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

RANDOM_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

def random_string(n):
    return ''.join(random.choice(RANDOM_CHARS) for _ in range(n))

def encrypt_password(password, salt):
    plaintext = random_string(64) + password
    key = salt.encode("utf-8")
    iv = random_string(16).encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + encrypted).decode("ascii")

print(encrypt_password("P@ssw0rd", "QAQVEU444clkxIXy"))
```

登录请求形态：

```http
POST /authserver/login HTTP/1.1
Host: cas.target
Content-Type: application/x-www-form-urlencoded
Cookie: <登录页下发的会话>

username=2023XXXX1043&saltPassword=<base64(iv+ciphertext)>&execution=<token>&dllt=generalLogin&cllt=userNameLogin&_eventId=submit
```

注意：原文的 JS 片段返回 `iv.toString() + ciphertext.toString()`，与 Python 示例的 `base64(iv+ciphertext)` 并不完全一致；上线前必须用目标页面实际生成的密文做字节级比对，确认是 hex 还是 Base64、IV 是否前置、salt 长度是否恰好 16 字节。

## 变体与关联

- 变体：不同 CAS 主题/定制可能改用 RSA、SM2/SM4、不同随机前缀长度、不同字符集、IV 放在密文尾部或单独字段；salt 可能每次会话轮换。
- 变体：不逆向算法，直接用 Playwright/Selenium 打开登录页，调用页面自身的 `encryptPassword` 函数生成密文。
- 关联：[[web-generic-auth-servlet-null-role-fail-open]]（认证逻辑缺陷）；[[web-generic-auth-type-dispatch-unauth-data-exposure]]（认证后数据面）。
- 不确定点：原文未展示登录成功的响应，42 次弱口令全部失败且 IP 被封；加密复现是完整的，但“能否登录成功”取决于凭据、验证码与频率控制。示例 salt/字符集仅为该 CAS 定制，换目标需重新逆向。

## 检测与防御

- **认识边界**：前端加密只防传输层明文与简单重放，不防自动化；攻击者可在本地复现同一算法。
- **频率与锁定**：按 IP/账号/设备做登录频率限制、验证码、失败计数与锁定；原文目标约 50 次请求/2 分钟即封 IP，但一刀切封禁会影响正常用户，建议结合设备指纹与风险评分。
- **token 管理**：`execution` 应短时效、一次性、绑定会话；salt 可按会话轮换（原文为固定值，复用成本低）。
- **响应一致性**：成功/失败/验证码错误的响应长度与状态码保持一致，避免用户枚举；但不要只靠响应差异做安全判断。
- **监控**：同一 IP 高频 GET 登录页（批量获取 execution）与高频 POST 登录；验证码失败率异常；登录页 JS 被大量下载。
- **合规**：凭据测试必须在授权范围内，遵守账号锁定与速率限制，避免造成业务中断。
