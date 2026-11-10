---
id: mobile-miniprogram-aes-cbc-rsa-wrapped-iv-key-sign-replay
title: 小程序自定义加密：AES-CBC 的 iv/key 被 RSA 公钥包裹后随请求头下发，签名是「密文 + 私钥」——逆出来后固定 iv/key 用 Python 重造参数即可任意改包重放
type: scenario
domain: mobile
path: mobile
technique: miniprogram-aes-cbc-rsa-wrapped-iv-key-sign-replay
aliases:
- 小程序 securityParam 加密
- salt encryptkey 请求头
- RSA 包裹 AES 的 iv 与 key
- jsrsasign 签名
- WeChatOpenDevTools 断点调试
- 微信小程序改包重放
tags:
- mobile
- miniprogram
- reverse
- aes-cbc
- rsa
- sign
- jsrsasign
- replay
- burp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:15+08:00'
  notes: 已对照原文核对；本次核对未读取图片；securityParam=AES-CBC(明文,salt/iv,encryptkey/key)、salt/encryptkey 由 p()/g() 随机生成后用 RSA 公钥加密（jsrsasign KJUR.crypto.Cipher.encrypt）、sign 用私钥对 securityParam 与加密值签名、公钥私钥硬编码在前端、固定 iv/key 用 Python 重造后可改包重放等要点均与正文一致；AES 具体模式/padding、RSA 的 key 格式（PKCS#1/PKCS#8）、签名拼接的确切字段顺序原文只在截图与断点里，卡内 PoC 为结构示意并已标「结构示意」
---

## 一句话结论

当小程序把请求体做成「`securityParam` = AES-CBC(明文, key, iv)」，再把 `key`/`iv` 分别用 **RSA 公钥**加密成请求头里的 `encryptkey`/`salt`、并用**RSA 私钥**对密文签名（`sign`）时，只要公钥私钥是硬编码在前端的，就等价于没有加密：反编译或开 devtools 断点找出 `AES`/`RSA`/签名三处实现，把 `iv`/`key` 固定下来，用 Python 复现同样的加密与签名，就能任意篡改业务参数并重放，绕过"加密 + 签名"的防篡改假象。

## 原理

- **key 与 iv 随请求一起发**：`salt`（iv）与 `encryptkey`（key）是前端每次随机生成的，但被 RSA 公钥包裹后放在请求头里一并送达，服务端用私钥解开再用它们解密 `securityParam`——也就是**密钥完全由客户端决定**。
- **公钥私钥硬编码在前端**：`jsrsasign` 调用 `KJUR.crypto.Cipher.encrypt(t, r)` 用的公钥、签名用的私钥都能从反编译的 JS 里直接找到；找到私钥就意味着能自己生成合法签名。
- **签名只是「密文 + 私钥」**：`sign` 方法把 `securityParam`（以及加密后的值）用私钥签名，不掺服务端密钥、不含 nonce 以外的混淆，所以本地重算即可通过校验。
- **因此整套机制的强度取决于前端保密性**：前端代码可反编译、可断点，所有"秘密"都在客户端，等价于开放。攻击者只需保证「AES 参数自洽 + 签名自洽」就能过服务端，之后所有业务参数（金额、账号、`id`）都可任意改。
- **工具链**：小程序包用解包工具反编译出 JS，搜索 `Encryptkey`/`securityParam` 即可定位；静态看不懂时用 `WeChatOpenDevTools` 打开 devtools 断点（需微信版本匹配，本例 3.9.10.19），甚至可以在断点处直接改内存里的参数验证猜想。

## 触发条件

- 目标是小程序（或 H5/APP 的 JS 前端），加密与签名算法在客户端完成。
- RSA 公钥（用于加密 iv/key）与私钥（用于签名）都出现在前端代码里——这是本卡成立的关键，若签名改由服务端密钥完成则只能做"重放"而非"改包"。
- 算法为标准实现（本例 AES-CBC + `jsrsasign` 的 RSA），没有额外的设备指纹/风控绑定（若 `encryptkey` 绑定了设备 ID，则需一并伪造）。
- 能抓到一条合法请求作为模板（结构、字段顺序、时间戳格式）。

## 利用步骤

1. 反编译小程序包，全局搜 `Encryptkey`/`securityParam`/`sign`，定位加密、RSA、签名三处代码（通常在同一文件相邻位置）。
2. 打开 devtools（工具开不了就降微信版本，本例 3.9.10.19；删掉 `RadiumWMPF` 下残留文件再重进可解决"版本对了但没开起来"），在加密函数与签名函数上下断点。
3. 断下来读实参：`AES` 的 key/iv 生成方式、编码（UTF-8/hex/base64）、padding（PKCS7）；`RSA` 用的公钥格式（PKCS#1/PKCS#8、base64 还是 hex）；签名是对哪些字段按什么顺序拼接。
4. 用 Python 复现：`pycryptodome` 做 AES-CBC，`rsa`/`cryptography` 做 RSA 加密与签名（私钥即可签）。
5. 生成一组固定的 `iv`/`key`（不必随机），按模板顺序拼出完整请求，重放验证。
6. 通过后即可任意改业务参数；进一步用 Burp 插件（自动加解密/签名）或本地代理脚本做到"边改边签"。

## PoC

```python
# 结构示意：把前端三段逻辑在本地用同一套参数复现
import base64, json, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import rsa

PUB = rsa.PublicKey(*load_public_key_from_js())   # 前端硬编码的公钥
PRIV = rsa.PrivateKey(*load_private_key_from_js()) # 前端硬编码的私钥（签名用）

iv, key = b'0123456789abcdef', b'fedcba9876543210'   # 固定下来，不再随机
plain = json.dumps({"amount": 1, "to": "attacker"}, separators=(',', ':'))

cipher = AES.new(key, AES.MODE_CBC, iv)
security_param = base64.b64encode(cipher.encrypt(pad(plain.encode(), 16))).decode()

salt       = base64.b64encode(rsa.encrypt(iv,  PUB)).decode()   # RSA 包裹 iv
encryptkey = base64.b64encode(rsa.encrypt(key, PUB)).decode()   # RSA 包裹 key
ts         = str(int(time.time() * 1000))
sign       = base64.b64encode(rsa.sign((security_param + ts).encode(), PRIV, 'SHA256')).decode()

headers = {"salt": salt, "encryptkey": encryptkey, "timestamp": ts, "sign": sign}
body    = {"securityParam": security_param}
# 用 headers + body 重放；响应体同样用 key/iv 解密
```

## 变体与关联

- 变体：签名只对 `securityParam` 而不含时间戳时，可无限重放同一密文（无防重放）；含时间戳但服务端不校验窗口时同样可重放。
- 变体：`iv`/`key` 不由客户端随机而是硬编码常量时，连 RSA 那层都不用管，直接 AES 解密即可（更弱）。
- 变体：算法换成 SM2/SM4、或 key 由 `wx.login` 的 code 派生并绑定 session 时，需要先拿 code 再算 key，且换设备/换 session 会失效。
- 关联：[[mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration]]（同为小程序 AES + 签名重算，但那边是 AES-ECB + 固定派生密钥 + MD5 签名）、[[code-analysis-reverse-obfuscation-weapi-asrsea-aes-rsa-hop-param-forge]]（AES + RSA 双层参数伪造的 Web 版）、[[code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge]]（固定 key/iv 的 AES-CBC 请求伪造）。
- 边界：若私钥不在前端（只用公钥加密 iv/key、签名由服务端私钥完成），则只能解密响应、无法伪造签名；若服务端把 `encryptkey` 与设备指纹/登录态绑定，则单纯复制参数会被拒。

## 检测与防御

- 检测（渗透视角）：小程序包内出现 `KJUR.crypto.Cipher`、`jsrsasign`、`securityParam`、`Encryptkey` 等关键字；请求头同时带 `salt`/`encryptkey`/`sign`/`timestamp`。
- 修复：签名密钥必须留在服务端（客户端只做"提交"，服务端用 HMAC 私钥校验）；不要把 RSA 私钥打进前端；对关键业务参数在服务端重新校验（金额、受益人）。
- 加固：绑定设备指纹/登录态并做一次性 nonce 防重放；对异常改包行为（同一账号短时间多设备、金额跳变）做风控；启用小程序代码加固与反调试。
