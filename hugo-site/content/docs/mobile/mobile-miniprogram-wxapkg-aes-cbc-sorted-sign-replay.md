---
id: mobile-miniprogram-wxapkg-aes-cbc-sorted-sign-replay
title: 小程序 wxapkg 反编译逆出 AES-CBC 硬编码 key/iv 与「排序键值+密钥」MD5 签名，重算 timestamp/nonce 实现改包重放
type: scenario
domain: mobile
path: mobile
technique: miniprogram-wxapkg-aes-cbc-sorted-sign-replay
tags:
- mobile
- miniprogram
- reverse
- wxapkg
- aes-cbc
- md5
- signature
- replay
- burp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:36:57+08:00'
  notes: 已对照原文与20/20图片核对：图03 VUE_APP_SIGN_KEY=rDJiNB9j7vD2、图04 AES-CBC/Pkcs7 常量 key=Wet2C8d34f62ndi3/iv=K6iv85jBD8jgf32D、图08-09 timestamp=Date.parse/1e3、nonce=Date.now().slice(-6)、SignMD5 排序键名+拼接键值+secret 后 MD5、图10 Python sign 复算、图13/14 autoDecoder AES/CBC/PKCS5Padding 配置与响应重放均与卡一致，重放链路成立。dedup 候选 mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration（AES-ECB/派生key/MD5(json+ts)）与 RSA 包裹 key/iv 卡均 related 非同链，保留正确。原文未给组件版本，affected_versions 留空正确。无 sources/source_url、无文章ID/URL/长段摘录，路径 mobile 合法。小问题（不影响核实）：1) 文中 autoDecoder 请求正则图14实为 data=([^&\s]+)，卡内 PoC 写作 data=([^&]*)；2) 关联段'本篇同批的教师接口学生名单遍历卡'未入库（已作为既有卡 web-generic-auth-teacher-roster-api-student-token-lesson-enumeration 的重复被 reject），属悬空指代。未验证点：PoC 未执行，服务端签名校验未实测。
url: /docs/mobile/mobile-miniprogram-wxapkg-aes-cbc-sorted-sign-replay/
draft: false
kb_aliases:
- 小程序 AES-CBC 硬编码密钥
- 小程序 sign 重算
- 排序键值 MD5 签名
- timestamp nonce 规则
- wxapkg 反编译改包
- autoDecoder 小程序
---

## 一句话结论

微信小程序的 wxapkg 包可用反编译工具还原出 `app-service.js`，其中请求体用 AES-CBC/PKCS7 加密、key 与 iv 以字符串常量硬编码，`sign` 则由“参数对象按键名排序后依次拼接键名+键值，再追加硬编码 secret 做 MD5”生成；同时还原出 `timestamp`/`nonce` 的生成规则后，攻击者就能在本地重新加密任意参数、重算签名与随机数，用 Python 脚本或 Burp autoDecoder 透明改包重放。

## 原理

- **小程序包可离线解包**：微信小程序代码打包在 wxapkg 中，`app-service.js` 等文件可被解包工具还原为可读 JS。前端代码中的密钥、IV、签名函数和接口列表对攻击者完全可见，“加密”只是提高抓包可读性门槛。
- **静态 key/iv 等价于明文**：代码里 `AES` 配置为 `mode: CBC`、`padding: Pkcs7`，key 与 iv 直接是两个字符串常量（原文为 `Wet2C8d...` 与 `K6iv...`，各 16 字符）。AES-CBC 本身安全，但密钥由客户端持有且固定，攻击者照抄即可加解密，无需破解算法。
- **签名由客户端可复算**：`SignMD5` 的实现是 `Object.keys(data).sort().reduce((acc, k) => acc + k + data[k], "")`，再把拼接串与硬编码 secret（原文为 `rDJiNB9j7vD2`）连接后做 MD5。整个过程不含服务端独有秘密，攻击者修改任意字段后都能算出新 `sign`，签名只保证“格式自洽”，不构成身份或权限校验。
- **timestamp/nonce 只是形式防重放**：请求拦截器把 `timestamp` 设为当前秒级时间，`nonce` 取 `Date.now()` 字符串的后 6 位；文章样本中 nonce 前 3 位要求等于 timestamp 末 3 位，其余位随机补足。规则可从 JS 直接还原，本地生成合法 nonce 没有障碍，所谓防重放对能重算的人无效。
- **autoDecoder 把加解密透明化**：在 Burp 的 autoDecoder 中配置请求/响应 AES-CBC 加解密，并用正则 `data=([^&]*)` 提取请求密文、`"data":"([^"]*)"` 提取响应密文，即可在 Repeater/Intruder 中直接看到明文并修改，插件自动重新加密与签名。原文还先用在线 AES 工具与自写 Python 脚本验证 key/iv 和 sign 算法，再迁移到插件。
- **为什么成立**：服务端能解密并校验签名，但两者都可由客户端复现；只要攻击者拿到一条合法请求作为模板，就能构造任意业务参数的合法请求。

## 触发条件

- 目标为小程序，请求体或响应体包含 Base64 密文字段（如 `data=`），并带 `sign`、`timestamp`、`nonce` 等字段；
- 能获取小程序 wxapkg（本地缓存、抓包下载或他人提供），并可用 wxapkg 类工具反编译；
- AES key/iv 与签名 secret 硬编码在 JS 中，签名算法可静态还原或运行时调试；
- 服务端未额外绑定设备指纹/一次性 nonce 存储，或绑定可被绕过。

## 利用步骤

1. 抓包观察请求：`POST /v3/api.php/...`，表单字段 `ostype=5&data=<Base64 密文>`，响应 JSON 中 `data` 也是密文。
2. 用 wxapkg 反编译工具解包本地小程序缓存，得到 `app-service.js` 等文件，全局搜索 `AES`、`CBC`、`sign`、`nonce`、`timestamp`。
3. 定位加密配置与常量：`mode: CBC`、`padding: Pkcs7`、key/iv 字符串；定位 `SignMD5`：排序键名、拼接键值、追加 secret、MD5。
4. 用 Python 复现 AES-CBC 加解密与签名，先用自己的请求验证能解出明文、算出的 sign 能被服务端接受。
5. 还原 `timestamp`/`nonce` 生成规则，构造任意业务参数的明文 JSON，加密、重算 sign 与 nonce 后重放。
6. 将同一套 key/iv/算法配置到 Burp autoDecoder（或自写加解密代理），实现 Repeater/Intruder 中的透明改包。

## PoC

Python 复现（key/iv/secret 为占位符，逻辑与原文一致）：

```python
import base64, hashlib, time, random, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"<16-byte-key>"      # 从 app-service.js 提取
IV  = b"<16-byte-iv>"       # 从 app-service.js 提取
SECRET = "<hardcoded-sign-secret>"

def encrypt(obj):
    pt = json.dumps(obj, separators=(",", ":")).encode()
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(pt, 16))
    return base64.b64encode(ct).decode()

def decrypt(b64):
    pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(base64.b64decode(b64))
    return unpad(pt, 16).decode()

def sign_md5(data):
    joined = "".join(f"{k}{data[k]}" for k in sorted(data))
    return hashlib.md5((joined + SECRET).encode()).hexdigest()

ts = int(time.time())
nonce = int(str(ts)[-3:] + "".join(str(random.randint(0, 9)) for _ in range(3)))
data = {"uid": 100123, "course_id": 464, "timestamp": ts, "nonce": nonce, "ostype": 5}
data["sign"] = sign_md5(data)
print("ostype=5&data=" + encrypt(data))
```

autoDecoder 关键配置：请求正则 `data=([^&]*)`，响应正则 `"data":"([^"]*)"`；加解密算法 AES/CBC/PKCS5(7)Padding，Ciphertext Base64，SessionKey 与 Ivparameter 填上面提取的 key/iv。

## 变体与关联

- 变体：AES 模式可换 ECB（无 iv）、key 可由常量派生，或 key/iv 用 RSA 公钥包裹后随请求头下发，见 [[mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration]]、[[mobile-miniprogram-aes-cbc-rsa-wrapped-iv-key-sign-replay]]。
- 变体：签名算法可换 `MD5(json+timestamp)`、HMAC、SM3；若密钥/私钥硬编码在前端同样可重算，见 [[web-generic-auth-js-signature-jsrpc-autodecoder]]、[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]。
- 关联：拿到透明改包能力后常接功能级越权/ID 遍历，见本篇同批的教师接口学生名单遍历卡；抓包链路见 [[mobile-miniprogram-charles-burp-upstream-proxy-capture]]。
- 边界：若签名为服务端密钥 HMAC 且密钥不下发、或 nonce 在服务端一次性存储并强校验，则只能重放已有请求，不能改包。

## 检测与防御

- 服务端：签名改用服务端持有的 HMAC-SHA256 密钥，覆盖 method、path、body、timestamp、nonce；服务端保存 nonce 并校验时间窗口，拒绝重复/过期请求。
- 服务端：不要把 AES key/iv 当做安全边界；前端加密只用于防明文抓包，真正的授权必须在服务端按会话与角色判断。
- 检测：同一账号短时间大量结构相同、仅个别字段递增的请求；`timestamp` 跳跃/重复、`nonce` 规律异常；请求解密后参数与正常业务偏差大。
- 加固：密钥动态下发并绑定设备/会话（仍需服务端校验）、代码混淆与反调试只能提高成本，不能替代服务端校验。
