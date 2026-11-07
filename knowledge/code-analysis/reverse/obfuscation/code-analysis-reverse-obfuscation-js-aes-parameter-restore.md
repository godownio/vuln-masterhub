---
id: code-analysis-reverse-obfuscation-js-aes-parameter-restore
title: JavaScript 混淆下定位 AES-CBC 参数加密并还原 key/iv 与 iv||密文格式
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: js-aes-parameter-reverse
aliases:
- 前端 AES 加密逆向
- content 字段解密
- AES-CBC key/iv 提取
- iv 前置拼接密文
- 登录参数还原
- JS 混淆加密分析
tags:
- javascript
- reverse
- aes
- cbc
- obfuscation
- frontend-encryption
- key-extraction
- login
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:27:29+08:00'
  notes: 已对照 15 张图核对 Sources 搜索、encrypt 断点、key 49EVOKbs2rs2QkpI9ppRkrzTZ9eOPd9z、WordArray.random(16) iv、iv.concat(ciphertext)+base64 与 CyberChef 解出明文；password 字段 key/iv 与截图一致；未验证点：未在本机重放解密脚本
---

## 一句话结论

前端把登录参数整体加密成单个 `content` 字段、请求中又没有 RSA 加密的对称密钥字段时，基本可判定为对称加密；在 DevTools Sources 中搜索字段名定位 `encrypt`，断点读取 key/iv，再按“iv 与密文拼接后 base64”的格式拆分，即可离线还原用户名、口令等明文。

## 原理

- JS 混淆（字符串数组 + 索引函数）只替换名字，不改变运行时语义；断点停下时变量里仍是真实的 key、iv 和函数名，`encrypt` 等关键函数名通常还会保留。
- 判据：请求体只有 `content`、没有额外的长随机字段，说明没有“RSA 加密对称密钥”这一步，属于对称加密；若两次请求的 key 相同，则密钥固定写死在前端。
- `encrypt` 函数内出现 `iv`、`mode`、`padding` 三个参数即可识别为分组密码。原文为 AES、CBC 模式、PKCS7 填充，key 32 字节（AES-256），iv 由 `lib.WordArray.random(16)` 随机生成。
- IV 每次随机，但请求包里没有 IV 字段，说明 IV 必须随密文一起传给服务端；继续看 return 前的 `iv.concat(ciphertext)`，再整体 base64，即可确认格式为 `base64(iv || ciphertext)`。
- 解密时把 base64 还原成字节，前 16 字节为 IV，其余为密文；用抓到的固定 key 做 AES-CBC 解密并去填充，得到 JSON 明文。
- 口令字段可能走另一套硬编码 key/iv（原文 `password` 字段就是独立加密），需要用 Network → Initiator 调用链另找加密函数。

## 触发条件

- 目标站点在浏览器端对请求参数做对称加密，密钥/IV 必须存在于前端 JS（否则浏览器无法加密）。
- 攻击者可访问登录页、加载 JS，并有一个可触发请求的测试账号。
- 能使用浏览器 DevTools 或抓包工具；请求/响应可被查看。
- 加密结果只做保密、未做服务端签名/绑定，还原后的明文可进一步用于改包、重放或接口测试。

## 利用步骤

1. 用 `test/test` 登录并抓包：若 body 只有一个 `content` 密文字段，先判为对称加密。
2. DevTools → Sources → 右键服务器目录 → Search，搜索 `content`，定位到 `app.*.js` 中的赋值位置。
3. 在 `content` 赋值行下断点，重新提交登录；断下后查看变量，确认其已是密文，并选中外层函数查看 `name` 是否为 `encrypt`。
4. 单步进入 `encrypt`：根据 `iv`、`mode`、`padding` 判断算法；读取 key 变量（32 字节）和 iv 生成表达式（`WordArray.random(16)`）。
5. 查看 return 前的拼接：`iv.concat(ciphertext)` 后 base64；记录顺序。
6. 取一段抓到的 `content`，base64 解码；前 16 字节作 IV，剩余作密文，用 key 做 AES-CBC 解密并去 PKCS7 填充，得到明文 JSON。
7. `password` 字段单独处理：Network → 选中登录请求 → Initiator → 找 `login` 调用链，在参数赋值处下断点，进入其加密函数读取硬编码 key/iv，再解密该字段。
8. 将两段逻辑串成脚本，后续可直接构造/解密请求参数。

## PoC

`content` 字段解密（Python + pycryptodome）：

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

content = "cd8IybuU1T8E6x6dncKX95GFzWG34MONsVWSG4dZu34HpNjs..."  # 抓包值
raw = base64.b64decode(content)
iv, ct = raw[:16], raw[16:]
key = b"49EVOKbs2rs2QkpI9ppRkrzTZ9eOPd9z"  # 32 字节，前端写死

pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode())   # {"username":"test","password":"4F3qL3OZnPFi...=="}
```

`password` 字段（key/iv 固定，密文直接 base64）：

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = base64.b64decode("4F3qL3OZnPFi...==")
key = b"JIlidaopg9APlIlIJIlidaopg9APlIlI"
iv  = b"JIlidaopg9APlIlI"
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode())  # test
```

原文用 CyberChef 以同样的 AES/CBC/PKCS7、key 与 IV 设置解密，得到 `{"username":"test","password":"..."}` 与 `test`。

## 变体与关联

- 变体：key 每次请求随机时，必有一个 RSA/ECDH 加密后的 key 字段随包发送；定位该字段并用私钥不可得的公钥思路改为在 JS 断点处直接读取明文 key。
- 变体：IV 可能在密文后部、单独字段或固定值；以 `concat` 的顺序和请求字段为准，不要默认前置。
- 变体：CryptoJS 站点可直接在 console 调用其 `AES.decrypt`，或 hook `CryptoJS.AES.encrypt/decrypt` 打印入参。
- 变体：混淆较重时，先在 console 打印字符串数组/还原索引函数，再配合断点；本文的断点法对大多数 webpack/CryptoJS 站点足够。
- 边界：若服务端对参数做 HMAC/签名并与会话绑定，单靠解密不能改包；若加密在 WebAssembly/原生层完成，需换用动态调试或 hook。

## 检测与防御

- 检测（防御方视角）：前端 bundle 中出现硬编码 key/iv、`CryptoJS.AES.encrypt`、`WordArray.random(16)` 与 `concat` 拼接；登录请求 body 仅一个 `content` 字段。
- 防御：不要把前端加密当作传输安全，必须使用 TLS；前端密钥一律视为公开，不得用于保密或身份认证。
- 防御：若必须做请求保护，使用服务端下发的会话密钥 + AEAD（如 AES-GCM）并加 HMAC/签名，绑定会话、时间戳与 nonce，防止解密后的改包与重放。
- 加固：服务端对关键参数做二次校验与权限检查，不能因为“参数已加密”就信任其内容。
