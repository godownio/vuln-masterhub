---
id: ctf-web-client-aes-score-forgery-hardcoded-key-iv
title: 分数由前端 AES 加密提交：密钥/IV 在前端 JS 里，解出明文改分再重新加密即刷分
type: scenario
domain: ctf
path: ctf/web
technique: client-side-aes-encrypted-score-tamper
aliases:
- 前端 AES 密钥刷分
- api.php 分数篡改
- 客户端加密计分绕过
- 游戏分数由客户端决定
tags:
- aes
- client-side-trust
- business-logic
- score-tamper
- javascript
- ctf
- crypto
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:47:39+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文仅写「前端发现 api.php，aes 解密发送 score，拿到 key 和 iv 加密发包」，卡内 key/iv/模式/padding 为通用还原、非原文实测值，PoC 未对真实目标运行，故置信度维持 low
---

## 一句话结论

当游戏/答题类应用把得分在浏览器端算好后用 AES 加密提交给 `api.php` 一类的接口、且密钥与 IV 硬编码在前端 JS 中时，服务端并不掌握“分数从哪来”的事实，攻击者照抄算法解出明文、把分数改成目标值再重新加密提交即可直接达成通关条件。

## 原理

- **信任边界放错**：计分本应在服务端依据行为记录计算；把分数交给客户端生成，服务端只能验证“密文能否解开”，无法验证“分数是否真实”，因此任何能重放加密逻辑的人都能提交任意分数。
- **对称加密不等于防篡改**：AES-CBC 只提供机密性，不提供完整性（没有 MAC/GCM tag）。即便密钥不泄露，攻击者只要知道算法与密钥就能改密文；而这里密钥和 IV 就在前端 JS 里，连密文篡改都不需要，直接重新加密明文即可。
- **前端不可保密**：前端 JS 是公开代码，任何硬编码 key/iv、盐值、签名算法都必须视为公开；混淆只能提高阅读成本。

## 触发条件

- 应用把分数（或等价的判定结果）由客户端计算/提交。
- 提交前用对称加密/编码保护，算法、key、iv 在前端 JS 或小程序包中可见。
- 服务端只校验密文可解或格式正确，缺少“分数上限/动作序列/服务端重算”校验。

## 利用步骤

1. 打开前端 JS，定位到调用 `api.php`（或同类计分接口）的代码，读取 AES 模式、padding、key、iv 与明文字段名（如 `score`）。
2. 用同一算法在本地解一条正常请求的密文，确认明文字段结构。
3. 把分数改成通关阈值（本题为 10000），重新加密并替换请求体提交。
4. 若服务端还校验其他字段（批次号、时间戳、签名字段），一并伪造或在抓到的合法请求上原地改分。
5. 刷新页面/领奖接口确认通关。

## PoC

```javascript
// 前端泄露的算法参数（原文：key 与 iv 均在前端）
const key = CryptoJS.enc.Utf8.parse("<key from front-end js>");
const iv  = CryptoJS.enc.Utf8.parse("<iv from front-end js>");

const plain = JSON.stringify({ score: 10000, /* 其它字段按正常请求补齐 */ });
const cipher = CryptoJS.AES.encrypt(plain, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
console.log(cipher.toString());   // 直接作为请求体提交
```

```python
# 等价的最小实现（只给出调用形状，key/iv 取自前端）
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json, base64

key, iv = b"<16 byte key>", b"<16 byte iv>"
data = json.dumps({"score": 10000}, separators=(",", ":")).encode()
print(base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))).decode())
```

无真实目标 PoC：原文只记录“从前端拿到 key/iv 后加密发包即得满分”，未给出密文样例。

## 变体与关联

- **完整性缺失**：CBC 无 MAC → 比特翻转改明文；ECB → 相同明文块可重排/拼接；拿到 key 则直接重加密。
- **同族问题**：前端硬编码签名（HMAC、`md5(参数+盐)`）、前端决定 `isAdmin`/`price`/`discount`、客户端时间戳参与业务判定，都属于客户端信任。
- **关联**：`ctf-web-wasm-client-game-logic-tamper-proof-forgery`（用 wasm2wat 改客户端 AI/胜负判定与 proof）、`web-generic-payment-amount-tamper-no-order-binding`（金额由客户端提交且未与订单绑定）。
- **边界**：若服务端用服务端持有的事件流重算分数，或对密文附加 HMAC（密钥不下发前端），本方法失效。

## 检测与防御

- **架构**：分数/胜负必须由服务端依据可验证的事件序列计算；客户端只提交动作，不提交结果。
- **密码学**：不要把对称密钥下发到前端；需要防篡改时使用服务端密钥的 HMAC/GCM 或非对称签名，并绑定 nonce、用户、时间窗。
- **业务校验**：分数上限、增速合理性、同会话重复提交、异常时间分布；领奖前做二次校验。
- **检测**：同一账号短时间内分数从 0 跳到阈值；同一密文重复提交；密文长度/结构异常；来源 IP 与历史行为不一致。

## 可信度与边界

- 原文为线下竞赛 web 题，正文只写明“前端发现 api.php、AES 解密后发送 score、拿到 key 与 iv 加密发包”，具体算法参数与请求体在截图中，未在正文给出密文样例。
- 卡内 PoC 为按该描述还原的通用形状，未对真实目标运行。
