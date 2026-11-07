---
id: web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover
title: 微信小程序手机号登录：SessionKey 泄露 + encryptedData 重加密导致任意手机号账号接管
type: scenario
domain: web
path: web/generic/auth
technique: wechat-miniprogram-sessionkey-encrypteddata-phone-login-takeover
tags:
- wechat
- miniprogram
- sessionkey
- encrypteddata
- aes-cbc
- phone-login
- account-takeover
- api
- auth
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:24:10+08:00'
  notes: 已对照原文与截图核对：/api/applets/login 请求含 signature/encryptedData/iv/openId，AppletPentester 截图中 SessionKey、IV、明文 phoneNumber/purePhoneNumber/watermark 与密文、加密按钮均与卡片一致；AES-128-CBC + 改 phoneNumber 重加密后按目标手机号登录的机制描述准确。原文未展示后端代码，具体 SessionKey 泄露载体为抓包观察，卡片已标 confidence medium。未复现。
url: /docs/web/generic/auth/web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover/
draft: false
kb_aliases:
- 小程序 SessionKey 泄露
- encryptedData 重加密
- 微信手机号登录篡改
- AppletPentester
- 任意手机号登录
- 小程序 openId 绑定绕过
---

## 一句话结论

微信小程序把手机号作为登录身份时，服务端需要用 `session_key` 解密客户端提交的 `encryptedData`；如果登录流程把 `session_key`（及 IV）泄露给客户端，攻击者就能解密自己的手机号密文、把 `phoneNumber` 改成任意目标手机号后重新加密提交，服务端解密后按手机号登录，从而接管任意用户账号。

## 原理

- 小程序手机号获取流程：客户端调用 `wx.getPhoneNumber` 得到 `encryptedData` 与 `iv`，服务端用该用户 `session_key` 做 AES-128-CBC（PKCS#7 填充）解密，得到 `phoneNumber`、`purePhoneNumber`、`countryCode`、`watermark`（含 appid、timestamp）等字段。`session_key` 由 `wx.login` 的 code 经微信 `code2session` 接口换取，正常只应保存在服务端。
- 第一个缺陷是 `session_key` 泄露：登录/绑定流程的响应包或后续数据包把 `session_key`（以及 IV、openId）返回给客户端，或写入可读取的客户端存储/日志。攻击者拿到自己会话的 `session_key` 后，就拥有了生成合法密文的能力。
- 第二个缺陷是身份绑定缺失：服务端解密 `encryptedData` 后，直接把其中的 `phoneNumber` 当作登录身份，未校验该手机号是否属于当前 `openId`，也不校验密文是否由微信针对本次会话生成。于是攻击者用**自己的** `session_key` 加密**他人**手机号，服务端也会认可。
- 第三个常被忽略的点是 `signature`/`watermark`：若服务端校验 `signature`（基于 `session_key` 计算），攻击者因已持有 `session_key` 同样可以重新计算；若校验 `watermark.appid`/`timestamp`，攻击者可保留原水印或更新为合理值。只要 `session_key` 泄露，这些校验都不能阻止伪造。
- 成功后服务端按目标手机号找到对应用户并签发会话，攻击者获得该用户的全部业务权限与数据（企业信息、身份证、邮箱、银行账户等）。

## 触发条件

- 小程序使用“手机号快捷登录/绑定”流程，客户端提交 `encryptedData` + `iv`（可能还有 `signature`、`openId`），服务端用 `session_key` 解密。
- `session_key` 被返回给客户端、出现在响应/回调数据包、写入前端存储或日志。
- 服务端以解密出的手机号作为用户身份，且不校验手机号与当前 `openId` 的绑定关系，也不要求密文由微信侧生成。
- 攻击者能抓包改包（Burp/mitmproxy/Frida 等），并能从其他渠道获得目标手机号（例如同单位另一小程序的预约数据泄露）。
- 目标未对登录/绑定接口做频率限制或异常手机号变更检测。

## 利用步骤

1. 抓取小程序登录/手机号绑定请求，确认字段：`encryptedData`、`iv`、`signature`、`openId`，以及请求路径（如 `/api/applets/login`）。
2. 在登录流程的响应包或第二个数据包中寻找 `session_key`，同时记录 `iv` 与 `openId`；也可检查前端存储、日志、错误回显。
3. 用 `session_key` 作为 AES 密钥、`iv` 作为初始向量，AES-128-CBC 解密 `encryptedData`，确认明文结构含 `phoneNumber`、`purePhoneNumber`、`countryCode`、`watermark`。
4. 将 `phoneNumber` 与 `purePhoneNumber` 替换为目标手机号，保留/更新 `watermark`，按原 JSON 紧凑格式序列化。
5. 用同一 `session_key` 与新 IV（或原 IV）重新 AES-CBC 加密并 Base64 编码；若请求带 `signature`，用 `session_key` 重新计算。
6. 把新的 `encryptedData`（及 `iv`/`signature`）替换进登录请求并放行；服务端解密后按目标手机号登录，返回目标用户会话。
7. 验证是否进入目标账号（头像、姓名、单位、订单等），并评估可访问的敏感数据范围。
8. Burp 的 AppletPentester 等插件可把上述解密/改明文/重加密流程图形化；原文即用该插件完成。

## PoC

解密与重加密的核心逻辑（Python，示意）：

```python
import json, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

key = base64.b64decode(session_key)
iv  = base64.b64decode(iv)
ct  = base64.b64decode(encrypted_data)

plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
obj = json.loads(plain)
obj["phoneNumber"] = obj["purePhoneNumber"] = "13800000000"   # 目标手机号
new_plain = json.dumps(obj, separators=(",", ":")).encode()

new_iv = iv  # PoC 可复用原 IV；实际可用新的随机 16 字节 IV
new_ct = AES.new(key, AES.MODE_CBC, new_iv).encrypt(pad(new_plain, 16))
new_encrypted_data = base64.b64encode(new_ct).decode()
```

原请求形态（字段名以目标为准）：

```http
POST /api/applets/login HTTP/1.1
Content-Type: application/json

{"signature":"<sig>","encryptedData":"<base64>","iv":"<base64>","openId":"<openid>"}
```

把重加密后的 `encryptedData`、对应 `iv`（必要时重算的 `signature`）替换后提交，即可用目标手机号登录。

## 变体与关联

- 变体（泄露载体）：`session_key` 出现在登录响应、第二个业务数据包、前端本地存储、调试日志、错误信息中；也可能通过 `openId` + 弱绑定被间接利用。
- 变体（校验绕过）：服务端校验 `signature` 时，因 `session_key` 已泄露可重算；校验 `watermark.appid` 时可保留原水印；校验时间戳时可更新为当前时间。
- 变体（目标字段）：除手机号外，`encryptedData` 还可能包含昵称、头像、unionId 等；任意被服务端信任的字段都可能被改写。
- 关联：[[web-generic-auth-miniprogram-appointment-daterange-querytype-pii]]（同单位的预约数据泄露提供目标手机号，两链组合形成完整接管）。
- 关联：[[web-generic-auth-login-header-userid-token-binding-takeover]]（同为移动端登录接口信任客户端可控身份标识导致接管）。
- 关联：[[pentest-recon-mobile-app-traffic-shadow-asset]]（小程序/移动端流量与影子资产发现）。
- 边界：若服务端严格校验手机号与 `openId` 的绑定、或 `session_key` 从未离开服务端、或每次登录强制短信验证码，则本链不成立；不同小程序使用的加密字段/接口名可能不同。

## 检测与防御

- 根本修复：`session_key` 只在服务端保存与使用，任何响应、日志、前端存储都不得返回；对日志中的敏感字段做脱敏。
- 身份绑定：解密手机号后必须校验该手机号属于当前 `openId`/当前用户，不能把客户端提交的手机号直接当登录身份；首次绑定后以服务端绑定关系为准。
- 密文校验：校验 `signature`、`watermark.appid`、`watermark.timestamp` 与密文新鲜度；拒绝重复使用的 `encryptedData`/`iv`（防重放）。
- 会话安全：登录成功后签发服务端会话或短期令牌，敏感操作二次验证；手机号变更走独立验证流程并通知原用户。
- 检测：响应体/日志中出现 `session_key`；同一 `openId` 短时间内用不同手机号登录；解密失败率异常；登录请求中的 `encryptedData` 被替换但 `openId` 不变；同一手机号在多个 `openId` 下绑定。
- 运营：定期轮换 `session_key`；对小程序接口做速率限制与异常行为告警；敏感数据按最小权限返回。
