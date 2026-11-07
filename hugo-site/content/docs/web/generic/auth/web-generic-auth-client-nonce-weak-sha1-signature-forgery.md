---
id: web-generic-auth-client-nonce-weak-sha1-signature-forgery
title: 客户端 nonce + 无密钥 SHA1 签名可复现，绕过防重放伪造请求
type: scenario
domain: web
path: web/generic/auth
technique: client-nonce-weak-signature-forgery
tags:
- web
- auth
- api
- signature
- sha1
- nonce
- anti-replay
- javascript-reverse
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:02:32+08:00'
  notes: 已对照原文与图04/09/10/14/15核对：nonce 为 UUID v4（a[6]&15|64、a[8]&63|128）去横线 32 hex；待签名串 d 实际为 data={...}&nonce=...&timestamp=...，appKey/appSecret 未参与；Python 复算后替换字段，图15 返回 200。卡中 AES 仅作边界说明，原文未展开。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/auth/web-generic-auth-client-nonce-weak-sha1-signature-forgery/
draft: false
kb_aliases:
- nonce 防重放绕过
- sign 伪造
- SHA1 签名复现
- 前端签名逆向
- 无密钥签名
- 全数据包加密绕过
---

## 一句话结论

API 的 `nonce`/`timestamp` 由客户端生成、`signature` 只是对 `data`+`nonce`+`timestamp` 做 SHA1 且没有使用任何服务端密钥时，攻击者只要从前端 JS 复刻字段格式与哈希算法，就能为任意篡改后的请求生成新 nonce 和合法签名，绕过“防重放”并伪造请求。

## 原理

- 防重放的安全前提是：nonce 由可信方生成或至少绑定会话，服务端记录已用 nonce 并拒绝重复。若 nonce 完全由客户端生成、服务端只检查“这个 nonce 没见过”，攻击者每次自造一个新的合法格式 nonce 即可，防重放退化为“不能原样重发”。
- 签名算法的安全前提是：签名必须依赖只有服务端知道的密钥（HMAC/私钥），且覆盖方法、路径、业务参数、时间戳、nonce 与 body。若签名只对公开字段做裸哈希，任何人都能重算。
- 本例中前端 `dn()` 生成 `nonce = Ge().replaceAll('-','')`（UUID v4 去掉横线，32 位 hex）和毫秒时间戳；`un(i,r,e,t,s)` 把 `appKey`、`appSecret`、`nonce`、`timestamp`、`data` 放入对象，用带 key 排序、禁用 URL 编码的序列化得到待签名串，最后交给 `xo()` 做哈希。
- 调试器里待签名串 `d` 的实际值为：
  `data={"page":1,"size":10,"tenantId":1488}&nonce=<32hex>&timestamp=<ms>`
  也就是说 `appKey`/`appSecret` 没有进入签名，哈希算法从输出 40 位 hex 可判定为 SHA1。签名不含密钥，等价于公开校验和。
- 因此攻击链是：重放被 nonce 拒绝 → 逆向前端 nonce 生成 → 逆向签名拼接与哈希 → 在 Python 中为新 nonce/时间戳/篡改后的 body 重新计算签名 → 通过校验。
- 报文整体 AES 加密只是传输层混淆：密钥与算法若在前端 JS 中，仍可被提取并复现；它不提供真实性，也不能替代服务端密钥签名。本例原文未展开 AES 细节，本卡只把“加密不改变可伪造性”作为边界说明。
- AI 在这里的作用是加速 JS 到 Python 的翻译和哈希算法推断（例如按 40 位输出猜 SHA1），不是漏洞根因；根因仍是客户端可控的 nonce 与无密钥签名。

## 触发条件

- API 请求包含 `nonce`/`timestamp`/`signature` 等字段，且前端 JS 可读、未做代码混淆到不可逆的程度。
- 服务端对 nonce 只做唯一性/格式校验，未绑定会话或未持久化已用值；时间戳窗口可被新时间戳满足。
- 签名算法只使用请求中可见的字段，未使用服务端独占密钥，或把密钥硬编码在前端 JS 中。
- 若 body 被 AES 加密，攻击者能从 JS 提取密钥、IV、模式与填充方式（或通过调试器直接调用前端加密函数）。
- 攻击者持有有效会话/Token（若接口需要登录），并能访问目标 API。

## 利用步骤

1. 抓包重放原请求，确认返回 `check nonce replay` 之类的防重放错误，记录 `nonce`、`timestamp`、`signature` 字段。
2. 在 F12 Sources 中全局搜索 `nonce`、`signature`、生成函数名，打断点跟进；记录 nonce 的生成逻辑（本例为 UUID v4 去横线）与签名前的拼接格式。
3. 在断点处查看待签名串 `d` 的实际内容，确认字段顺序、JSON 排序规则、是否包含 appKey/appSecret。
4. 用输出长度/已知样本验证哈希算法（40 位 hex → SHA1 候选），用 Python 复算一次已知请求，确认与抓包 signature 一致。
5. 修改业务参数，生成新的 nonce 与毫秒时间戳，按相同规则重算 signature；若 body 加密，先用提取的 AES 参数加密新 body。
6. 替换四个字段后重发，确认业务成功；随后可批量伪造/篡改请求。

## PoC

nonce 与签名复刻（Python，示意）：

```python
import hashlib, json, os, time

def generate_nonce() -> str:
    # UUID v4：16 随机字节，设置版本位与变体位，去掉 '-'
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".replace("-", "")

def generate_signature(data_obj, nonce, timestamp):
    # data 需与前端序列化一致：key 按字母序、不 URL 编码、紧凑 JSON
    data_str = json.dumps(data_obj, separators=(",", ":"), sort_keys=True)
    input_str = f"data={data_str}&nonce={nonce}&timestamp={timestamp}"
    return hashlib.sha1(input_str.encode("utf-8")).hexdigest()

body = {"page": 1, "size": 10, "tenantId": 1488}
nonce = generate_nonce()
timestamp = int(time.time() * 1000)
sign = generate_signature(body, nonce, timestamp)
print(nonce, timestamp, sign)
```

请求字段替换：

```http
POST /api/... HTTP/1.1
Host: target
Content-Type: application/json
X-Tenant-Header: 1488
Authorization: Bearer <token>
Nonce: <新 32 位 hex>
Timestamp: <新毫秒时间戳>
Signature: <重算的 SHA1>
```

若响应/请求体整体 AES 加密，则把明文 body 用前端同款 AES 参数加密后再发送；签名按明文 body 计算（以实际前端顺序为准，需先在断点确认）。

## 变体与关联

- nonce 变体：UUID v4、随机 hex、时间戳+随机数、递增计数器。只要能生成“格式合法且未用过”的值，且服务端不绑定会话，就能绕过唯一性检查。
- 签名变体：`data&nonce&timestamp` 裸 SHA1（本例）、MD5、拼接顺序不同、包含/不包含 appKey；若密钥硬编码在前端，同样可提取后伪造。
- 传输变体：全报文 AES/SM4/自定义异或；密钥在前端即视为公开，逆向或直接调用前端加密函数均可复现。
- 关联：[[web-generic-auth-api-signature-validation-differential-test]]（先判断签名是否真的被校验；本卡处理“确实校验但算法可伪造”的情况）；[[web-generic-auth-cookie-base64-identity-forgery]]（另一类客户端可信数据被伪造的认证缺陷）。
- 边界：服务端使用仅自己持有的 HMAC 密钥、nonce 绑定会话并持久化、时间戳窗口严格、AES 密钥由服务端下发/轮换时，本手法不成立。

## 检测与防御

- 检测：同一账号短时间出现大量格式合法但从未见过的 nonce；签名正确但请求体参数与正常业务分布不符；请求节奏呈脚本化；前端 JS 中出现 `appSecret`、AES key、`signature` 拼接逻辑。
- 防御：签名改用服务端独占密钥的 HMAC-SHA256（或非对称签名），覆盖 method、path、query、body hash、timestamp、nonce；密钥绝不下发前端。
- 防御：nonce 由服务端签发或绑定会话，服务端缓存已用 nonce 并设置 TTL；时间戳窗口收窄；常量时间比较；对重放/异常 nonce 告警。
- 防御：全报文加密不能替代签名与 TLS；把 AES 密钥放前端只增加逆向成本，必须配合服务端真实性校验。
