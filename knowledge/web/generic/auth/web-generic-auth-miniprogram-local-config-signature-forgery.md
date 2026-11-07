---
id: web-generic-auth-miniprogram-local-config-signature-forgery
title: 小程序本地加密配置 + 固定 AES 密钥：恢复 appKey 后伪造 HMAC 请求签名
type: scenario
domain: web
path: web/generic/auth
technique: miniprogram-local-config-signature-forgery
aliases:
- 小程序签名伪造
- 本地加密配置恢复
- 固定 AES 密钥解配置
- appKey 泄露
- HMAC-SHA256 Authorization 伪造
- 客户端签名边界失效
tags:
- miniprogram
- javascript
- client-side-crypto
- signature-forgery
- hmac
- aes
- auth-bypass
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V62
  verified_at: '2026-11-05T12:50:48+08:00'
  notes: 已对照原文与图01-04核对：/payurl 请求头 Authorization 含 appId/Timestamp/Nonce/Signature；JS 中 Authorization = getAuthorization(body, appId, appKey, 'post') 本地生成；CONFIG.data 为密文、用本地固定 AES 密钥解密得到 appId/appKey；签名流程为紧凑 JSON+SHA256+appId+timestamp+nonce+bodyHash 的 HMAC-SHA256+Base64；Python 重签脚本输出 Authorization/Content-Length/Body，与卡一致。未验证点：appId/appKey 已脱敏，原文签名函数以伪代码呈现；PoC 未复跑；原文未标注产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

小程序把签名所需的 `appId`/`appKey` 以“本地密文配置 + 本地固定 AES 密钥”的形式打包在客户端，攻击者反编译小程序包即可离线解密出 `appKey`，再按 `HMAC-SHA256(appKey, appId+timestamp+nonce+sha256(body))` 本地重算 `Authorization`，从而伪造任意业务请求。

## 原理

- 小程序前端在发请求前本地调用签名函数：`Authorization = getAuthorization(body, appId, appKey, "post")`，说明签名能力不在服务端，而是随客户端分发。
- 配置不是明文，但解密密钥也硬编码在客户端：`AES_ECB_Decrypt(CONFIG.data, "固定字符串")` → JSON，得到 `appId`、`appKey`、`wxAppId`、回调地址等。密文与密钥同处客户端，等同于明文。
- 签名算法为标准 HMAC：先把请求体序列化为紧凑 JSON（无空格、固定键序），做 SHA256 得到 hex；拼接 `appId + timestamp + nonce + bodyHash`；用 `appKey` 做 HMAC-SHA256；最后 Base64。
- 因为算法、密钥、时间戳/随机数生成方式都可复现，攻击者可以离线构造任意 body 的合法签名，不依赖官方客户端，也不需要服务端下发一次性签名。
- 这类设计把“签名”当成了混淆手段而非安全边界：只要密钥在客户端，签名的完整性保护就等价于没有。

## 触发条件

- 客户端（小程序/App/Web JS）本地计算请求签名，签名密钥或可解密密钥随包分发。
- 配置以本地密文形式存在，但解密密钥硬编码/可推导。
- 服务端只校验签名，不额外绑定用户会话、订单状态或金额。
- 时间戳/nonce 只做简单校验（甚至不校验重放），攻击者可自由生成。

## 利用步骤

1. 抓包定位统一支付/业务接口，观察 `Authorization` 头与请求体字段。
2. 反编译小程序包（如 `wxapkg` 解包），搜索 `getAuthorization`、`appKey`、`appId`、`AES`、`CONFIG` 等关键字。
3. 找到配置解密逻辑，提取密文与固定密钥，离线解密：
   ```javascript
   const plain = AES_ECB_Decrypt(CONFIG.data, fixedKey);
   const cfg = JSON.parse(plain); // { appId, appKey, ... }
   ```
4. 还原签名函数，确认序列化方式（紧凑 JSON、键序）、哈希算法、拼接顺序与编码。
5. 编写脚本对修改后的 body 重算签名：
   ```python
   body_json = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
   body_hash = hashlib.sha256(body_json.encode()).hexdigest()
   raw = f"{APP_ID}{timestamp}{nonce}{body_hash}".encode()
   signature = base64.b64encode(hmac.new(APP_KEY.encode(), raw, hashlib.sha256).digest()).decode()
   ```
6. 把新的 `Authorization`、`Content-Length`、标准化 body 回填到 Repeater 重放，验证业务接口接受。

## PoC

```python
import base64, hashlib, hmac, json

def canonical_json(data):
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

def build_signature(body, app_id, app_key, timestamp, nonce):
    body_json = canonical_json(body)
    body_hash = hashlib.sha256(body_json.encode("utf-8")).hexdigest()
    raw = f"{app_id}{timestamp}{nonce}{body_hash}".encode("utf-8")
    return base64.b64encode(
        hmac.new(app_key.encode("utf-8"), raw, hashlib.sha256).digest()
    ).decode("ascii")

body = {"totalAmount": 10, "mchntOrderId": "...", "...": "..."}
print(build_signature(body, APP_ID, APP_KEY, "20260428171049", "6029186847"))
```

```text
# 请求头示例
Authorization: appId="...",Timestamp="20260428171049",Nonce="6029186847",Signature="...=="
```

## 变体与关联

- 变体：AES-CBC + 固定 IV、XOR/RC4、Base64 多层编码、WebAssembly 实现；密钥可能藏在 JS bundle、`app-config.js`、云函数配置或本地存储中。
- 变体：签名算法换成 MD5/SHA1/RSA；若为 RSA，检查私钥是否也在客户端。
- 变体：即使 `appKey` 不在客户端，若签名只覆盖部分字段（如不覆盖金额），仍可篡改未签名字段。
- 关联：[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（无密钥/弱签名伪造）、[[web-generic-payment-amount-tamper-no-order-binding]]（签名伪造后的金额篡改）。
- 边界：密钥由服务端动态下发且绑定设备/会话、签名覆盖全部业务字段、时间戳/nonce 严格防重放、或使用 mTLS/硬件密钥时，伪造失败。

## 检测与防御

- 检测：同一账号/设备在短时间内用不同 timestamp/nonce 重放请求；签名正确但业务字段异常（金额、订单号）；客户端包中出现 `appKey`/固定 AES 密钥；请求来源非官方客户端。
- 修复：签名密钥只保存在服务端（HSM/KMS），客户端改为调用服务端签名接口或使用短期、绑定用户/订单的 token；不要把 `appKey` 或可解密密钥打进客户端。
- 加固：签名覆盖全部关键字段（含金额、订单号、回调地址）；严格校验 timestamp/nonce 防重放；服务端二次校验金额与订单；对客户端做完整性校验与加固（仅提高成本，不能替代服务端信任边界）。
