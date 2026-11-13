---
id: web-generic-auth-sso-subapp-register-mobile-identity-any-user-login
title: SSO 子应用绕过 SSO 自建 register 认证：仅校验手机号即签发 token 导致任意用户登录（含双层加密+sign 复刻绕过）
type: scenario
domain: web
path: web/generic/auth
technique: sso-subapp-register-mobile-identity-token-issuance
aliases:
- SSO 认证缺陷
- 子应用自建认证
- register 接口任意用户登录
- 手机号换 token
- 仅手机号认证
- SSO ticket 未使用
- SM4+AES 双层加密
- sign 复刻
tags:
- web
- sso
- authentication
- account-takeover
- token
- register
- sm4
- aes
- frontend-encryption
- sign
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V524
  verified_at: '2026-11-11T14:49:12+08:00'
  notes: 已对照原文与17张截图核对（全部经img_small降采样读取成功）：A域/sso/ticket 基于token+appId颁发ticketId、B域/sso/login?ticketId=返回data但后续请求未携带（HTTP history仅一条sso/login）、B域/auth/register请求响应均加密；SM4-ECB/hex（key硬编码，图09）解出{IdcardNo,userMobile,userName,openId}，响应解出{code,data:{effective,id,loginName,userPassword,xaccessToken}}；仅手机号需正确、身份证/姓名只校验格式（原文加粗结论）；userInfo再套AES-ECB/PKCS7（图12/14），PoC字段paperType/name/paperNum/phone与截图一致；sign=md5(md5(w+data)+8位随机串)与图15/17一致。已修正一处抓包头映射：原文正文称b=8位随机串、_=sign，但放大抓包核对显示失败请求b=86...c53、成功请求b=b3...cc06（随data变化），而_=Z38ZzxzS两次不变且等于原文Python示例的随机串b，故线上实际为b=sign、_=随机串；已将原理与PoC改为headers={b:sign,w:w,_:random8}并注明原文叙述与抓包相反，KB卡与staging草稿同步修改。原文无版本信息，未设affected_versions合理。dedup：sms-code-empty-field（验证码置空）、getTokenById（按userId签发）、identity-selection IDOR等均非同链；全库dup-scan无本卡pair。卡片原子、无重复，保留并verified。
---

## 一句话结论

当 SSO 子应用没有消费 SSO 下发的登录凭据（ticket 换取的 data 未被使用），而是用自己的 `/auth/register` 类接口按“身份证+姓名+手机号”认证并签发 token，且服务端实际只要求手机号正确（其余字段仅校验格式）时，攻击者只要知道任意用户手机号，就能调用该接口取得其 token，实现任意用户登录；即使事后给请求加 SM4/AES 双层加密与 MD5 sign 头，也可通过复刻前端 JS 继续利用。

## 原理

- **正常 SSO 流程**：A 应用（认证中心）根据用户 Token 与目标子应用 appId 颁发 `ticketId`，子应用 B 用 `ticketId` 向 A 换取 `data`（B 的授权访问凭据），B 应以此建立会话。
- **缺陷点**：抓包发现 B 只调用了 `sso/login?ticketId=...`，返回的 `data` 并未被后续请求携带——B 实际上走自己的认证系统（`/auth/register`），SSO 只完成了跳转，没有承担认证职责。集成不完整的 SSO 相当于把认证决定权下放给子应用。
- **register 接口的身份绑定错误**：接口以 `{IdcardNo, userMobile, userName, openId}` 作为登录/注册认证要素，返回 `{id, loginName, userPassword, xaccessToken}`。测试发现只有手机号必须正确，身份证与姓名只需格式正确，于是“手机号”成为唯一身份依据——知道手机号即可为该用户签发 token，攻击者无需其密码、身份证或姓名。
- **为什么会失败**：认证三要素本应验证“持有者就是本人”（如短信验证码、证件信息一致性），但服务端未对身份证/姓名做任何比对，也未要求验证码或密码，等于把身份查询当成了身份认证（认证与授权混用）。
- **修复绕过**：开发在接口上叠加了前端加密——请求/响应 SM4-ECB（hex 输出、硬编码 key），register 的 `userInfo` 字段再套一层 AES-ECB（PKCS7）；请求头携带 `b`（`sign`）、`w`（时间戳）、`_`（8 位随机串），`sign = md5(md5(w + data) + 随机8位串)`。原文正文按 JS 变量名叙述为 b=随机串、_=sign，但抓包中 `_` 头固定为 8 位随机串（与原文 Python 示例 `b='Z38ZzxzS'` 一致）、`b` 头值随 data 变化，故以抓包头名为准。这些算法与密钥都在浏览器 JS 中，可复刻生成合法请求，前端加密无法修复服务端认证缺陷。
- **定位要点**：站点 JS 分两层加载（A 网关按 appId 下发 + B 应用自有 JS），加密函数与 sign 算法分属不同 JS 文件；按 header 字段名 `sign` 搜索可快速定位。

## 触发条件

- 目标为 SSO 体系下的子应用，抓包显示 SSO 返回的凭据未被使用，或子应用存在独立的登录/注册/快速登录接口。
- 该接口以身份要素（手机号/身份证/姓名/邮箱）作为认证依据，且缺少验证码、密码或要素一致性校验（本例仅手机号必须正确）。
- 攻击者知道受害者手机号（常见于订单、公开资料、短信枚举），并能访问该接口。
- 修复后若仅增加前端加密/sign，仍满足“算法与密钥在前端可取”的条件。

## 利用步骤

1. 走一遍正常 SSO 流程，抓包记录：A 的 `/sso/ticket`（颁发 ticketId）、B 的 `/sso/login?ticketId=`（返回 data），观察后续请求是否携带该 data；若未使用，怀疑 B 有独立认证。
2. 浏览 B 的接口，寻找 `/auth/register`、`/auth/login`、`/user/register` 等；对比两个不同账号登录后的请求差异，发现 register 请求体含身份要素、响应返回 token。
3. 解密/还原请求与响应（本例 JS 为 SM4-ECB + hex）：在 JS 中搜索 `sm4Encrypt`/`decrypt` 与硬编码 key，确认算法参数；解密后得到 `{"IdcardNo":"...","userMobile":"...","userName":"...","openId":null}` 与 token 响应。
4. 构造受害者数据：将其手机号填入 `userMobile`，身份证/姓名按格式随便填，发送 register 请求；若响应返回该用户的 `xaccessToken` 即验证成立。
5. 用该 token 调用业务接口（如订单查询），确认取得受害者数据（本例可查订单记录），完成任意用户登录。
6. 若修复后接口加密变化：定位新增的 `userInfo` AES-ECB 层与 sign 头（`sign = md5(md5(timestamp + data) + random8)`），用 Python/Node 复刻 SM4、AES、MD5 与随机串，重新构造请求即可继续利用。
7. 最小化验证后停止，不批量遍历手机号。

## PoC

还原后的请求形态（字段与算法按目标替换；原文域名、key、token 已脱敏）：

```http
POST /api/<app>/auth/register HTTP/1.1
Host: <b-app-domain>
Content-Type: application/json

{"IdcardNo":"<任意格式合法值>","userMobile":"<受害者手机号>","userName":"<任意姓名>","openId":null}
# 请求体实际为 SM4-ECB(hex) 密文；响应同样加密，解密后应含：
# {"code":"1","data":{"effective":true,"id":"...","loginName":"...","xaccessToken":"<token>"}}
```

修复后（双层加密 + sign）的构造骨架：

```python
import hashlib, json, time, random, string
# sm4_encrypt / aes_ecb_encrypt：按扣出的 JS 复刻（SM4-ECB -> hex；AES-128-ECB/PKCS7 -> hex）
user_info = aes_ecb_encrypt(json.dumps({"paperType":"1","name":"","paperNum":"","phone":"<受害者手机号>"}))
data = sm4_encrypt(json.dumps({"userInfo": user_info, "openId": None}))
b = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
w = str(int(time.time() * 1000))
sign = hashlib.md5((hashlib.md5((w + data).encode()).hexdigest() + b).encode()).hexdigest()
headers = {"b": sign, "w": w, "_": b}   # 抓包头名：b=sign、w=时间戳、_=8位随机串（原文正文按 JS 变量名叙述为 b=随机串、_=sign，与抓包相反）
# POST data 到 register，响应 SM4 解密后取 xaccessToken
```

说明：原文在真实项目中通过上述方式用他人手机号获取了 token 并读取其订单记录，发现即上报未做批量测试；SM4 key、AES key 与具体域名均已打码，PoC 未在本会话执行。

## 变体与关联

- 变体：子应用自建认证接口若要求短信验证码，可结合短信码回显/空值绕过/撞库等；若要求密码，则退化为口令爆破。
- 变体：接口可能名为 `register`、`fastLogin`、`oneKeyLogin`、`loginByMobile`；认证要素可能只有手机号或邮箱。
- 关联：[[web-generic-auth-gettokenbyid-userid-token-issuance]]——同为“接口按参数签发 token”，但那条按 userId 未授权签发，本条按手机号认证签发。
- 关联：[[web-generic-auth-identity-selection-id-idor-any-user-login]]——服务端缺归属校验的另一种形态。
- 关联：[[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]、[[code-analysis-reverse-frontend-request-response-encryption-automation]]——前端加密复刻自动化；本条是“SM4+AES 双层 + MD5 sign”的实例。
- 边界：服务端校验身份证/姓名与手机号一致性、要求短信验证码或密码、token 绑定设备指纹时，仅凭手机号不成立；加密若改为服务端一次性密钥且不可复用，复刻难度上升。

## 检测与防御

- 修复：子应用必须消费 SSO 下发的凭据并以其建立会话，不得另建一套弱认证；register/快速登录接口需校验身份要素的真实性（短信验证码、密码或权威源比对），不能把“查询到该用户”当作认证。
- 加固：token 绑定会话与设备、短有效期；敏感接口（订单、账单）做对象级授权；前端加密仅作传输保护，不得作为安全边界。
- 检测：同一 IP/设备在短时间内用不同手机号调用 register；register 请求中身份证/姓名与手机号不匹配但成功签发 token；SSO 流程中 ticket 换取 data 后未使用、随后直接调用自有认证接口的异常序列；sign/加密参数格式与正常前端不一致的自动化请求。
- 响应：发现后立即下线或收紧该接口，吊销异常签发的 token，评估被登录账户范围并通知用户。
