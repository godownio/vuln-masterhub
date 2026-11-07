---
id: web-generic-auth-login-bruteforce-response-payload
title: 登录爆破的响应判读与 Payload 变换：过滤差异、Base64/MD5/前缀与动态时间戳
type: scenario
domain: web
path: web/generic/auth
technique: login-bruteforce-response-and-payload-transform
aliases:
- 登录爆破
- 响应长度过滤
- Burp Intruder 过滤失败响应
- payload processing Base64 MD5
- 动态时间戳爆破
- getpasshash
tags:
- auth
- bruteforce
- burp
- yakit
- user-agent
- password
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:25+08:00'
  notes: 已对照 50 张截图核对长度/状态码/Location 过滤、Base64/MD5/前缀、getpasshash 与 JSON→Base64→MD5、Yakit 热加载时间戳；未验证点：未在本机复现，合并了多关卡通用手法
---

## 一句话结论

登录接口可被反复尝试时，先用错误凭据建立“失败基线”，再按响应长度、状态码、跳转 `Location`、错误文本或响应时间筛选出成功响应；如果前端对密码做了 Base64、MD5、前缀拼接或 JSON→Base64→MD5 等变换，就在爆破工具的 payload processing 中复现同样的变换，动态参数（如时间戳）则用热加载脚本在发送前生成。

## 原理

- 大多数登录接口对失败请求返回统一页面，但成功请求往往在响应长度、状态码（200/302）、`Location` 跳转目标、错误文案或响应时间上不同。直接看原始响应会被大量噪声淹没，需要用过滤器把失败基线排除。
- 前端加密/哈希只是把明文密码在浏览器里变换后再提交；服务端校验的是变换后的值。攻击者只要复现同一变换，就能继续用常见弱口令字典爆破。常见形式：Base64 编码、MD5 哈希、固定前缀/后缀拼接、隐藏字段（如 `getpasshash`）承载哈希、`JSON.stringify → Base64 → MD5` 链。
- 某些请求还带动态参数（时间戳、随机数、签名）。如果校验只要求“格式正确/时间接近”，可在爆破工具的请求模板中用 `{{yak(genTS|dummy)}}` 之类占位，由热加载脚本在每次发送前生成当前时间戳。
- 过滤失败响应的常见维度：状态码（排除 2xx 以外的固定失败码）、响应长度（排除基线长度）、关键字（排除 “Login Failed”/“密码错误”）、`Location`（排除跳回登录页的 302）。成功响应通常是不在排除集合里的少数项。

## 触发条件

- 登录接口没有有效限速/锁定，或限速可绕过（见关联卡）。
- 攻击者知道或能枚举出有效用户名，或可以对用户名+密码同时爆破。
- 前端变换逻辑可复现（JS 可读、哈希算法标准、盐/前缀固定或可获取）。
- 字典可用（弱口令 top1000、业务相关口令等），且目标允许足够请求量。

## 利用步骤

1. 用一组错误账号/密码发送请求，记录失败响应的状态码、长度、错误文本、`Location`。
2. 用正确账号（或已知有效账号）对比成功响应，找出稳定差异；没有已知账号时，先做用户名枚举。
3. 选择攻击模式：单参数用 Sniper，用户名+密码用 Cluster bomb，固定用户名+密码用 Sniper；需要一一对应时用 Pitchfork。
4. 若密码被编码/哈希，在 Payload processing 中添加 Base64/MD5/前缀/自定义脚本；若参数是整段 JSON 的哈希，复现 `JSON.stringify → Base64 → MD5`。
5. 若请求带时间戳/随机数，在模板中放占位符，用 Yakit 热加载或 Burp 插件生成动态值。
6. 用过滤器排除失败响应（长度/状态/关键字/Location），按剩余结果验证登录。
7. 成功后立即停止并保存证据；避免触发账号锁定或业务告警。

## PoC

Base64 密码：

```text
POST /login HTTP/1.1
username=admin&password=<base64(password)>
```

MD5 密码：

```text
POST /login HTTP/1.1
username=admin&password=<md5(password)>
```

固定前缀：

```text
username=admin&password=godxing%40<password>
```

隐藏哈希字段（前端 `md5(password)` 写入 `getpasshash`）：

```text
username=admin&password=123456&getpasshash=<md5(123456)>
```

JSON→Base64→MD5（前端 `md5(btoa(JSON.stringify({username,password})))`）：

```text
POST /login HTTP/1.1
Content-Type: text/plain

<md5(base64('{"username":"admin","password":"<password>"}'))>
```

Yakit 动态时间戳占位：

```text
timestamp={{yak(genTS|dummy)}}
```

```go
genTS = func(p) {
    ts = time.Now().Unix()
    return sprint(ts)
}
```

Burp 过滤失败响应（示意）：状态码只保留 200/302，长度排除基线值，关键字排除 `Login Failed`，`Location` 排除 `/login.html`。

## 变体与关联

- 变体：用户名也做编码/哈希；密码加随机盐时需先从前端 JS 或接口获取盐。
- 变体：验证码/滑块存在时，先评估验证码是否可复用、可识别或可绕过，再爆破。
- 变体：成功响应返回 token/Set-Cookie，可直接用于后续越权测试。
- 关联：[[web-generic-auth-login-rate-limit-bypass-cookie-xff]]（限速/封禁绕过）。
- 关联：[[web-generic-auth-username-enumeration-timing-lockout]]（先枚举有效用户名）。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（2FA 验证码爆破）。
- 注意：爆破会产生大量请求，必须在授权范围内并控制速率；不要把“响应长度不同”直接等同于成功，需用已知正确/错误样本校验过滤器。

## 检测与防御

- 防御：服务端限速（按账号+IP+设备指纹）、渐进式延迟、验证码、MFA；失败响应统一长度/文案/状态码，避免可区分。
- 防御：密码在前端哈希不能替代 TLS 与服务端哈希；服务端仍要用强哈希（bcrypt/Argon2）存储，且不要用可预测盐。
- 防御：对同一账号的失败次数做锁定/告警，对分布式来源做风控；不要只按 `PHPSESSID` 或可伪造的 `X-Forwarded-For` 计数。
- 检测：同一 IP/账号短时间大量 401/403；响应长度/状态码分布异常；`User-Agent` 为空或工具特征；登录失败后立即出现成功；WAF 记录高频 `/login` 请求。
