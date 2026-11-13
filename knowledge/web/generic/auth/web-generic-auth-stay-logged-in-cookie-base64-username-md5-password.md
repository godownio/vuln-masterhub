---
id: web-generic-auth-stay-logged-in-cookie-base64-username-md5-password
title: stay-logged-in Cookie 可预测：base64(username:md5(password)) 构造与离线口令爆破
type: scenario
domain: web
path: web/generic/auth
technique: predictable-remember-me-cookie-username-md5
aliases:
- stay-logged-in cookie
- remember me 可预测
- base64 用户名 md5 密码
- cookie 构造爆破
- 记住我 Cookie 伪造
tags:
- auth
- cookie
- remember-me
- predictable
- bruteforce
- base64
- md5
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:08:39+08:00'
  notes: 已对照原文与截图核对：stay-logged-in解码为wiener:51dc30ddc473d43a6011e9ebba6ca770(42/43/44图,MD5(peter)值正确)、Payload processing MD5->prefix carlos:->Base64(46)、命中6474 vs 194(47/48)均与卡片一致；与AES remember-me类卡非同链；未验证点：未复现
---

## 一句话结论

当站点 “stay-logged-in” Cookie 的内容是 `base64(username + ":" + md5(password))` 且服务端直接信任该 Cookie 时，攻击者可用自己的账号观察并推断格式，再对目标用户名构造候选口令的 Cookie（MD5→加前缀→Base64）批量请求，命中即无需口令接管账户。

## 原理

- Remember-me 机制本应使用服务端生成的高熵随机 token（可撤销、可绑定设备/过期），但有的实现把“用户名 + 口令哈希”确定性拼接后 Base64 放进持久 Cookie，服务端解码后按用户名取出口令哈希比对。
- 由于 token 只依赖用户名与口令，攻击者创建自己的账号即可看到 `base64("自己的用户名:" + md5("自己的口令"))`，从而推断出构造公式；无需源码即可复现。
- MD5 无盐且速度快：候选口令可离线计算哈希，或利用在线 MD5 反查库直接还原；命中后构造的 Cookie 与合法 Cookie 完全一致，服务端无法区分。
- Cookie 直接作为“已认证”凭据，等效于跳过登录流程；攻击者甚至不需要知道目标口令明文，只需得到匹配的 `md5(password)`。
- 若攻击者无法注册账号，也可通过 XSS/日志等方式窃取任意用户的 Cookie 后分析格式，或在开源框架中查到构建细节。

## 触发条件

- 应用提供 “Remember me / Stay logged in” 功能，持久 Cookie 形如 Base64 的确定性拼接。
- Cookie 内容包含用户名与口令哈希（或其他可预测字段），且服务端直接信任该 Cookie 完成登录。
- 目标用户名已知；攻击者能创建账号或获得任意一个合法 Cookie 用于推断格式。
- 目标账号的 Remember-me Cookie 可被替换使用（无设备绑定/额外签名）。

## 利用步骤

1. 用自己的账号勾选“记住我”登录，抓取响应中的 `stay-logged-in` Cookie。
2. Base64 解码，观察结构；本例得到 `wiener:51dc30ddc473d43a6011e9ebba6ca770`，前半为用户名，后半为 32 位十六进制（MD5）。
3. 验证假设：对已知口令做 MD5（本例 `peter` → `51dc30ddc473d43a6011e9ebba6ca770`），确认格式为 `username:md5(password)`。
4. 构造 Intruder 攻击：请求 `GET /my-account?id=<victim>`，把 `stay-logged-in` Cookie 设为变量；Payload 处理链配置为 `Hash: MD5 → Add prefix: <victim>: → Base64-encode`。
5. 用候选口令字典跑批，按响应长度/状态码筛选（命中通常返回 200 且长度明显大于失败，如 6474 vs 194）。
6. 用命中的 Cookie 直接访问账户页面，确认接管后停止测试。

## PoC

```text
# 原始 Cookie
stay-logged-in=d2libm...（Base64）
# 解码
wiener:51dc30ddc473d43a6011e9ebba6ca770
# md5("peter") = 51dc30ddc473d43a6011e9ebba6ca770
```

Burp Intruder Payload Processing（对每个候选口令）：

```text
1. Hash: MD5
2. Add prefix: carlos:
3. Base64-encode
```

```http
GET /my-account?id=carlos HTTP/1.1
Host: target
Cookie: stay-logged-in=<base64(carlos:md5(candidate))>; session=<own-session>
```

- 原文实测：构造出的某条 Cookie 返回 200、长度 6474，其余失败请求长度 194，浏览器带入该 Cookie 后直接显示 `Your username is: carlos`。

## 变体与关联

- 若 Cookie 中还包含时间戳等字段，可用自己账号多次登录对比变化规律后再构造。
- 无账号时可通过 XSS 窃取 Remember-me Cookie 分析结构（见 [[web-generic-auth-cookie-php-serialized-signature-forge]] 等 Cookie 伪造类卡片）。
- 与硬编码 AES Remember-me Cookie 不同，本条是完全无密钥、可离线计算的确定性结构；AES 类见 [[web-java-framework-spring-rememberme-aes-cookie-spel-injection]]。
- 边界：若服务端对 Cookie 做 HMAC 签名、绑定设备指纹或维护服务端 token 表，则无法直接构造。

## 检测与防御

- 检测：Cookie 中 `stay-logged-in`/`remember-me` 值 Base64 解码后呈现 `用户名:32位hex` 结构；同一账号 Cookie 在多设备/多次登录中可预测变化；异常 Cookie 直接访问账户页。
- 防御：Remember-me 使用服务端生成的高熵随机 token 并存储/签名（HMAC），设置过期、可撤销、绑定设备；不要将口令或其哈希放入 Cookie；Cookie 加 HttpOnly/Secure/SameSite；口令哈希加盐并采用慢哈希。
