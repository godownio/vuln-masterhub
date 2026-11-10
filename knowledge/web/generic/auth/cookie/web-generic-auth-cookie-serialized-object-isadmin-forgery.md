---
id: web-generic-auth-cookie-serialized-object-isadmin-forgery
title: Cookie 中 PHP 序列化对象未签名可篡改 isAdmin 字段实现越权
type: scenario
domain: web
path: web/generic/auth/cookie
technique: serialized-cookie-tampering
aliases:
- 序列化 Cookie 越权
- PHP 对象 Cookie 伪造
tags:
- php
- cookie
- serialization
- auth-bypass
- privilege-escalation
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:02:45+08:00'
  notes: 已对照原文核对：cookie URL解码序列化串与isAdmin b:0改b:1响应返回flag证据图齐全（img03/04）；dedup确认与签名伪造卡不同链（本卡无签名保护）
---

## 一句话结论

服务端把登录身份存为 URL 编码的 PHP 序列化对象且无签名校验时，把 Cookie 中 `isAdmin;b:0` 改为 `b:1` 即可从 guest 越权为 admin。

## 原理

服务端用 `unserialize($_COOKIE['user'])` 还原身份对象（如 Admin{name,isAdmin}），权限判断仅依赖对象内 isAdmin 属性；Cookie 未附加 HMAC 签名、也未与服务端会话绑定，客户端可任意改写。序列化格式中布尔值以 `b:0`/`b:1` 表示，改一字节即可翻转权限位，无需构造任何漏洞利用链。

## 触发条件

- Cookie 值 URL 解码后形如 `O:5:"Admin":2:{s:4:"name";s:5:"admin";s:7:"isAdmin";b:0;}`；
- 服务端直接 unserialize 后依据对象属性做权限判断，无签名/加密完整性保护。

## 利用步骤

1. 抓包获取 Cookie:user，URL 解码得到序列化字符串；
2. 将 `s:7:"isAdmin";b:0` 中的 0 改为 1（可将 name 同步改为 guest 以保持 user 一致性），重新 URL 编码回填；
3. 重放请求，响应返回 admin 身份内容（原文实测返回 FLAG）。

## PoC

```
Cookie: user=O%3A5%3A%22Admin%22%3A2%3A%7Bs%3A4%3A%22name%22%3Bs%3A5%3A%22guest%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A1%3B%7D
```

明文为 `O:5:"Admin":2:{s:4:"name";s:5:"guest";s:7:"isAdmin";b:1;}`，原文实测以 guest+isAdmin=1 拿到 flag。

## 变体与关联

- 与基于默认密钥伪造签名 Cookie 的场景互补：本场景连密钥都不需要，属于"只加密不认证/完全不保护"的最弱形态；
- 若 Cookie 同时有 base64/URL 编码层，先解码再改再编码；
- 深层变体是利用 str_replace 长度变化的序列化逃逸，需要注入更复杂属性时使用。

## 检测与防御

- 检测：Cookie 中出现 `O:\d+:"`、`s:\d+:` 等序列化特征即告警。
- 防御：身份信息只存服务端 session；必须在 Cookie 存数据时加 HMAC 签名或用加密 cookie；禁止 unserialize 不可信输入（改用 json_decode）。
