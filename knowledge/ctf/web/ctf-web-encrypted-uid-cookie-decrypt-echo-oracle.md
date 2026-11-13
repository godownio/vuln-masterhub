---
id: ctf-web-encrypted-uid-cookie-decrypt-echo-oracle
title: 加密 uid Cookie 的解密回显接口当 oracle：替换为任意密文即可解出明文（动态 Flag）
type: scenario
domain: ctf
path: ctf/web
technique: encrypted-uid-cookie-decrypt-echo-oracle
aliases:
- uid 密文解密 oracle
- 解密回显接口
- Cookie 密文替换解密
- flagA 解密
- 解密机接口
tags:
- ctf
- web
- cookie
- encryption-oracle
- info-disclosure
- crypto-misuse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V527
  verified_at: '2026-11-11T15:07:10+08:00'
  notes: '已对照原文 content.md 与全部 31 张图核对。图14 登录响应 Set-Cookie uid=<密文> 与 flagA=<密文>、图15 响应头 X-Flag2: flag2{xHOpRP}、图16 GET /auth/uid 返回真实 UID（14xx58）、图17 将 uid Cookie 替换为 flagA 密文后同接口返回 flagA{aecxxx52}（长度15），与卡片描述完全一致。卡片原子（解密回显 oracle 单点技巧），与 web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery（CBC 位翻转伪造角色）、crypto-protocol-decrypt-reencrypt-oracle（协议重加密 oracle）、crypto-aes-ecb-byte-at-a-time-hidden-suffix-oracle（加密侧 oracle）均非同链。原文属 CTF 动态 Flag，无产品版本/CVE。PoC 未执行。保留。'
---

## 一句话结论

当登录后服务端把加密后的 UID 写进 `uid` Cookie，而某个接口读取该 Cookie、解密后把明文回显时，这个接口就是一个解密 oracle：把 `uid` 的值替换成任意目标密文（例如另一个 Cookie 中动态 Flag 的密文）再请求，服务端就会替你把该密文解成明文。

## 原理

- `uid` Cookie 是「加密后的身份标识」，服务端信任它并在类似 `/auth/uid` 的接口中解密后返回真实 UID（用于前端展示）。加密保证了机密性，但没有提供认证性——如果密文没有 MAC/AEAD 或签名校验，任何提交的密文都能被解密。
- 接口把解密结果直接作为响应正文返回，等于对外提供了一个「给我任意密文，返回明文」的服务；攻击者不需要知道密钥，只要拿到目标密文（本例动态 Flag 就存放在 `flagA` Cookie 中）。
- 与「伪造身份」不同：本技巧不要求能构造合法密文，只利用解密 + 回显；它说明「加密≠认证」，也说明把内部标识解密后原样返回是高危设计。
- 本例：登录接口响应同时下发 `uid=<密文>` 与 `flagA=<动态 Flag 密文>`；正常请求 `/auth/uid` 返回真实 UID；将 `uid` Cookie 值替换为 `flagA` 的密文后重放，响应变为 `flagA{aecxxx52}`。

## 触发条件

- 应用把用户标识、角色或其它敏感值以密文形式放在 Cookie/Header/URL 中，并在某接口解密后回显明文。
- 解密前不校验密文与当前用户绑定，也不校验完整性（无签名/无 MAC，或校验可绕过）。
- 目标密文与被替换字段使用同一算法与密钥（同一系统内通常如此）。
- 攻击者能拿到目标密文（如另一个 Cookie、响应头、页面源码）。

## 利用步骤

1. 登录抓包，观察 `Set-Cookie` 中的密文字段（如 `uid=...`）与前端随后调用的接口（如 `GET /auth/uid`）。
2. 正常请求该接口，确认响应是解密后的明文（如真实 UID）。
3. 找到目标密文（如动态 Flag 所在的 `flagA` Cookie 值）。
4. 将 `uid` Cookie 的值替换为目标密文，保留其余 Cookie 与请求头，重放请求。
5. 读取响应正文中的明文；如响应格式受限制，可尝试把目标密文放进其它会被解密回显的字段。

## PoC

```http
GET /auth/uid HTTP/1.1
Host: target
Cookie: uid=<目标密文>; flagA=<目标密文>

HTTP/1.1 200 OK
Content-Type: text/plain

flagA{aecxxx52}
```

说明：原文中 `uid` 与 `flagA` 均为加密值，将 `uid` 替换为 `flagA` 的密文后 `/auth/uid` 返回了解密后的动态 Flag。PoC 未在本机执行。

## 变体与关联

- 变体：回显点可能是「用户信息接口」「图形验证码解密」「日志/调试回显」「二维码内容解析」等；密文可能位于 Cookie、Header、URL 参数或 localStorage。
- 变体：若为 CBC 模式且接口对 padding 错误有不同响应，可进一步做 padding oracle；若为固定 IV/ECB，可做密文重放或块拼接。
- 关联：[[ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback]]（Cookie 身份可信问题）、[[ctf-web-client-aes-score-forgery-hardcoded-key-iv]]（客户端加密数据可被篡改/重放）。
- 边界：若密文带签名且服务端校验用户绑定，替换后会被拒绝；若接口只返回「成功/失败」而不回显明文，则不构成解密 oracle。

## 检测与防御

- 不要把解密后的标识或敏感值原样回显给客户端；身份展示应由服务端 session/数据库查询完成。
- 加密必须配合 MAC 或使用 AEAD（如 AES-GCM）并校验完整性；密文绑定用户 ID 与用途，拒绝跨字段复用。
- 对同一 Cookie 值被替换后的解密请求、解密失败与 padding 错误统一响应，避免形成 oracle。
- 安全测试：登录后收集所有密文 Cookie，逐一替换进会回显明文的接口，观察是否返回其它字段的明文。
