---
id: web-generic-auth-sms-code-md5-hash-response-offline-bruteforce
title: 短信登录校验用 md5(手机号+6位验证码) 且响应回显哈希：离线爆破 100 万空间任意用户登录
type: scenario
domain: web
path: web/generic/auth
technique: sms-code-md5-hash-response-offline-bruteforce
tags:
- web
- auth
- sms
- otp
- md5
- bruteforce
- account-takeover
- logic-flaw
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 微厦在线学习考试系统 2.0
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:49:54+08:00'
  notes: V262 重核：对照正文与24图，login.js 前端校验 obj.vcode != md5(phone+sms)、发码响应 POST /api/v2/Sms/SendLoginVcode 的 result 回显 MD5、离线爆破命中 104270、随后成功登录均一致；dedup 两个 likely_duplicate（明文回显/多号码共用）机制不同，理由成立；dup-scan 无本卡 pair。affected_versions 按 LICENSE.txt 软件版本 2.0 设为微厦在线学习考试系统 2.0（原文未给修复版本）。
url: /docs/web/generic/auth/web-generic-auth-sms-code-md5-hash-response-offline-bruteforce/
draft: false
kb_aliases:
- 短信验证码哈希爆破
- md5(手机号+验证码)
- 验证码 result 泄露
- 前端校验验证码绕过
- 离线爆破六位验证码
---

## 一句话结论

短信登录的前端校验规则是 `md5(手机号 + 6 位验证码) == 响应包里的 result`，而 `result` 会随发码响应直接返回；手机号已知、验证码只有 6 位（10^6 空间），攻击者对 `000000-999999` 离线计算 MD5 即可还原验证码，再以“目标手机号 + 该验证码”登录任意账号。

## 原理

- 短信验证码本应只在服务端生成、经短信通道下发并在服务端校验；任何把验证码或“可逆推出验证码的校验量”返回给客户端的实现，都破坏了“持有手机”这一认证因子。
- 目标系统的 `login.js` 中有：

```javascript
let storage = 'login_sms_seconds';
var obj = $api.storage(storage);
if (obj == undefined) return this.tips('sms', false, '请发送验证码');
if (obj.expires <= new Date()) return this.tips('sms', false, '验证码过期');
if (obj.vcode != $api.md5(form.phone + form.sms)) return this.tips('sms', false, '验证码不正确');
```

  即客户端保存的 `vcode` 是 `md5(手机号 + 验证码)`，前端仅做本地比对，真正的登录请求仍把明文 `phone + sms` 发给服务端。
- 发码响应（`POST /api/v2/Sms/SendLoginVcode`）的 `result` 字段就是该 MD5。攻击者拿到 `result` 后，手机号是已知固定前缀，只需枚举 6 位数字计算 MD5 比对，即可在本地还原验证码；整个过程不触发登录接口，天然绕过登录失败次数/短信发送频率限制。
- 之所以可行：MD5 无盐、输入空间仅 10^6、验证码没有一次性绑定到服务器端会话（或绑定但客户端持有同一校验量）；离线爆破在普通机器上秒级完成。

## 触发条件

- 目标提供手机号+短信验证码登录，发码接口或任意响应中返回 `md5(手机号+验证码)` 或类似可离线枚举的校验值。
- 验证码为 6 位纯数字（4 位更易），手机号已知/可枚举；校验值无盐或盐值可预测。
- 登录接口接受“手机号+明文验证码”直接签发会话，且不要求验证码必须由同一会话/同一请求发起，或攻击者先请求一次码即可获得有效码。
- 目标账号允许短信登录（未注册手机号也可能被自动创建/登录）。

## 利用步骤

1. 对目标手机号请求短信登录验证码，抓取发码响应，取出 `result`（即 `md5(手机号+验证码)`）。
2. 用已知手机号作前缀，枚举 `000000-999999`，逐个计算 `md5(前缀+code)` 与 `result` 比较。
3. 命中后取候选串后 6 位即验证码（原文实测命中 `18*******104270`，验证码为 `104270`）。
4. 向登录接口提交 `phone=目标手机号&sms=还原出的验证码`，服务端校验通过后签发会话，即登录为目标账号。
5. 登录后可继续访问个人信息/后台接口；原文随后结合账号 IDOR 控制了近万条账号。

## PoC

原文 PoC（Python 3，离线爆破）：

```python
import hashlib

prefix = "18xxxxxxx29"          # 目标手机号
target_hash = "xxxxxxxxxxxxxxxxxxxxxxxxx"  # 发码响应中的 result

for i in range(1000000):
    code = f"{i:06d}"
    if hashlib.md5((prefix + code).encode()).hexdigest() == target_hash:
        print(f"[+] Found match: {prefix}{code}")
        break
else:
    print("[-] No match found.")
```

原文运行结果命中 `18*******104270`，随后用该验证码成功登录（发码响应、爆破结果、登录成功均有截图）。

## 变体与关联

- 若响应回显的是明文验证码，见 `web-generic-auth-sms-code-echo-response-arbitrary-login`；本卡是回显“可离线爆破的哈希”，不需要服务端回显明文。
- 若验证码在多个手机号间共用/固定，见 `web-generic-auth-sms-code-multi-number-shared-arbitrary-login`。
- 变体：`md5(phone+code)` 换成 SHA1/HMAC（盐泄露）、4 位码、时间戳参与但可枚举、验证码未绑定手机号等；也可结合短信轰炸/并发接口放大。
- 关联：登录后横向利用账号 IDOR/未授权接口（同文章后续链）。

## 检测与防御

- 验证码只在服务端生成与校验；任何响应都不得返回验证码、其哈希或可离线枚举的校验量。
- 校验值使用服务端密钥的 HMAC（如 `HMAC(secret, phone+code+nonce)`）并设置短有效期、一次性使用；不要用无盐 MD5。
- 登录/校验接口做频率限制、失败次数锁定、设备/会话绑定；验证码尝试次数用尽即失效。
- 前端校验只能作为体验优化，不能作为安全边界；服务端必须重新校验手机号、验证码、有效期与用途。
- 监控：同一 IP/设备对发码接口高频请求、随后对登录接口提交不同手机号；发码响应体中出现 32 位十六进制哈希字段可作为审计线索。
