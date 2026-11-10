---
id: web-generic-auth-sms-4digit-code-bruteforce-arbitrary-registration
title: 4 位短信验证码无尝试次数限制：爆破验证码注册任意手机号账号
type: scenario
domain: web
path: web/generic/auth
technique: sms-4digit-code-bruteforce-arbitrary-registration
aliases:
- 短信验证码爆破
- 4 位验证码爆破
- 任意用户注册
- 任意手机号注册
- 短信验证码可爆破
- 注册验证码爆破
tags:
- web
- auth
- sms
- verification-code
- bruteforce
- registration
- burp
- logic-flaw
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T05:27:25+08:00'
  notes: 已对照全文与43图核对：图28短信均为4位码（5045/4835/1385/0117）；图29 Payloads含@/+86/逗号等；图30 Intruder Numbers 999-9999，7774长度374、失败342；图32-37注册任意手机号12313245678，Intruder命中3503（长度303）并进入个人中心显示该号码。已修正原文对两案例长度/命中码的混淆（7774=374，3503=303）。0x6爆破与0x7任意注册合并为同一'4位码无次数限制'原子，可接受。dedup仅与APP 6位码爆破等related；dup-scan无本篇pair。未复现。
---

## 一句话结论

注册接口的短信验证码只有 4 位数字，且没有按手机号/会话限制失败次数，攻击者对一个自己并不持有的手机号触发验证码后用 Burp Intruder 穷举 999–9999，即可猜中验证码并完成注册，形成任意手机号账号注册。

## 原理

- 短信验证码的认证语义是“证明请求者持有该手机号”。4 位数字的空间只有约 9000（1000–9999）或 10000 种，若服务端不限制单次验证码的尝试次数，穷举成本极低。
- 注册流程一般分两步：先向手机号发送验证码，再提交手机号、验证码、密码等完成注册。若第二步只比对“手机号 + 验证码”，没有失败计数、锁定、延迟或验证码一次性失效，攻击者就可以对同一个验证码反复提交候选值。
- 攻击者并不需要持有目标手机号：验证码会发送到目标号码，但攻击者只需在自己的请求里不断尝试该号码对应的 4 位码；一旦命中，服务端就按该手机号创建账号。
- 成功与失败响应通常在长度、状态码、跳转或提示文案上有差异。文章案例用响应长度筛选命中：失败响应长度多为 342；爆破案例命中码 `7774`（响应长度 374），注册案例命中码 `3503`（响应长度 303），注册成功后个人中心显示任意填写的手机号 `12313245678`。
- 危害包括：绕过手机号真实性校验批量注册、抢占/冒用他人手机号注册、为后续欺诈/刷单/薅羊毛提供账号；若注册后能绑定该号码相关业务，还可能影响真实机主。

## 触发条件

- 注册接口使用 4 位（或更短）纯数字短信验证码。
- 验证码校验没有尝试次数限制、失败锁定、递增延迟、验证码一次性失效或图形验证码二次校验。
- 攻击者可对任意手机号触发发送验证码，且发送接口不要求该号码已注册或归属攻击者。
- 注册接口接受手机号 + 验证码 + 密码等参数，成功响应可与失败区分。
- 没有按 IP/设备/手机号的风控阻断大量请求。

## 利用步骤

1. 打开注册页，输入一个任意手机号（可为自己不持有的号码），点击发送验证码，抓取发送请求与注册请求。
2. 观察注册请求中的验证码字段名（如 `vcode`、`code`、`smsCode`）与位数；文章案例为 4 位数字。
3. 确认验证码是否一次性、是否有失败次数限制：连续提交几个错误码，观察是否仍可继续、账号是否被锁、验证码是否失效。
4. 用 Burp Intruder 选择注册请求，Sniper 模式标记验证码位置；Payload type 选 Numbers，From 999、To 9999、Step 1、Min integer digits 4。
5. 按响应长度/状态码/关键字过滤，找出与失败响应不同的命中请求；文章案例命中码为 `7774`（长度 374，失败多为 342）与 `3503`（长度 303）。
6. 用命中验证码完成注册，登录后查看个人中心，确认账号绑定的是任意填写的手机号。
7. 在授权范围内停止，不要批量注册或占用真实用户号码。

## PoC

```http
# 1) 对任意手机号触发验证码
POST /user/sendRegisterSms HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

tel=12313245678

# 2) 爆破注册验证码（Burp Intruder）
POST /user/register HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

tel=12313245678&name=tester&vcode=§9999§&pwd=Passw0rd!&type=1
```

```text
Attack type: Sniper
Payload type: Numbers
From: 999  To: 9999  Step: 1  Min integer digits: 4
Filter: response length != 342（或排除失败提示）
```

## 变体与关联

- **6 位验证码**：空间扩大到 100 万，但若完全无次数限制仍可爆破，只是耗时和请求量更大；应优先确认是否存在限速。
- **验证码重放**：若验证码成功后不失效，可在有效期内重复使用；参见 [[mobile-android-sms-login-code-bruteforce-replay]]。
- **验证码未绑定手机号**：发码与验码取参不一致时，可用自己的验证码登录他人号码；参见 [[web-generic-auth-sms-login-code-not-bound-phone-parameter-tamper]]。
- **2FA 验证码爆破**：登录二次验证场景的同类问题；参见 [[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]。
- **验证码可预测**：生成阶段使用递增/时间种子时，无需爆破即可推算；参见 [[web-generic-auth-sms-otp-generation-predictable-sequence-restart-seed]]。

## 检测与防御

- 使用 6 位以上、CSPRNG 生成的验证码；验证码与手机号 + 会话绑定，一次性使用，有效期 5 分钟左右。
- 对同一验证码设置尝试次数上限（如 5 次），失败达到阈值即作废并要求重新发送；同时对手机号、IP、设备做多维限流和递增延迟。
- 注册接口返回统一的失败提示与响应结构，避免通过长度/状态码区分“验证码错误”和“手机号已存在”。
- 高风险注册增加图形/行为验证码或人工审核；对短时间大量注册、同一 IP 多号码、异常手机号段建立风控规则。
- 监控：同一手机号/会话对验证码接口的高频提交；同一 IP 短时间注册多个账号；验证码错误率异常升高。
