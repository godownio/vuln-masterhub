---
id: web-generic-auth-password-reset-codesign-id-predictable-encryption-oracle
title: 密码找回 codesign/id 可预测且未绑定用户：用注册接口获取任意数值的站点加密值，重置任意账号密码
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-codesign-id-predictable-encryption-oracle
aliases:
- 任意用户密码修改
- codesign 加密值
- 忘记密码 id 可预测
- 注册接口加密 oracle
- username 加密值
- 重置票据未绑定用户
- 顺序 id 预测
tags:
- web
- auth
- password-reset
- predictable-id
- encryption-oracle
- parameter-tampering
- account-takeover
- logic-flaw
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V494
  verified_at: '2026-11-11T00:16:17+08:00'
  notes: 已对照原文与9张图片核对：发送验证码响应 code_id=988、注册989用户取得 iAq2Ad+WbphU9、admin123 密文 3PHmVyXZgPuT0oRPPfKg、step=4 重置返回 error:false 但 refer step=5、admin123 登录成功均一致；原理/触发条件/PoC 为单条完整任意用户改密链，颗粒度合适；无 sources/文章ID；原文为通用站点未给版本，affected_versions 已清除。未验证点：加密算法与 id 递增规律为案例特定，按目标调整。
---

## 一句话结论

找回密码流程把重置票据做成了自增数字 `id`，并在“发送验证码”的响应里直接返回（示例 988，下一次即 989）；最终重置请求用 `username`（目标用户名的站点加密值）和 `codesign`（该 id 的站点加密值）两个字段定位重置流程，服务端既不校验 id 是否可预测，也不校验 codesign 是否真的发给了 username 对应的邮箱。同时，站点对用户可控值做确定性加密并把密文暴露在注册/找回密码响应里，等于提供加密 oracle：注册一个名为 `989` 的用户即可拿到 989 的密文，在找回密码框输入 `admin123` 即可拿到其密文。把两者拼进重置请求，就能修改任意用户（包括管理员）的密码。

## 原理

- **票据 id 可预测**：发送邮箱验证码的响应包含 `id`（示例 988），每次请求递增；攻击者由此推断下一次重置票据 id 为 989。id 本身不是秘密，但它是服务端定位“待重置会话”的键，可预测就能提前准备。
- **加密不是完整性保护**：站点对 `username`、`id`（`codesign`）做加密后再传输，看起来防篡改，但加密是确定性的（同一明文得到同一密文），且多个接口会把用户输入加密后回显/使用：
  - 注册接口：注册用户名 `989`，服务端对其加密并处理；
  - 找回密码接口：输入目标用户名 `admin123`，请求里的 `username` 字段就是其密文。
  攻击者不需要知道算法或密钥，只需把这些接口当“加密 oracle”，获得任意明文的合法密文，再移植到重置请求中。
- **codesign 与 username 未绑定**：最终重置接口用 `codesign`（加密后的 id）识别重置会话，用 `username`（加密后的目标用户名）指定要改的账号，但没有在服务端校验“该 id 对应的验证码邮件是发给这个 username 的”。因此攻击者可以用自己触发/预测的 id 密文，配上任意目标用户名的密文。
- **为什么成功后返回 false**：案例中重置响应体的成功标志为 false，但重定向路径变成 `step=5`（流程进入完成步骤），实际密码已被修改；仅看布尔字段会误判失败，必须以登录验证为准。
- **根因组合**：可预测票据（id 泄露 + 递增）+ 确定性加密且可被 oracle 获取密文 + 关键字段未做服务端绑定校验，三者缺一不可。

## 触发条件

- 找回密码为多步流程，发送验证码响应返回递增的 `id`（或时间戳、可枚举的票据号），且该 id 用于最终重置请求。
- 重置请求包含 `username` 与 `codesign`（或类似“用户标识 + 票据”）两个客户端可控字段；服务端用 codesign 定位会话、用 username 定位账号，但不比对二者绑定关系。
- 站点对用户输入做确定性加密，且注册/找回密码/资料等接口会把加密值回显或用于请求， attacker 能获得任意明文的密文。
- 攻击者能注册账号、能触发一次找回密码并抓包（Burp 等代理）。

## 利用步骤

1. **摸底**：用自己的账号进入“忘记密码”，输入注册邮箱并点击获取验证码，抓包；记录响应中的 `id`（示例 988）与请求中的 `username` 加密值。
2. **推断下一个 id**：再次触发或根据递增规律确认下一次 id（示例 989）。
3. **获取 id 的密文**：用注册接口注册用户名为 `989` 的账号；回到忘记密码输入 `989` 并抓包，取得 `username` 字段中 989 的密文（`codesign` 使用同一加密体系）。
4. **获取目标用户名的密文**：在忘记密码输入目标账号（示例 `admin123`），抓包取得其 `username` 密文。
5. **构造重置请求**：提交修改密码请求，`username` 填目标用户名的密文，`codesign` 填 989 的密文，填入新密码。
6. **验证**：忽略响应中的 `false`，观察是否跳转到 `step=5`/完成页；用新密码登录目标账号确认接管。
7. **收尾**：记录请求/响应证据，恢复或报告；不要在生产环境扩大尝试。

## PoC

流程示意（字段名按目标调整，密文均为站点返回的合法值）：

```http
# 1) 触发找回密码，响应泄露 id
POST /<forgot-send-code> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=<enc(own_user)>&email=<own_email>
# 响应: {"id":988,...}

# 2) 注册用户名为下一个 id，取得其加密值
POST /<register> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=989&password=...&email=...

# 3) 在找回密码中输入 989 / 目标用户名，抓包取得各自 username 密文
POST /<forgot-send-code> HTTP/1.1
username=<enc(989)>
# 以及
username=<enc(admin123)>

# 4) 用目标用户名密文 + id 密文重置密码
POST /<reset-password> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=<enc(admin123)>&codesign=<enc(989)>&password=NewPass123
# 响应可能为 false，但 Location/step=5 表示成功
```

无独立可执行 PoC；上述请求序列即复现要点。

## 变体与关联

- **id 生成方式**：自增、时间戳、可枚举随机数、数据库主键；只要能在响应中观测并预测下一次，就能提前取得对应密文。
- **加密 oracle 位置**：注册、找回密码、资料修改、搜索建议等任何“把用户输入加密后回显/使用”的接口；密文可跨接口复用是核心。
- **绑定缺失位置**：codesign 与 username 未绑定、验证码与手机号/邮箱未绑定、重置票据未绑定会话等；KB 中已有 username 篡改、未绑定手机号、sid 复用等变体卡。
- **响应误导**：成功标志 false 但实际成功（本卡）、或前端只校验 status 字段（响应篡改类卡）。
- **关联卡**：密码重置 username 篡改、未绑定手机号重置、发码 sid 复用/响应篡改、密码重置 token 可预测等。

## 检测与防御

- **服务端设计**：重置票据使用高熵随机值，服务端保存“票据 → 用户 → 验证码/邮箱 → 过期时间”的绑定关系；重置时只认票据，不接受客户端另行提交的 username/用户 ID，或至少校验票据与 username 一致。
- **加密与完整性**：不要用“确定性加密 + 客户端回传”当防篡改；使用 AEAD/HMAC 或服务端不透明 token；同一密文不得跨接口/跨参数复用。
- **信息泄露**：发送验证码响应不要返回内部票据 id；错误信息与响应时间避免泄露账号/票据状态。
- **监控**：检测同一 IP/账号短时间内“注册与目标 id 相同用户名”“找回密码用户名与最终重置用户名不一致”“响应 false 但流程继续”等模式；对密码重置做频率限制与告警。
- **测试**：审计找回密码全流程时，逐字段替换（username、id、codesign、email、phone、step）并核对服务端绑定关系；不要只测验证码是否正确。
