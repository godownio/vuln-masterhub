---
id: cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent
title: Entra ID 管理员同意链：common 端点枚举租户 ID + Graph 查 redirect_uri + adminconsent 获取应用权限
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: entra-tenant-id-redirect-uri-adminconsent
aliases:
- Azure AD 租户 ID 枚举
- AADSTS50020 租户泄露
- adminconsent 管理员同意
- redirect_uri 枚举
- AADSTS50011
- 恶意 OAuth 应用
- 多租户应用授权
tags:
- azure
- entra-id
- oauth
- admin-consent
- tenant-enumeration
- redirect-uri
- graph-api
- initial-access
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:51:36+08:00'
  notes: 已对照原文与13张图核对；修正 AADSTS50020 表述：泄露的是登录账号所属租户 ID（本例账号由挑战页创建于目标租户 d26f353d），原卡误写为“不属于目标租户的账号”。tenant ID 枚举→Graph 读 redirectUris→adminconsent 精确匹配→client_credentials 取含 Group.Read.All/User.Invite.All 的目标租户 token 链与原文一致；PoC 未在本机执行
---

## 一句话结论

已知一个多租户 Entra 应用的 client_id/client_secret 时，先用 `common` 授权端点以外部账号登录，从 `AADSTS50020` 错误的 identity provider URL 中枚举目标 tenant ID；再用应用 token 调 Graph 读取该应用的 `web.redirectUris`，构造 redirect_uri 完全匹配的 `/adminconsent` 链接；管理员同意后，应用在目标租户获得 tenant-wide 应用权限，client_credentials 可换取带 `roles` 的 app-only token。

## 原理

- **common 端点的租户解析**：`login.microsoftonline.com/common/oauth2/v2.0/authorize` 会根据登录账号的 home tenant 解析租户。用一个目标租户内的账号（本例通过挑战页创建 `@azurectfchallengegame.com` 账号）访问位于其他租户的应用时，返回 `AADSTS50020`，消息中出现 `identity provider 'https://sts.windows.net/<tenant-id>/'`；即使登录失败，账号所属租户（即目标 tenant）ID 已经泄露。这是低成本、无需 API 权限的租户枚举 oracle。
- **redirect_uri 必须精确匹配**：`/adminconsent` 与应用的其他 OAuth 流一样校验 `redirect_uri` 是否在应用注册的 `web.redirectUris` 列表中，否则返回 `AADSTS50011`。攻击者用应用自身的 app-only token 调 Graph `GET /v1.0/applications(appId='<client_id>')?$select=web` 即可读到 `web.redirectUris`（本例该 URI 指向一个博客页面），再用完全相同的值构造请求。
- **管理员同意的效果**：`/common/adminconsent?client_id=<id>&redirect_uri=<exact>` 会向目标租户管理员展示应用申请的权限；管理员点“接受”后，浏览器被重定向到 `redirect_uri` 并附加 `?admin_consent=True&tenant=<target-tenant-id>`。管理员同意授予的是**应用权限**（application permissions / app roles），对整个租户生效，不需要每个用户单独同意。
- **client_credentials 换取 app-only token**：管理员同意后，用同一 client_id/client_secret 向目标租户的 token 端点请求 `grant_type=client_credentials`，签发的 JWT 中 `idtyp=app`、`tid=<target-tenant-id>`、`roles` 数组包含被授予的应用角色（本例为 `Group.Read.All`、`User.Invite.All`）。应用随后即可在目标租户内调用 Graph，无需任何用户登录。
- **与用户同意/条件访问的区别**：普通用户同意可能被条件访问阻止（本例出现 `53003` 访问被阻止），但管理员同意走的是管理员权限路径；管理员同意的范围由应用注册中配置的 application permissions 决定，可能远超用户同意能授予的委派权限。
- **前置的社会工程属性**：管理员同意需要目标租户管理员主动批准，因此该链在实战中通常配合“同意钓鱼”（ illicit consent grant）或已获得管理员会话；本例的挑战环境通过页面创建目标租户管理员账号来模拟这一前提。

## 触发条件

- 攻击者拥有一个多租户 Entra 应用（`signInAudience` 支持多组织），掌握其 client_id 与 client_secret，并在应用注册中配置了目标所需的应用权限。
- 目标租户存在可被诱导/已控制的管理员，愿意在 adminconsent 页面点击接受；或攻击者已持有管理员会话。
- 应用注册的 `redirectUris` 已知或可读；请求中的 redirect_uri 必须与其中之一完全一致。
- 目标租户未禁止管理员同意、未限制未验证应用、未启用仅允许特定发布者的策略；应用未被管理员同意策略阻断。
- 攻击者能访问 `common` 授权端点并用一个目标租户内的账号（本例由挑战页创建）触发 `AADSTS50020` 以获取该账号所属租户 ID，或通过其他情报源已知 tenant ID。

## 利用步骤

1. **确认应用与初始 token**：用 client_credentials 在应用所属租户获取 token，解码 JWT 确认 `aud=https://graph.microsoft.com`、`idtyp=app`、`appid`、`tid` 与 `roles`。
2. **枚举目标 tenant ID**：构造 `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=<id>&response_type=code&redirect_uri=<任意已注册URI>&scope=https://graph.microsoft.com/.default`，用目标租户的普通账号登录；读取 `AADSTS50020` 错误中的 `https://sts.windows.net/<tenant-id>/`，得到 tenant ID。
3. **读取 redirect_uri**：用应用 token 调 `GET https://graph.microsoft.com/v1.0/applications(appId='<client_id>')?$select=web`，从 `web.redirectUris` 取一个允许值；若返回多个，逐一尝试。
4. **构造管理员同意链接**：`https://login.microsoftonline.com/common/adminconsent?client_id=<id>&redirect_uri=<exact-redirect-uri>`，发送给目标租户管理员或在其会话中打开。
5. **管理员接受**：管理员在同意页看到应用申请的权限并点击接受；页面重定向到 `redirect_uri?admin_consent=True&tenant=<tenant-id>`，确认 `admin_consent=True` 与 tenant ID。
6. **换取目标租户 app-only token**：`POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token`，`grant_type=client_credentials`、`client_id`、`client_secret`、`scope=https://graph.microsoft.com/.default`；解码 token 确认 `tid` 为目标租户且 `roles` 含预期权限。
7. **后续利用**：用该 token 枚举组/用户/应用，或执行应用权限允许的操作（如邀请 Guest、读取组、读取目录对象）；结合动态组规则可进一步继承资源角色（见关联卡片）。

## PoC

以下为最小请求骨架（占位符需替换；未在本机执行）：

```bash
# 1) 应用初始 token
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/<HOME_TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "scope=https://graph.microsoft.com/.default" | jq -r .access_token)

# 2) common 授权端点触发 AADSTS50020，从错误消息提取目标 tenant ID
echo "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=<REGISTERED_REDIRECT>&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"

# 3) 读取应用注册的 redirectUris
curl -sH "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications(appId='<CLIENT_ID>')?\$select=web" | jq .

# 4) 管理员同意链接（发给目标租户管理员）
echo "https://login.microsoftonline.com/common/adminconsent?client_id=<CLIENT_ID>&redirect_uri=<EXACT_REGISTERED_REDIRECT>"

# 5) 管理员同意后，用目标租户换取 app-only token
TARGET_TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/<TARGET_TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "scope=https://graph.microsoft.com/.default" | jq -r .access_token)
```

```bash
# 6) 查看 token 权限
echo "$TARGET_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{tid,idtyp,roles}'
```

## 变体与关联

- 变体：用 `prompt=consent` 的授权码流尝试用户同意；用 `organizations` 端点替代 `common`；用设备码流诱导管理员登录；把 redirect_uri 指向攻击者域名以接收 code/token。
- 变体：应用使用证书而非 client_secret；使用多租户发布者验证；申请 `.default` 范围触发管理员同意；利用 `admin_consent=True` 后长期有效的 app-only token。
- 关联：[[cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role]]（拿到 `Group.Read.All`/`User.Invite.All` 后的动态组提权）、[[cloud-cloud-iam-workload-role-policy-selfcheck]]（云身份权限自查）。
- 关联攻击面：OAuth 同意钓鱼、恶意应用注册、未验证发布者应用。

## 检测与防御

- **审计日志**：监控 Entra ID 审计日志中的 `Consent to application`、`Add service principal`、`Add app role assignment`、`Update application`；关注 `admin_consent=True` 的重定向与新的 app-only token 签发。
- **同意策略**：限制用户同意，启用管理员同意工作流；禁止或限制未验证发布者的应用；按发布者/权限白名单控制管理员同意；定期审查企业应用与 service principal。
- **应用注册审查**：检查 `redirectUris` 是否包含外部域名/博客/短链等可疑地址；检查 `signInAudience` 是否为 `AzureADMultipleOrgs`；检查应用中配置的高危 application permissions（`Directory.Read.All`、`Group.Read.All`、`User.Invite.All`、`Application.ReadWrite.All` 等）。
- **凭据管理**：定期轮换 client_secret/证书；监控异常的 client_credentials 登录（非惯用 IP、非惯用应用、短时间大量 Graph 调用）；对 app-only token 的 `roles` 与 `tid` 做基线。
- **租户枚举**：`AADSTS50020` 本身难以完全避免，但可通过统一登录域名、限制外部账号访问、监控大量 common 端点探测来降低信息价值；不要把 tenant ID 当作秘密。
- **响应**：发现未授权管理员同意时，撤销同意/删除 service principal、轮换应用密钥、审查该应用在租户内创建的对象（Guest、组、角色分配），并检查是否已利用动态组进一步提权。
