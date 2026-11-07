---
id: cloud-cloud-iam-entra-id-session-cookie-replay
title: Entra ID 会话接管：注入 ESTSAUTH/ESTSAUTHPERSISTENT Cookie 复用已认证云会话
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: entra-id-session-cookie-replay
tags:
- cloud
- entra-id
- azure-ad
- microsoft-365
- cookie
- session-hijack
- mfa-bypass
- credential-access
- browser
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V208
  verified_at: '2026-11-07T02:27:59+08:00'
  notes: 已对照原文与20/21图核对：ESTSAUTH/ESTSAUTHPERSISTENT/ESTSAUTHLIGHT、login.microsoftonline.com 注入 Cookie 复用已认证会话、Global Administrator 接管与原文一致；卡内 CDP setCookie 为结构化复现。未验证点：未复跑；无受影响版本；frontmatter 无 sources/source_url。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-entra-id-session-cookie-replay/
draft: false
kb_aliases:
- Entra ID cookie 注入
- ESTSAUTHPERSISTENT
- ESTSAUTH 会话复用
- Microsoft 365 会话劫持
- Azure AD cookie 接管
- 浏览器 Cookie 接管云身份
---

## 一句话结论

当攻击者从浏览器（如 Chrome v20 Cookie）拿到 `login.microsoftonline.com` 的 `ESTSAUTH`/`ESTSAUTHPERSISTENT`/`ESTSAUTHLIGHT` 等认证 Cookie 后，把这些 Cookie 注入自己的浏览器或 HTTP 客户端并访问 Entra ID/portal，即可复用受害者已通过 MFA 的会话，以受害者身份访问 Exchange Online、OneDrive、SharePoint、Teams 等；若受害者是全局管理员，可直接接管整个 Entra ID 租户。

## 原理

- **Entra ID 的会话载体是 Cookie**：用户完成交互式登录与 MFA 后，Microsoft 身份平台在 `login.microsoftonline.com` 域下写入认证 Cookie。`ESTSAUTH` 表示当前认证会话，`ESTSAUTHPERSISTENT` 是“保持登录”的持久会话，`ESTSAUTHLIGHT` 为轻量会话标识；它们在有效期内就是 bearer 凭据。
- **为什么能绕过 MFA**：MFA 只在建立会话时校验一次；之后的请求只要携带有效 Cookie，就被视为已认证。攻击者不需要口令、MFA 码或设备，只需复用 Cookie。
- **Cookie 的来源**：信息窃取木马、浏览器凭据导出、Chrome App-Bound Key 解密、终端侧内存/磁盘提取等都能拿到这些 Cookie；Cookie 是明文值，经过 TLS 保护但落盘后不再受 MFA 保护。
- **注入条件**：Cookie 未过期、会话未被撤销；目标租户未启用 Token Protection/绑定设备的 Conditional Access，或攻击者的会话不被策略判定为高风险；Cookie 的 Domain/Path/Secure/HttpOnly 属性需正确设置（HttpOnly 不能通过 `document.cookie` 写入，但可用 CDP/扩展/浏览器数据库直接写入）。
- **持久性**：`ESTSAUTHPERSISTENT` 让会话跨浏览器重启保留；攻击者可在 Cookie 过期前持续访问。全局管理员会话意味着租户级控制（用户、应用、策略、邮箱、数据）。
- **与刷新令牌/PRT 的区别**：Cookie 复用是“会话层”接管，不需要 refresh token；如果还能窃取 PRT（Primary Refresh Token），则可获得更持久的令牌链，但 Cookie 已足够完成 Web 会话接管。

## 触发条件

- 已获取目标用户在 `login.microsoftonline.com` 域下的有效认证 Cookie（至少 `ESTSAUTH` 或 `ESTSAUTHPERSISTENT`）。
- Cookie 未过期，且会话未被管理员撤销（密码重置不一定撤销 Cookie，需显式 Revoke sessions）。
- 目标租户未强制 Token Protection/设备合规/可信位置等能阻止 Cookie 复用的 Conditional Access。
- 攻击者能在浏览器中设置目标域 Cookie（CDP、扩展、DevTools、直接写 Cookie 数据库）或构造带 Cookie 的 HTTP 请求。
- 受害者在 Chrome/Edge 等浏览器中登录过 Microsoft 365/Entra ID，且可能勾选“保持登录状态”。

## 利用步骤

1. 从已解密的浏览器 Cookie 导出结果中筛选 `host` 为 `.login.microsoftonline.com`/`login.microsoftonline.com` 的条目，重点保留 `ESTSAUTH`、`ESTSAUTHPERSISTENT`、`ESTSAUTHLIGHT`（以及 `CCState`、`buid` 等辅助 Cookie）。
2. 启动一个干净的浏览器实例（建议独立 user-data-dir），开启远程调试（`--remote-debugging-port=9222`），避免污染分析环境。
3. 通过 Chrome DevTools Protocol 的 `Network.setCookie` 逐个写入 Cookie：domain 设为 `.login.microsoftonline.com`，path `/`，secure=true，httpOnly 按原值；`ESTSAUTHPERSISTENT` 的过期时间按原值设置。
4. 导航到 `https://login.microsoftonline.com/` 或 `https://portal.office.com/`；若会话有效，会直接进入已登录状态，不再要求口令/MFA。
5. 验证身份与权限：访问 `https://portal.azure.com/`/Entra 管理中心/Exchange/SharePoint，确认账号、角色（如 Global Administrator）与可访问资源。
6. 若需要 API 访问，可从浏览器会话中获取后续 token，或直接操作门户；记录租户 ID、账号 UPN、角色与可访问数据作为影响证明。
7. 清理：删除注入的 Cookie/关闭临时浏览器；在授权测试中及时通知防守方撤销会话。

## PoC

```python
# 通过 Chrome DevTools Protocol 注入 Cookie（Chrome 需以 --remote-debugging-port=9222 启动）
import json, requests, websocket

cookies = json.load(open("cookies.json"))["cookies"]
targets = [c for c in cookies if "login.microsoftonline.com" in c["host"]]

# 省略 CDP 连接细节：获取 ws url 后依次发送 Network.setCookie
# {"method":"Network.setCookie","params":{
#   "name":"ESTSAUTHPERSISTENT","value":"<cookie-value>",
#   "domain":".login.microsoftonline.com","path":"/","secure":True,"httpOnly":True}}
```

```http
GET / HTTP/1.1
Host: login.microsoftonline.com
Cookie: ESTSAUTHPERSISTENT=<value>; ESTSAUTH=<value>
```

```text
# 验证：浏览器访问 portal.office.com / entra.microsoft.com，若直接进入已登录状态且显示受害者账号/角色，即会话复用成功。
# 案例：注入后以 Global Administrator 身份接管 Microsoft Entra ID。
```

## 变体与关联

- 变体：窃取 PRT（Primary Refresh Token）或 refresh token，获得更持久的令牌链；参见 roadtools/ROADrecon 相关研究。
- 变体：其他 Microsoft 云服务（Exchange Online、SharePoint、Teams、OneDrive）复用同一会话 Cookie；也可横向到已 SSO 的第三方 SaaS。
- 变体：其他云身份提供商（Okta、Google Workspace、AWS SSO）同样存在会话 Cookie/令牌复用风险，思路一致。
- 关联：[[pentest-privilege-escalation-chrome-v20-abe-dpapi-cng-lsass-xor]]（Chrome v20 Cookie 解密的来源）、[[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]（v10 旧方案）、[[defense-forensics-terminal-osc52-clipboard-read]]（另一类剪贴板凭据窃取）。
- 边界：Cookie 过期/会话被撤销/启用 Token Protection 后复用失败；Conditional Access 可能要求合规设备或阻断匿名 IP；HttpOnly Cookie 需要 CDP/扩展写入，不能仅靠 JS。

## 检测与防御

- 检测（云侧）：Entra 登录日志中的异常 IP/地理位置、同一账号短时间多地登录、非托管设备/浏览器 UA 变化、会话 Cookie 复用特征；Microsoft Defender for Cloud Apps 的异常 token/cookie 使用告警。
- 防御（身份）：启用 Conditional Access Token Protection（绑定设备/令牌）、要求合规设备与 MFA 强度、缩短会话与持久 Cookie 生命周期、禁用不必要的“保持登录”。
- 响应：发现 Cookie 泄露后立即 `Revoke-MgUserSignInSession`（或 `Revoke-AzureADUserAllRefreshToken`）撤销会话与刷新令牌，重置口令，检查邮箱规则/应用授权/管理员角色变更。
- 加固（终端）：启用 Chrome App-Bound Encryption、EDR 监控浏览器 Cookie 数据库读取与内存注入、禁止在终端保存长期云会话；对高权限账号使用专用/特权访问工作站。
