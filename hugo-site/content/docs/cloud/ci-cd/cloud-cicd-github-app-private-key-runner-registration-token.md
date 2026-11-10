---
id: cloud-cicd-github-app-private-key-runner-registration-token
title: GitHub App 私钥泄露到 CI 环境：生成安装令牌并以 organization_self_hosted_runners:write 换取组织 runner 注册令牌
type: scenario
domain: cloud
path: cloud/ci-cd
technique: github-app-key-installation-runner-registration-token
tags:
- ci-cd
- github
- github-app
- private-key
- token
- self-hosted-runner
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:17:39+08:00'
  notes: 已对照原文核对 GH_APP_ID/GH_APP_PVK 泄露、gh token generate 安装令牌含 organization_self_hosted_runners:write、POST /orgs/<org>/actions/runners/registration-token 换注册令牌的完整链；原文未给受影响版本。
url: /docs/cloud/ci-cd/cloud-cicd-github-app-private-key-runner-registration-token/
draft: false
kb_aliases:
- GH_APP_PVK 泄露
- GitHub App 私钥接管
- installation token 换 runner 注册令牌
- runner registration-token
- gh token generate
- organization_self_hosted_runners
---

## 一句话结论

在自托管 runner 上拿到命令执行后，环境变量里常能看到 GitHub App 的 `GH_APP_ID` 与 `GH_APP_PVK`（RSA 私钥）；用私钥和 App ID 生成安装访问令牌（installation token），若该 App 被授予 `organization_self_hosted_runners: write`，即可调用 `POST /orgs/<org>/actions/runners/registration-token` 取得组织级 runner 注册令牌，为后续注册恶意 runner（如冒用 `ubuntu-latest` 标签）铺路。

## 原理

- **GitHub App 的身份模型**：App 用私钥签 JWT 证明身份，换取 installation access token（`ghs_...`，通常 1 小时）；令牌权限来自 App 在组织上的安装授权，而不是用户身份。私钥泄露 = App 身份被完全接管。
- **CI 环境是私钥高发地**：部署类工作流常把 App 私钥/ID 放进环境变量（示例 `GH_APP_ID=889830`、`GH_APP_PVK=-----BEGIN RSA PRIVATE KEY-----...`）供脚本创建 release、推镜像等；一旦 runner 被 RCE，`env` 即可读出。
- **权限决定下一步**：用 `gh token generate --key leaked-private-key.pem --app-id <id>` 得到的令牌若带 `organization_self_hosted_runners: write`，就能为整个组织签发 runner 注册令牌；注册令牌是「把任意机器加入组织 runner 池」的凭证，有效期约 1 小时。
- **为什么是提权**：攻击者原本只有某个仓库/工作流的代码执行；拿到组织级 runner 注册权限后，可以注册自己的机器并接收组织内其他仓库（包括受保护仓库）的作业，越过分支保护与仓库边界。
- **边界**：App 未安装到组织、未授予 runner 管理权限、私钥已轮换/失效、组织禁止自托管 runner 或需要审批时链不成立。

## 触发条件

- 攻击者已在某个能访问 App 环境变量/密钥文件的工作流或 runner 上获得命令执行。
- 目标组织安装了对应 GitHub App，且 App 具备 `organization_self_hosted_runners: write`（或 `admin:org` 等更大权限）。
- 私钥仍有效，组织允许创建 runner 注册令牌。
- 攻击者能访问 `api.github.com`（或 GitHub Enterprise API）。

## 利用步骤

1. 在 runner 上读取环境变量与文件，收集 `GH_APP_ID`、`GH_APP_PVK`/`.pem` 私钥。
2. 用 `gh token generate --key leaked-private-key.pem --app-id <app_id>` 生成安装令牌，确认权限包含 `organization_self_hosted_runners: write`。
3. 以该令牌调用 `POST /orgs/<org>/actions/runners/registration-token`，取得 `token`（注册令牌）与过期时间。
4. 把注册令牌交给恶意 runner 客户端（如 `gh-hijack-runner.py --registration-token ... --labels ubuntu-latest`），注册到组织。
5. 等待组织内匹配标签的工作流作业被调度到恶意 runner，窃取 secrets（参见 [[cloud-cicd-github-actions-runner-label-ubuntu-latest-hijack]]）。
6. 清理/轮换痕迹前评估影响：App 私钥可再次生成令牌，需组织侧撤销安装或轮换私钥才能阻断。

## PoC

```bash
# 1) runner 上收集到的环境变量（示意）
# GH_APP_ID=889830
# GH_APP_PVK=-----BEGIN RSA PRIVATE KEY----- ...

# 2) 私钥换安装令牌
gh token generate --key leaked-private-key.pem --app-id 889830
# {
#   "token": "ghs_...",
#   "expires_at": "...",
#   "permissions": { "organization_self_hosted_runners": "write" }
# }

# 3) 换组织 runner 注册令牌
export GH_TOKEN="ghs_..."
gh api --method POST -H "Accept: application/vnd.github+json" \
  /orgs/<org>/actions/runners/registration-token
# { "token": "BIHLY...", "expires_at": "..." }
```

## 变体与关联

- 变体：私钥来自 GitHub App 的 `.pem` 文件、Kubernetes Secret、Vault、CI 变量或镜像层；权限可换 `admin:org`、`self-hosted runners` 管理；GitHub Enterprise Server 的 API 路径相同。
- 变体：若没有 App 私钥，可用具备 `admin:org` 的 PAT、被泄露的 runner 注册令牌或组织管理员会话达到同样目的。
- [[cloud-cicd-github-actions-runner-label-ubuntu-latest-hijack]]：本卡注册令牌的直接用途。
- [[cloud-cicd-github-runner-credentials-session-hijack]]：另一种不注册新 runner、直接冒用现有 runner 凭据的路径。
- 边界：App 权限最小化、私钥不进入 CI、组织启用 runner 注册审批或仅允许指定 runner 组时链不成立。

## 检测与防御

- 防御：GitHub App 私钥绝不进入工作流环境/仓库；用 OIDC 或 GitHub 托管的短期凭据；App 权限最小化，去掉 `organization_self_hosted_runners: write`（除非确有必要）；定期轮换私钥并撤销旧安装。
- 防御：限制谁能创建组织 runner，启用 runner 组与仓库访问控制；对自托管 runner 注册做审批与审计。
- 检测：组织 Audit Log 中的 GitHub App 令牌生成、`runner_registered`、`registration_token` 相关事件；异常 IP 调用 `/orgs/*/actions/runners/registration-token`；runner 列表出现未知机器。
- 响应：轮换 App 私钥/撤销安装、删除未知 runner、轮换 CI secrets 与云凭据、排查 runner 上持久化。
