---
id: cloud-cicd-github-actions-runner-label-ubuntu-latest-hijack
title: 以 ubuntu-latest 标签注册恶意自托管 runner：劫持组织内 GitHub 托管作业并窃取 CI secrets
type: scenario
domain: cloud
path: cloud/ci-cd
technique: github-actions-rogue-runner-label-hijack
aliases:
- 恶意 runner 劫持
- runner 标签冒充
- ubuntu-latest 标签劫持
- GitHub 托管 runner 劫持
- gh-hijack-runner
- 自托管 runner 提权
tags:
- ci-cd
- github-actions
- self-hosted-runner
- label-spoofing
- job-hijack
- secrets
- supply-chain
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:17:36+08:00'
  notes: 已对照原文图07/08与演示输出核对：注册令牌注册 runner、ubuntu-latest 标签出现在组织 Runners 页、作业被领取并输出 SENSITIVE_CLOUD_KEY/SENSITIVE_SSH_KEY/system.github.token、删除会话后工作流 internal error；原文未给受影响版本。
---

## 一句话结论

拿到组织级 runner 注册令牌后，攻击者可以注册一台自托管 runner 并把标签设为 `ubuntu-latest`；组织内原本为 GitHub 托管 runner 设计的 `runs-on: ubuntu-latest` 工作流会被调度到这台恶意 runner 上执行，攻击者因此直接拿到作业环境与 secrets（示例泄露 `SENSITIVE_CLOUD_KEY`、`SENSITIVE_SSH_KEY`、`system.github.token`），无需向受保护仓库推送任何代码。

## 原理

- **runner 标签是自填字符串**：注册 runner 时由注册方提交 labels（如 `self-hosted`、`linux`、`x64`、`ubuntu-latest`），GitHub 不校验这些标签是否「官方保留」。组织级 runner 默认对所有仓库可用，作业调度按 `runs-on` 与 runner 标签匹配。
- **`ubuntu-latest` 也是可匹配标签**：`runs-on: ubuntu-latest` 表面表示 GitHub 托管 runner，但组织内若存在带同名标签的自托管 runner，作业可能被分配给这台 runner（文中观察到「任何包含 ubuntu-latest 标签的工作流默认会使用我们的 runner（如果可用）」）。
- **为什么能越过分支保护**：敏感仓库可能禁止直接 push、要求 PR 审核与签名，但这些保护只约束代码写入；工作流本身在 `push` 到 main 时照常运行，攻击者控制的 runner 只是「执行者」，不需要向仓库写入任何内容。
- **窃密方式**：恶意 runner 客户端（如 `gh-hijack-runner.py`）用注册令牌与 GitHub 建立 runner 会话，接收作业消息并解密，读取环境变量中的 secrets 与 `system.github.token`；示例输出直接打印云密钥、SSH 私钥与 GitHub token。
- **为什么隐蔽**：runner 出现在组织的 Runners 页面中，标签看起来正常；作业正常被领取并执行到一半，若不审计 runner 列表与注册事件，很难与合法自托管 runner 区分。
- **边界**：组织禁止自托管 runner、注册需要审批、作业显式使用 `runs-on: [self-hosted, <unique-label>]`、使用 runner 组隔离、或 GitHub 调度优先托管 runner 时，劫持不一定成功。

## 触发条件

- 攻击者持有组织级（或目标仓库级）runner 注册令牌（可由 App 私钥、PAT、泄露凭据获得）。
- 组织允许自托管 runner，且目标工作流使用 `runs-on: ubuntu-latest`（或其他可被冒用的标签）。
- 恶意 runner 能出网与 GitHub 通信，并在作业需要的架构上运行（Linux x64）。
- 目标工作流会在攻击者等待窗口内被触发（如正常开发者 push）。

## 利用步骤

1. 取得注册令牌（见 [[cloud-cicd-github-app-private-key-runner-registration-token]]）。
2. 用恶意 runner 客户端注册并指定标签：`gh-hijack-runner.py --registration-token <token> --url https://github.com/<org> --labels ubuntu-latest`。
3. 在组织 Settings → Actions → Runners 中确认出现一台带 `ubuntu-latest` 标签的自托管 runner（文中截图显示其与 "Standard GitHub-hosted runners" 并列，状态 Idle）。
4. 等待合法开发者向敏感仓库 push 触发 `runs-on: ubuntu-latest` 的工作流；恶意 runner 领取作业。
5. 客户端解密作业消息，输出环境变量与 secrets（示例：`SENSITIVE_CLOUD_KEY`、`SENSITIVE_SSH_KEY`、`system.github.token`）。
6. 用窃取的云密钥/SSH 私钥/token 继续访问云资源或仓库；必要时删除/替换 runner 掩盖。

## PoC

```bash
# 用注册令牌注册冒用 ubuntu-latest 标签的恶意 runner
gh-hijack-runner.py --registration-token BIHLYJXS...5XA \
  --url https://github.com/syncicd --labels ubuntu-latest

# 输出示例
[+] Session ID: 26113d38-5474-41dd-a4eb-42a0e77ecb28
[+] AES key: JnowJl...Hox6bw==
[+] New Job: deploy (messageId=2)
- SENSITIVE_CLOUD_KEY: cloud_key_ela...
- SENSITIVE_SSH_KEY: -----BEGIN OPENSSH PRIVATE KEY-----
- system.github.token: ghs_CVe...
```

说明：命令/字段来自文中演示；实际标签可按目标工作流的 `runs-on` 调整（如 `windows-latest`、`macos-latest`、自定义标签）。

## 变体与关联

- 变体：冒用其他托管标签（`windows-latest`、`macos-latest`）或项目自定义标签；在仓库级而非组织级注册；使用 runner 组把恶意 runner 限定到目标仓库。
- [[cloud-cicd-github-app-private-key-runner-registration-token]]：注册令牌的来源链。
- [[cloud-cicd-github-runner-credentials-session-hijack]]：不注册新 runner，直接盗用现有 runner 凭据接管会话的另一条路径。
- [[cloud-cicd-github-actions-pr-head-ref-expression-injection-rce]]：在已劫持/已 RCE 的 runner 上执行命令的初始入口。
- 边界：runner 注册审批、runner 组限制、工作流使用唯一自托管标签或固定托管版本时，冒用标签可能拿不到作业。

## 检测与防御

- 防御：组织 Settings → Actions → Runners 定期审计，删除未知/多余 runner；限制谁可注册 runner，启用 runner 组与仓库访问控制；对自托管 runner 使用唯一、不可猜测的标签。
- 防御：把 App/机器人的 `organization_self_hosted_runners: write` 权限视为高敏感权限，最小化授权；工作流尽量使用 GitHub 托管 runner 并确认组织内没有同名标签 runner。
- 检测：Audit Log 的 `runner_registered`/`runner_group` 事件与异常注册 IP；Runners 页面出现与 "Standard GitHub-hosted runners" 并列的自托管同名标签 runner；同一标签 runner 数量异常。
- 检测：工作流运行日志/作业领取记录与合法 runner 名单不一致；secrets 使用后出现异常云 API 调用或仓库操作。
- 响应：删除恶意 runner、吊销注册令牌与相关 App 安装、轮换全部 CI secrets 与云凭据、审计受影响仓库的提交与部署。
