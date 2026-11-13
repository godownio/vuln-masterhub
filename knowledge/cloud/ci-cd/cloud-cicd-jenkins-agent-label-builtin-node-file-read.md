---
id: cloud-cicd-jenkins-agent-label-builtin-node-file-read
title: Jenkins Pipeline 指定 built-in 节点：绕过专用 agent 隔离读取控制器文件
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-agent-label-builtin-controller-access
aliases:
- Jenkins built-in node
- agent label 滥用
- 控制器节点执行
- Jenkins 主节点文件读取
- pipeline 指定 agent
tags:
- cicd
- jenkins
- agent
- built-in-node
- controller
- file-read
- isolation-bypass
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:11+08:00'
  notes: 已对照原文与图07核对 agent { label 'built-in' } 与 /var/jenkins_home/flag5.txt 的 base64 读取。
---

## 一句话结论

当 Jenkins 声称所有任务都在专用 agent 上运行、但仍允许 Pipeline 通过 `agent { label 'built-in' }` 自选节点时，攻击者只需在 PR 的 Jenkinsfile 中指定 built-in/controller label，就能让构建在 Jenkins 控制器上执行，直接读取 `/var/jenkins_home` 下的 flag、凭据与配置，绕过"专用节点隔离"。

## 原理

- **Jenkins 控制器本身也是节点**：内置节点（built-in node，历史上叫 master）默认承载控制器进程与 `JENKINS_HOME`；专用 agent 通常用于隔离构建负载。
- **Pipeline 可自选 agent**：声明式/脚本式 pipeline 的 `agent { label '...' }` 由 Jenkinsfile 决定；Jenkinsfile 随 PR 代码走，攻击者可改为 `built-in`（或 `master`/控制器对应 label），任务就被调度到控制器。
- **控制器上的敏感资产**：`/var/jenkins_home` 下有 credentials.xml、secrets/、jobs、构建历史与本地 flag 文件；在控制器上执行 shell 即可读取。
- **隔离假设失效**：只配置专用 agent 而不限制 label 选择，并不能阻止任务回到控制器执行；这是 CI/CD 的 "Insecure System Configuration" 类风险。

## 触发条件

- 攻击者能修改 Jenkinsfile 并触发构建（PR/分支均可）。
- Jenkins 允许 Pipeline 选择 built-in/controller label（未禁用或未做 agent 白名单）。
- 控制器 `JENKINS_HOME` 中存在敏感文件/凭据，且构建进程有读权限。

## 利用步骤

1. clone 仓库，修改 Jenkinsfile：
   ```groovy
   pipeline {
       agent { label 'built-in' }
       stages { stage('Unit Tests') { steps { sh "cat /var/jenkins_home/flag5.txt | base64" } } }
   }
   ```
2. 推送分支/提 PR，触发构建。
3. 在构建控制台读取 base64 并解码，得到控制器上的文件内容。

## PoC

```groovy
pipeline {
    agent { label 'built-in' }
    environment { PROJECT = "sanic" }
    stages {
        stage ('Unit Tests') {
            steps {
                sh "cat ~/flag5.txt|base64"
            }
        }
    }
}
```

原文在 PR 构建日志中成功读出 `flag5.txt` 并 base64 输出；若 label 不确定，可先通过 `env`/节点列表或常见 `built-in`/`master` 试探。

## 变体与关联

- **label 变体**：`master`、`controller`、`built-in` 或管理员自定义的控制器 label；也可指定到带生产凭据的其他高权限节点。
- **读取目标**：`JENKINS_HOME` 下 credentials.xml、secrets/master.key、jobs 配置、构建日志；也可直接执行命令/横向。
- **关联**：[[cloud-cicd-jenkins-direct-ppe-jenkinsfile-credential-exfil]]（同属 Jenkinsfile 可控导致的执行面扩大）。

## 检测与防御

- **限制 agent 选择**：禁止 Pipeline 在 built-in/controller 节点执行；使用 agent 白名单/标签约束、Jenkins 的 "Restrict where this project can be run"、或在控制器上设置 `numExecutors=0`。
- **控制器加固**：控制器只做调度，不跑构建；敏感文件最小权限；凭据使用 Jenkins credentials 而非明文文件。
- **变更审查**：对 Jenkinsfile 中 `agent` 的变更做 CODEOWNERS/审批；保护分支。
- **检测**：监控 built-in 节点上的异常构建与 `cat`/`env`/`base64` 命令；审计节点标签变更与任务调度记录。
