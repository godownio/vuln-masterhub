---
id: cloud-cicd-jenkins-indirect-ppe-build-script-makefile
title: Jenkins 间接 PPE：流水线仓库不可写时改代码仓库 Makefile 借构建执行窃取凭据
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-indirect-ppe-build-script-injection
tags:
- cicd
- jenkins
- ppe
- makefile
- build-script
- credentials
- supply-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:06+08:00'
  notes: 已对照原文与图03核对流水线仓库 pre-receive hook 拒绝、代码仓库 Makefile 注入与 PR 触发；原文未附 make 阶段输出截图，成功为作者自述。
url: /docs/cloud/ci-cd/cloud-cicd-jenkins-indirect-ppe-build-script-makefile/
draft: false
kb_aliases:
- 间接 PPE
- Indirect PPE
- Makefile 注入
- 构建脚本投毒
- Jenkins 构建脚本 RCE
- 代码仓库提权流水线
---

## 一句话结论

当 Jenkins 流水线定义位于受保护、不可推送的仓库，但构建时会拉取另一个可写的业务代码仓库并执行其中的构建脚本（如 `make`）时，攻击者只需修改代码仓库的 `Makefile`（或等价构建脚本）增加恶意 target，PR 触发流水线即可在 CI 中执行任意命令，窃取该构建可访问的凭据。

## 原理

- **间接 PPE**：流水线定义（Jenkinsfile）与业务代码分仓存放，前者有 pre-receive hook/保护分支不可写，但后者对开发者开放；Jenkinsfile 中的 `sh "make"`、`sh "npm test"`、`sh "pytest"` 等步骤会执行代码仓库里的构建脚本/测试代码。
- **执行边界错位**：安全控制只保护了"流水线定义"，却把"会被 CI 解释执行的文件"当成普通数据；只要攻击者能改 `Makefile` 等文件并触发构建，就等价于改 Jenkinsfile。
- **凭据仍会注入**：构建在带凭据（`withCredentials`/环境变量）的 agent 上运行，恶意 target 可直接读取环境变量并 `base64` 输出。

## 触发条件

- 存在流水线仓库 + 代码仓库的双仓结构；流水线定义仓库不可写（pre-receive hook 拒绝）。
- Jenkinsfile 在构建阶段执行代码仓库中的构建脚本（Makefile、package.json scripts、setup.py、测试文件等）。
- 攻击者对代码仓库有写权限，能推送分支/提 PR，且该 PR 会触发流水线。
- 构建使用可被窃取的凭据或敏感环境变量。

## 利用步骤

1. clone 代码仓库，确认流水线会执行 `make`（或等价命令）。
2. 在 `Makefile` 中加入恶意 target（覆盖默认 target 或让默认目标依赖它）：
   ```make
   whoami:
       echo $FLAG | base64
   ```
3. 新建分支并推送（向流水线定义仓库推送会被 pre-receive hook 拒绝，但代码仓库允许），创建 PR。
4. Jenkins 触发 PR 构建并在 `make` 阶段执行恶意 target，控制台日志得到 base64 凭据。

## PoC

```make
whoami:
	echo $FLAG|base64
```

```bash
git checkout -b challenge2
git add Makefile
git commit -m "commit"
git push -u origin challenge2   # 向代码仓库推送，而非被保护的流水线仓库
```

原文实测在 PR 流水线的 make 输出中得到 base64 flag；向流水线仓库推送则报 `pre-receive hook declined`。

## 变体与关联

- **构建脚本载体**：Makefile、`package.json` 的 `scripts`（`npm test`/`npm run build`）、`setup.py`/`pyproject.toml`、Gradle/Maven 配置、CMake、shell 脚本、测试文件（pytest 导入即执行）。
- **触发方式**：PR 构建、分支构建、定时构建；也可通过依赖包安装阶段执行。
- **同族**：[[cloud-cicd-jenkins-direct-ppe-jenkinsfile-credential-exfil]]（直接 PPE）、[[cloud-cicd-git-dependency-tag-republish-poisoning]]（依赖链投毒）。

## 检测与防御

- **把构建脚本纳入代码审查**：Makefile/package.json/setup.py 等会进入 CI 执行的文件与 Jenkinsfile 同等对待，变更需审批；保护分支 + CODEOWNERS。
- **流水线隔离**：不可信 PR 的构建使用无生产凭据的 agent；构建凭据按环境隔离、最小权限。
- **行为检测**：审计构建日志中的 base64/外连；监控构建过程中对凭据环境变量的访问；对构建脚本中的网络命令（curl/wget/nc）告警。
- **架构**：将 CI 执行环境与敏感凭据解耦，生产部署使用 OIDC 短期凭据并限制 PR 事件。
