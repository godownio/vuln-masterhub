---
id: web-nodejs-n8n-git-node-bare-repo-hook-rce
title: n8n Git 节点裸仓库 Hook 执行：克隆数据被识别为可执行 Hook 导致认证用户 RCE（CVE-2025-62726）
type: scenario
domain: web
path: web/nodejs
technique: n8n-git-node-bare-repo-hooks
tags:
- n8n
- nodejs
- git
- rce
- workflow
- authenticated
- bare-repository
- hook
- cve-2025-62726
cve:
- CVE-2025-62726
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 1.113.0
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:40:04+08:00'
  notes: 原文无图，已通读全文核对：CVE-2025-62726/<1.113.0、Git 节点 repositoryPath 作为 baseDir、裸仓库根目录 hooks/pre-push 触发、PoC 用 Execute Command 复制并置 bare=true、补丁 5bf3db5b 与 N8N_GIT_NODE_DISABLE_BARE_REPOS 均一致；affected_versions 已在卡中。未验证点：未按原文脚本实跑，且原文无截图可交叉验证复现结果。
url: /docs/web/nodejs/web-nodejs-n8n-git-node-bare-repo-hook-rce/
draft: false
kb_aliases:
- CVE-2025-62726
- n8n 裸仓库 RCE
- n8n Git 节点 Hook 执行
- bare repository hook RCE
- n8n 1.113.0
---

## 一句话结论

n8n 1.113.0 之前的 Git 节点允许把用户指定的 `repositoryPath` 当作任意仓库使用且不拒绝裸仓库（bare repository）；拥有工作流编辑权限的攻击者可让该路径下的 `hooks/pre-push` 等文件被 Git 当作可执行 Hook，在执行 `git push` 时以 n8n 进程用户身份运行任意命令。

## 原理

- Git 的安全边界建立在“数据”与“可执行逻辑”的区分上：`git clone` 只把对方仓库的工作树文件下载为数据，不会把 `.git/hooks` 下的钩子安装到本地并执行，因此克隆不受信仓库通常不等于执行对方代码。
- 裸仓库打破了这个边界：裸仓库没有工作树，仓库根目录本身就是 Git 目录，`hooks/` 直接位于根目录下。Git 在该目录执行操作时会按正常机制查找并运行 `hooks/pre-push` 等钩子。
- n8n Git 节点的 `repositoryPath` 完全取自节点参数，并直接作为 simple-git 的 `baseDir`；代码只设置了 `GIT_TERMINAL_PROMPT=0`，没有校验该路径是否是裸仓库，也没有阻止其读取仓库本地配置。
- 因此攻击者可以先让恶意仓库中的 `hooks/pre-push`（可执行位可由 Git 跟踪）和 `config`（内容含 `bare = true`）作为普通文件被克隆到 n8n 可写目录；当 Git 节点以该目录为 `repositoryPath` 执行 push 等操作时，Git 将其识别为裸仓库并运行根目录下的 Hook，Hook 的内容从此前“克隆下来的数据”变为“被执行的命令”。
- 该链的危害边界是工作流编辑权限：Git 节点以 n8n 进程的操作系统用户身份调起系统 git，Hook 命令继承该用户权限；若该用户是容器内 node 用户或宿主服务账号，攻击者即从“能编工作流”升级为“能在 n8n 主机执行命令”。

## 触发条件

- n8n 版本低于 1.113.0，Git 节点可用（未被 `NODES_EXCLUDE` 禁用）。
- 攻击者持有有效账号并能创建、修改并执行工作流（不要求管理员）。
- 工作流能控制 Git 节点的 `repositoryPath` 与仓库地址，或能通过其他节点（如 Read/Write File、Execute Command）在 n8n 进程可写目录构造出裸仓库布局。
- 目标目录对 n8n 进程用户可写；Hook 文件可执行（经 Git 克隆保留可执行位，或由命令节点 chmod）。
- 随后触发的 Git 操作会运行 Hook（如 push；原文用 push 触发 `pre-push`）。

## 利用步骤

1. 攻击者准备恶意仓库：仓库工作树中包含裸仓库布局所需文件，核心是根目录下可执行的 `hooks/pre-push`，脚本内容为要执行的命令；并提交至少两次，避免 push 时因 “Everything up-to-date” 不进入 Hook 执行路径。
2. 工作流第一步用 Git 节点 Clone，把恶意仓库克隆到 n8n 进程可写的临时目录（如 `/tmp/clone`）。此时 `hooks/pre-push` 只是普通文件。
3. 把克隆内容布置为裸仓库形态：原文用 Execute Command 节点将 `/tmp/clone` 复制到 `/tmp/bare`，并修改 `/tmp/bare/config` 写入 `bare = true`。
4. 同一工作流用 Git 节点对 `/tmp/bare` 执行 Push；Git 按裸仓库语义读取根目录 `hooks/pre-push` 并执行。
5. Hook 以 n8n 进程用户身份运行（原文脚本 `touch /tmp/output_check/pwned_62726`），通过写入文件或回连验证；攻击者也可替换为反弹 shell、读取环境变量/密钥等命令。
6. 变体：若环境禁用 Execute Command 但允许 Git 节点，可把 `config`、`HEAD`、`objects/`、`refs/`、`hooks/pre-push` 作为被跟踪文件直接放在恶意仓库里，Clone 后该工作树即具备裸仓库识别所需的文件结构，再以同一路径执行 push，减少对命令节点的依赖（此变体未在原文实测，confidence: low）。

## PoC

原文提供了一键脚本与手动流程，核心节点参数如下（未在本机执行）：

```text
# 恶意仓库 hooks/pre-push（需可执行）
#!/bin/sh
touch /tmp/output_check/pwned_62726
```

```text
# n8n 工作流（原文 PoC 路径）
1) Git 节点：Clone  源仓库 -> /tmp/clone
2) Execute Command 节点：cp -r /tmp/clone /tmp/bare
   并修改 /tmp/bare/config 设置 bare = true
3) Git 节点：Push  repositoryPath = /tmp/bare
```

验证：宿主机挂载目录出现 `output_check/pwned_62726`，说明 Hook 已以 n8n 进程权限执行。

## 变体与关联

- 变体：Hook 类型可换为 `pre-commit`、`post-checkout`、`post-merge` 等，配合 Git 节点的 commit/checkout/pull 操作触发；命令可改为反弹 shell 或读取 `N8N_ENCRYPTION_KEY` 等敏感环境变量。
- 变体：与 Write File 节点组合直接写入裸仓库布局，不依赖 Execute Command；能否写入可执行 Hook 取决于文件节点是否保留权限位与目标目录权限。
- 关联：[[web-nodejs-n8n-git-node-gitconfig-sshcommand-rce]]（CVE-2026-27498，写 `.git/config` 注入 `core.sshCommand`）、[[web-nodejs-n8n-git-clone-arbitrary-file-write-rce]]（CVE-2026-21877，Clone 任意文件写入）、[[web-nodejs-n8n-authenticated-execute-command-workflow-rce]]（工作流编辑权限直接执行命令）。三条链的共同边界都是：工作流编辑者不应等于宿主机命令执行者。
- 边界：1.113.0 起 Git 节点在启用防护时调用 `checkIsRepo('bare')` 并拒绝裸仓库；`N8N_GIT_NODE_DISABLE_BARE_REPOS=true` 可强制开启防护。若 Execute Command 与 Git 节点均被禁用、或 n8n 以严格低权限容器运行且无可写目录，链不成立。

## 检测与防御

- 升级 n8n 至 1.113.0 或更高版本；无法升级时设置 `N8N_GIT_NODE_DISABLE_BARE_REPOS=true`，并限制 `Execute Command`、Read/Write File 等高危节点的使用权限。
- 将工作流创建/编辑权限收紧到可信用户；n8n 服务以低权限容器运行，限制可写目录、出站网络与凭据挂载。
- 检测：审计 Git 节点出现异常 `repositoryPath`（尤其指向 `/tmp` 且仓库根目录含 `config`、`hooks/`、`HEAD`、`objects/`）；工作流中 Clone 后紧接 push 到同一临时目录；n8n 进程派生的 `git` 子进程随后执行 shell 或 `touch`/`curl`/`bash` 等命令。
- 排查：检查 n8n 数据目录与临时目录下可疑的裸仓库布局、`hooks/pre-push` 内容与可执行位；关注工作流变更记录中对 Git 节点路径与仓库地址的修改。
