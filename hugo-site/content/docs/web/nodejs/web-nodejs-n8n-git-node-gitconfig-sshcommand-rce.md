---
id: web-nodejs-n8n-git-node-gitconfig-sshcommand-rce
title: n8n Git 节点读取被篡改 .git/config：core.sshCommand 注入导致认证用户 RCE（CVE-2026-27498）
type: scenario
domain: web
path: web/nodejs
technique: n8n-git-node-gitconfig-sshcommand-injection
tags:
- n8n
- nodejs
- git
- rce
- workflow
- authenticated
- cve-2026-27498
cve:
- CVE-2026-27498
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: n8n < 2.2.0、< 1.123.8
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:40:43+08:00'
  notes: 已对照原文与6张截图核对：受影响/修复版本2.2.0、1.123.8、Git.node.ts仅设GIT_TERMINAL_PROMPT未限制仓库本地配置、simple-git以用户可控repositoryPath为baseDir、Read/Write File节点与Git节点组合、修复新增N8N_BLOCK_FILE_PATTERNS与默认正则^(.*/)*\.git(/.*)*$且仅作用于ReadWriteFile/ReadBinaryFiles，均与原文及截图一致。未验证点：原文无实际PoC，卡片PoC未实测；core.sshCommand为按git机制还原的具体配置键，原文仅泛称恶意ssh配置，未直接点名该键；原文frontmatter无sources/source_url。版本按原文修复版本设置。
url: /docs/web/nodejs/web-nodejs-n8n-git-node-gitconfig-sshcommand-rce/
draft: false
kb_aliases:
- CVE-2026-27498
- n8n Git 节点 RCE
- n8n .git/config 命令注入
- core.sshCommand 注入
- readWriteFile 与 Git 节点组合
---

## 一句话结论

n8n 在 2.2.0 / 1.123.8 之前，仅有工作流创建或编辑权限的认证用户可先用 Read/Write File 节点向某目录的 `.git/config` 写入 `core.sshCommand`，再用 Git 节点以该目录为 `repositoryPath` 执行 fetch/pull；系统 git 在走 SSH 传输时会执行该配置项，从而以 n8n 进程用户身份执行任意命令。

## 原理

- Git 节点的 `repositoryPath` 直接取自节点参数，被用作 simple-git 的 `baseDir`，代码只设置了 `GIT_TERMINAL_PROMPT=0`，没有校验目标是哪个仓库、也没有清理仓库本地配置中的危险键。
- `core.sshCommand` 是 git 自带的“用自定义命令替代 ssh”配置项。只要远端 URL 使用 `ssh://`（或 scp 风格）传输，`git fetch`/`pull`/`push` 就会调用该配置指定的命令；这是 git 的预期功能，git 不会对配置值做可信性判断。
- 因此“能写 `.git/config`”等价于“能让 n8n 在下一次 Git 操作时执行任意 shell 命令”。n8n 的 Read/Write File 节点允许工作流作者读写进程可访问的任意路径，两者组合即构成写配置→触发执行的完整 RCE 链。
- 该链绕过的是“工作流编辑者不应等于宿主机命令执行者”这一权限边界：Git 节点和写文件节点都以 n8n 进程的操作系统用户身份运行，命令权限即 n8n 服务账号权限。
- 官方修复新增全局文件访问黑名单 `blockFilePatterns`（环境变量 `N8N_BLOCK_FILE_PATTERNS`），默认正则 `^(.*\/)*\.git(\/.*)*$`，在 ReadWriteFile 与 ReadBinaryFiles 节点执行前拒绝访问 `.git` 目录及其内容，从写入端切断该链。

## 触发条件

- n8n 版本低于 2.2.0 或低于 1.123.8。
- 攻击者持有有效账号，且该账号能创建、编辑并执行工作流（工作流权限即可，不要求管理员）。
- 实例未通过 `NODES_EXCLUDE` 排除 `n8n-nodes-base.readWriteFile`，Git 节点可用。
- n8n 进程用户对目标目录有写权限，且目标目录能被 git 识别为仓库（宿主机上已有的 git 仓库，或用同一写文件节点构造 `.git/HEAD`、`.git/refs`、`.git/objects` 后的新目录）。
- 工作流执行后 Git 节点确实执行了会触发传输命令的操作（fetch/pull/push 且远端为 SSH）。

## 利用步骤

1. 选定 n8n 进程可写的目录（例如已有仓库 `/opt/app/repo`，或自建 `/tmp/.x`）。
2. 用 Read/Write File 节点向 `<dir>/.git/config` 写入恶意配置：`[core] sshCommand = <命令>`，并配置一个 `ssh://` 远端；若目录不是现成仓库，再写出 `.git/HEAD`（如 `ref: refs/heads/main`）并保证 `.git/refs`、`.git/objects` 存在。
3. 在同一工作流中添加 Git 节点，`operation` 选 `fetch`（或 `pull`），`repositoryPath` 指向该目录。
4. 执行工作流：simple-git 调起系统 git，git 读取被污染的本地配置，SSH 传输时执行 `sshCommand`。
5. 命令以 n8n 进程用户身份运行；用回连或写入文件确认执行结果。

## PoC

原文未给出可直接运行的 PoC，下面为按代码路径还原的最小验证配置，未实测：

```text
# 节点 1：Read/Write File（Write）
fileName: /tmp/n8n-poc/.git/config
data:
[core]
	sshCommand = sh -c 'id > /tmp/n8n-poc/pwned'
[remote "origin"]
	url = ssh://git@127.0.0.1/not-exist
	fetch = +refs/heads/*:refs/remotes/origin/*
```

```text
# 节点 2：Git
operation: fetch
repositoryPath: /tmp/n8n-poc
```

```bash
# 执行后检查（也可替换为反弹 shell 命令）
cat /tmp/n8n-poc/pwned
```

## 变体与关联

- 变体：Git 节点自带 `addConfig` 操作，可直接向一个已存在的仓库写入 `core.sshCommand`，可能省去写文件节点；前提仍是 `repositoryPath` 可控且该目录是合法仓库。
- 变体：同一思路可写 `core.fsmonitor`、`core.hooksPath` 等会被 git 其他子命令调用的配置项，把触发点扩展到 status/commit 等操作。
- 关联：[[web-nodejs-n8n-authenticated-execute-command-workflow-rce]]（同为工作流编辑权限升级为宿主机命令执行）、[[web-nodejs-n8n-expression-sandbox-escape-rce]]、[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]、[[web-golang-gogs-updaterepofile-symlink-git-config-rce]]（另一产品中写 `.git/config` 注入 `core.sshCommand` 的同类根因）。
- 边界：ReadWriteFile 被排除、`.git` 路径被黑名单拦截、n8n 已升级到修复版本、进程无 git 或目标目录无法成为仓库时，链不成立。

## 检测与防御

- 升级到 n8n 2.2.0 / 1.123.8 或更高版本；无法升级时把 `n8n-nodes-base.readWriteFile` 加入 `NODES_EXCLUDE`。
- 将工作流创建/编辑权限收紧到完全受信用户；工作流执行账号以低权限容器运行，限制可写目录与出站连接。
- 检测：审计工作流中出现 ReadWriteFile 写 `.git/config`、`.git/hooks` 等路径；Git 节点使用异常 `repositoryPath`；n8n 进程派生 `git` 后紧接 `sh`/`ssh` 子进程；仓库配置中出现异常的 `core.sshCommand`。
- 排查：检查 n8n 数据目录与常见仓库目录下 `.git/config` 的最近修改时间与内容，关注工作流变更记录中的可疑节点参数。
