---
id: web-golang-os-executable-symlink-config-hijack
title: Go os.Executable 符号链接配置劫持：Windows/macOS 从链接目录读取被篡改配置
type: scenario
domain: web
path: web/golang
technique: go-os-executable-symlink-config-hijack
aliases:
- os.Executable
- 符号链接配置劫持
- EvalSymlinks
- Go 服务配置覆盖
- 可执行文件目录配置
tags:
- go
- golang
- symlink
- os-executable
- config-hijack
- windows
- macos
- privilege
- security-audit
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:04:12+08:00'
  notes: 已对照原文核对：os.Executable+filepath.Dir 读同目录配置；原文演示 Linux 下经符号链接启动时 Go 跟踪链接读到 bin/test.txt，并指出 Windows/macOS 低权限用户可在可控位置放链接+篡改配置；修复为 EvalSymlinks 后取真实目录。卡内平台差异描述与原文一致，且补充 Windows 链接权限条件属合理限定。原文未给组件版本，affected_versions 空正确。原文图仅 01-05（无本段截图），本段为纯文字。dedup 最高分为卡自身，related 的 Gogs symlink 写 hooks 为具体 RCE 链，非同一链；dup-scan 无本篇 pair。未实测。
---

## 一句话结论

Go 的 `os.Executable()` 返回启动路径，在 Windows/macOS 上不保证解析符号链接；若服务用 `filepath.Dir(os.Executable())` 作为配置目录，低权限用户可在自己可控的位置创建指向该二进制的符号链接并在同目录放篡改配置，服务下次经该链接启动时会读取攻击者配置（如关闭证书校验、改服务器地址），而 Linux 的 `/proc/self/exe` 通常已解析链接。

## 原理

- **`os.Executable()` 的实现差异**：Linux 读取 `/proc/self/exe`，内核返回的是真实可执行文件（已解析符号链接）；Windows 使用 `GetModuleFileName`，macOS 使用 `_NSGetExecutablePath`，返回的可能是“启动时使用的路径”，不保证解析符号链接。
- **配置目录的常见写法**：`execBin, _ := os.Executable(); dir := filepath.Dir(execBin); cfg := filepath.Join(dir, "config.json")`。如果 `execBin` 是攻击者创建的符号链接路径，`dir` 就是攻击者可写的目录，配置文件也从那里读。
- **攻击链**：低权限用户在可写目录创建指向高权限/受保护服务的符号链接 → 在同一目录放置篡改后的配置文件（如 `tls_verify=false`、指向恶意更新服务器、放宽鉴权）→ 让服务下次通过该链接路径启动（计划任务、服务包装脚本、用户协助）→ 服务读取链接目录下的配置，安全设置被覆盖。
- **为什么 Windows/macOS 更危险**：Windows 的符号链接创建通常需要管理员/开发者模式，但目录 junction/其他重解析点或已授权的链接场景仍可被滥用；macOS 普通用户可创建符号链接。Linux 因 `/proc/self/exe` 解析到真实路径，同样的写法通常不受影响，但不要把平台差异当作安全边界。
- **修复**：`exe, _ := os.Executable(); real, _ := filepath.EvalSymlinks(exe); dir := filepath.Dir(real)`；优先把配置放在系统级目录（`/etc`、`%ProgramData%`）并校验配置文件的所有者/权限，而不是可执行文件旁边。
- **局限**：攻击成立需要服务确实从攻击者可控的链接路径启动；如果服务始终以真实路径启动，`os.Executable()` 返回真实路径，配置目录不受影响。因此该问题常见于“可执行文件可被低权限用户间接启动/复制到可控目录”的部署。

## 触发条件

- Windows/macOS 上的 Go 程序（服务/长期运行进程）读取“可执行文件同目录”的配置文件。
- 攻击者能在某目录创建指向目标二进制的符号链接/重解析点，并在该目录写入配置文件。
- 目标程序会通过攻击者可控的链接路径启动（计划任务、启动脚本、用户双击链接、服务管理器配置等）。
- 程序以更高权限运行且配置文件影响安全设置（TLS 校验、更新源、鉴权、日志路径等）。

## 利用步骤

1. 审计/探测程序是否用 `os.Executable()` + `filepath.Dir` 定位配置（源码或运行时行为）。
2. 在低权限可写目录创建指向目标二进制的符号链接（Windows 用 `mklink`/junction，macOS `ln -s`）。
3. 在链接所在目录放置同名配置文件，修改安全相关字段（关闭证书校验、换服务器、放宽权限）。
4. 让服务下次通过该链接路径启动；服务读到攻击者配置后按篡改后的设置运行。
5. 观察生效结果（连接攻击者服务器、跳过 TLS 校验、加载攻击者指定的插件/更新）。

## PoC

漏洞写法与修复写法（Go）：

```go
// 不安全：os.Executable 可能是符号链接路径
exe, _ := os.Executable()
dir := filepath.Dir(exe)
cfg := filepath.Join(dir, "config.json")

// 修复：先解析符号链接，再取真实目录
exe, _ = os.Executable()
real, err := filepath.EvalSymlinks(exe)
if err != nil {
    log.Fatal(err)
}
safeCfg := filepath.Join(filepath.Dir(real), "config.json")
```

攻击侧操作（macOS/Linux 风格；Windows 用 `mklink`）：

```bash
ln -s /opt/protected/service /home/lowpriv/service
printf '{"tls_verify": false, "server": "http://attacker.example"}\n' > /home/lowpriv/config.json
# 触发服务通过 /home/lowpriv/service 启动
```

## 变体与关联

- **变体**：配置文件换成插件目录、证书文件、日志目录、更新清单；符号链接换成目录 junction/硬链接/重解析点；也可攻击“可执行文件同目录的 DLL/依赖加载”（DLL 侧加载）。
- **关联卡片**：[[web-golang-gogs-updaterepofile-symlink-git-config-rce]]（Gogs 仓库内符号链接写 .git/config）；[[web-golang-gogs-symlink-delete-git-head-sshcommand-rce]]（符号链接删除 .git/HEAD 触发 RCE）；[[ai-security-agent-security-file-read-tool-symlink-realpath-bypass]]（normpath 边界检查被符号链接绕过）；[[pentest-privilege-escalation-windows-regpwn-atbroker-registry-symlink]]（Windows 符号链接/机会锁提权）。
- **区分**：本卡的核心是“用 os.Executable 的未解析路径定位配置目录”，不是通用的 symlink 文件读写绕过。

## 检测与防御

- **代码层**：`os.Executable()` 后必须 `filepath.EvalSymlinks()`；配置/插件路径优先使用系统目录，不要放在可执行文件旁边；校验配置文件的所有者与权限（仅管理员/服务账户可写）。
- **部署层**：服务以真实路径启动，不通过用户可控的链接/快捷方式；安装目录与配置目录分离，低权限用户不可写。
- **检测**：监控在可写目录创建指向受保护二进制的符号链接/重解析点；监控服务进程读取“自身路径旁边”的配置；对配置文件权限异常（其他用户可写）告警。
- **平台差异**：Linux 的 `/proc/self/exe` 会解析链接，但 Windows/macOS 不一定；跨平台程序应按最不安全的平台统一处理。
