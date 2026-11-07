---
id: binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2
title: seccomp write(fd==1/2) 写入限制绕过：fcntl dup2 重映射 stdout 写任意文件
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: seccomp-write-fd-fcntl-dup2-bypass
aliases:
- fcntl dup2 seccomp bypass
- CVE-2026-32128
- FastGPT 沙箱文件写入绕过
- stdout 重映射写文件
- seccomp fd 白名单绕过
tags:
- seccomp
- fcntl
- dup2
- sandbox-escape
- fastgpt
- file-write
- cve-2026-32128
cve:
- CVE-2026-32128
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: v4.14.7 及之前
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T12:11:13+08:00'
  notes: 已对照原文与图01核对：v4.14.7.2 的 constants.ts 第44行 allowBaseSyscalls 含 syscall.SYS_FCNTL，第114/115行 f.add_rule(ALLOW,'write',Arg(0,EQ,sys.stdout.fileno())) 与 stderr，图01 与原文代码一致；原文给出的 fcntl.dup2(fd,1)+sys.stdout.write 绕过链成立。卡内对静态检测的边界已诚实标注：原文称代码中无 open(/write(，但 PoC 实际含 os.open 与 sys.stdout.write，卡内注明若检测器用宽松子串匹配仍可能命中。affected_versions 按原文 v4.14.7 及之前保留。未验证点：未复跑 seccomp 环境；v4.14.7 的 /sandbox/python 入口以原文为准；frontmatter 无 sources/source_url。
---

## 一句话结论

当 seccomp 只用 write 的第一个参数（fd 号）做白名单、只允许 fd 1/2，却同时放行 `fcntl` 时，攻击者可用 `fcntl.dup2(fd, 1)` 把任意可写文件的 fd 复制到 1，再通过 `sys.stdout.write` 写文件；seccomp 看到的是 `write(1, ...)`，实际落点却是攻击者指定的文件。FastGPT v4.14.7 及之前的沙箱即受此影响（CVE-2026-32128）。

## 原理

- seccomp BPF 的 `Arg(0, EQ, 1)` / `Arg(0, EQ, 2)` 只比较系统调用参数值，不关心 fd 背后指向哪个文件。fd 是进程内的句柄，可以被 `dup2`/`dup3`/`F_DUPFD` 重定向到任意已打开文件。
- 沙箱的 seccomp 白名单包含 `syscall.SYS_FCNTL`，而 write 规则只允许 fd 等于 stdout/stderr 的 fileno。`fcntl.dup2(fd, 1)` 后，fd 1 指向目标文件，后续 `write(1, ...)` 或 `sys.stdout.write` 满足 seccomp 检查。
- 上层静态检测（`detect_file_write_operations`）只识别有限的字面写入模式；`fcntl.dup2` + 重定向 stdout 属于间接写入路径，不在其模式覆盖内（若检测器使用宽松的子串匹配，`os.open`/`sys.stdout.write` 仍可能命中，实际以目标实现为准）。
- 为什么成立：把「写文件」简化为「fd 号等于 1 或 2」是错误抽象。安全检查应该看打开路径、打开标志或系统调用语义，而不是看一个可被复制的句柄编号。

## 触发条件

- 沙箱的 seccomp 策略允许 `fcntl`（或 `dup`/`dup3`），同时 write 只按 fd 号放行 stdout/stderr；
- 上层还有仅匹配字面关键字的静态检测，且未覆盖 fd 重定向路径；
- 攻击者能在沙箱内执行 Python 代码（FastGPT 工作流代码节点或 `/sandbox/python`）；
- 受影响版本：FastGPT v4.14.7 及之前；v4.14.7.2 镜像的 `constants.ts` 中 `allowBaseSyscalls` 含 `syscall.SYS_FCNTL`，write 规则只允许 stdout/stderr 的 fileno。v4.14.8 重构后移除 seccomp、换成纯 Python 防护，本链不再适用，但同类逃逸改由 `inspect` 链完成。

## 利用步骤

1. 用 `os.open` 以 `O_WRONLY | O_CREAT` 打开目标文件，得到 fd。
2. 调用 `fcntl.dup2(fd, 1)`，把目标文件复制到 stdout 的 fd 号。
3. 用 `sys.stdout.write('...')` 或 `os.write(1, b'...')` 写入内容；seccomp 只看到 fd=1。
4. 需要走 stderr 时把 fd 复制到 2；`dup3`、`F_DUPFD` 是等价变体。
5. 关闭 fd 并确认文件落盘。

## PoC

```python
import os
import fcntl
import sys

fd = os.open('/tmp/evil.txt', os.O_WRONLY | os.O_CREAT)
fcntl.dup2(fd, 1)          # 把 stdout 重定向到 evil.txt
sys.stdout.write('pwned')  # 满足 seccomp write(fd==1)，实际写进文件
```

等价变体：

```python
import os
import fcntl

fd = os.open('/tmp/evil2.txt', os.O_WRONLY | os.O_CREAT)
fcntl.dup2(fd, 2)          # 重映射 stderr
os.write(2, b'pwned\n')
```

## 变体与关联

- 变体：`dup3`、`fcntl.F_DUPFD`、`os.dup2` 都能完成同样的 fd 重映射；把 fd 复制到 1 或 2 均可。
- 变体：用 `ctypes` 直接发起 `fcntl`/`dup2` 系统调用，绕过对 Python 标准库函数名的静态匹配。
- 关联：[[binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs]]（FastGPT v4.14.8 的 inspect 帧回溯链；与本卡同属「黑名单 + 藏引用」根因在 Python 层与 seccomp 层的两次失败）。
- 关联：[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（另一类 seccomp 边界绕过，利用 IFUNC resolver 在 constructor 安装 seccomp 之前执行）。
- 影响边界：本卡只解决「写文件」这一项。要获得完整逃逸还需读文件、网络或进程能力；在 FastGPT v4.14.7 上可与静态检测绕过、seccomp 白名单中的其他系统调用组合。

## 检测与防御

- 检测：用户代码中出现 `fcntl`、`dup2`、`dup3`、`F_DUPFD`、`os.write(1`、`sys.stdout.write` 与文件打开同时出现；沙箱进程出现 stdout/stderr 被重定向到普通文件的行为。
- 防御：seccomp 不要只按 fd 号放行 write；应禁止 `fcntl` 的 `F_DUPFD`/`F_DUPFD_CLOEXEC` 与 `dup`/`dup3`，或改用 seccomp user notification / LSM 做基于路径与打开标志的检查。
- 防御：静态检测不能作为安全边界；文件写入限制应由只读文件系统、挂载命名空间、非 root 用户和容器隔离共同保证。
- 防御：升级 FastGPT 到 v4.14.8 及以上（注意 v4.14.8 的部署模板仍可能指向 v4.14.7.2 旧镜像，需核对实际镜像 tag）；根本方案仍是系统级隔离，而不是在 Python/TS 层做字符串过滤。
