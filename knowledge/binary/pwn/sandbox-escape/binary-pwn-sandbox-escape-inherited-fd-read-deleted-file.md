---
id: binary-pwn-sandbox-escape-inherited-fd-read-deleted-file
title: fork 继承 root 已打开的 fd：低权限子进程经 /proc/<pid>/fd 读取已删除脚本
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: inherited-fd-read-deleted-file
aliases:
- 继承文件描述符绕过权限
- /proc/pid/fd 读取已删除文件
- fork 继承 fd 提权读取
- memfd 已删除文件读取
- 低权限进程读 root 打开的文件
tags:
- linux
- sandbox-escape
- file-descriptor
- procfs
- permission-bypass
- fork
- pyjail
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:16+08:00'
  notes: 已对照原文 Jail 一节核对：fd 4 指向 /memfd:/app/main.py (deleted)、lseek+read 读回源码、AES-CBC 解密 flag 一致；未复跑容器。
---

## 一句话结论

Linux 的权限检查发生在 `open()` 时；如果 root 先打开（甚至删除）一个文件，再 fork 出丢弃权限的子进程，而该 fd 未被 `CLOEXEC` 关闭，子进程就继承了这个已打开的 fd。子进程无需重新 open，直接用 `lseek(fd, 0, 0)` + `os.read(fd, ...)`（或读 `/proc/<pid>/fd/<n>`）就能读出原本无权访问、且路径已删除的文件内容。

## 原理

- **fd 是能力（capability）**：Unix 进程访问文件先 `open` 得到 fd，后续 `read/write/lseek` 只针对 fd，不再检查文件路径权限。权限判断只在 `open` 那一刻进行。
- **fork/exec 的继承**：`fork()` 后子进程复制父进程的 fd 表；`execve()` 默认保留未设置 `FD_CLOEXEC` 的 fd。Python 的 `subprocess`/`os.fork` 若显式 `pass_fds` 或未关闭 fd，就会把父进程打开的 fd 传给子进程。
- **已删除文件仍可通过 fd 读**：`unlink()` 只删除目录项，inode 与数据仍在，直到所有 fd 关闭。`/proc/<pid>/fd/<n>` 是指向该 inode 的符号链接（`/memfd:/app/main.py (deleted)`），`readlink`/`open` 该链接仍能访问。
- **为什么能绕过权限**：root 打开文件时已完成权限检查；子进程虽然 euid 是 nobody/ctf，但拿到的 fd 本身代表“已获授权”的打开实例。它不需要再次 `open` 路径，因此绕过文件 mode 与目录权限。
- **读取偏移**：子进程运行脚本时，fd 的读取偏移可能已到文件末尾；`lseek(fd, 0, 0)` 把偏移重置到开头，再 `os.read` 才能读到完整内容。
- **典型场景**：root 启动的 Python 服务把自身脚本放入 `memfd` 或打开后 `unlink`，再 fork 低权限子进程执行；子进程沙箱被逃逸（如 pyjail）后，攻击者即可读回脚本源码，从中拿到密钥/flag 或进一步利用。

## 触发条件

- root 父进程打开目标文件（普通文件或 `memfd_create`），随后 fork/exec 一个低权限子进程。
- 父进程把该 fd 传给子进程（`pass_fds`、未设 `CLOEXEC`、`fork` 后继承），且子进程可执行攻击者可控代码。
- 目标文件在子进程运行期间仍保持打开（即使已 `unlink`）。
- 系统挂载 `/proc`，且子进程对 `/proc/<pid>/fd` 有读权限（读自己或同 uid 进程通常允许）。

## 利用步骤

1. 逃逸/取得低权限 shell（本题先通过 Python `eval` 沙箱的 `__subclasses__` 链拿到 `os.system("sh")`）。
2. 查看进程与 fd：`ps aux` 找到 root 的 `python3 main.py` 与低权限子进程；`ls -la /proc/self/fd` 或 `/proc/<pid>/fd`，寻找指向 `/memfd:/app/main.py (deleted)` 的 fd（如 4）。
3. 确认可读：`readlink /proc/<pid>/fd/4`；尝试 `cat /proc/<pid>/fd/4`（可能因偏移在末尾而输出为空）。
4. 用 Python 重置偏移并读取：
   ```bash
   python -c "import os; os.lseek(4,0,0); print(os.read(4,90000).decode('latin1',errors='ignore'))"
   ```
5. 分析读出的源码/脚本，提取密钥、IV、密文或下一步利用点；本题从 `flag_hint()` 取得 AES-CBC 的 key/IV/ciphertext。
6. 解密得到 flag。

## PoC

```bash
# 1. 找到继承的 fd
ps aux
ls -la /proc/self/fd
# lrwx------ 1 nobody root 64 ... /proc/self/fd/4 -> /memfd:/app/main.py (deleted)

# 2. 读取 fd 内容（偏移可能已在 EOF，先 lseek 到 0）
python -c "import os; os.lseek(4,0,0); print(os.read(4,90000).decode('latin1',errors='ignore'))"
```

```python
# 从读到的源码中恢复 AES-CBC 参数后解密（示例）
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex("<key_hex>")
iv = base64.b64decode("<iv_b64>")
ct = base64.b64decode("<ciphertext_b64>")
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
print(pt.decode())
```

说明：PoC 为原文流程的最小化复现，未在本机执行；原文通过 `os.lseek(4,0,0)` + `os.read` 读回已删除的 `main.py`，从中得到 AES 参数并解出 flag。

## 变体与关联

- 变体（fd 来源）：`memfd_create` 匿名文件、打开后 `unlink` 的普通文件、继承的 socket/pipe、`/proc/<pid>/fd` 中其他进程的 fd（需权限）。
- 变体（继承方式）：`fork` 复制 fd 表；`execve` 保留未设 `CLOEXEC` 的 fd；Python `subprocess.Popen(..., pass_fds=[fd])`；容器运行时把宿主 fd 传入容器。
- 变体（提权/逃逸）：pyjail `__subclasses__` 逃逸拿到 shell；容器 `runc` fd 泄漏逃逸；`/proc/self/fd` 作为文件包含/任意读的跳板。
- 关联：[[binary-pwn-sandbox-escape-python-jail-subclass-traversal]]（先逃逸 Python 沙箱）；[[binary-pwn-sandbox-escape-chroot-openat-fd-exit-status-sidechannel]]（fd 与 chroot）；[[cloud-container-runc-fd-leak-escape]]（容器 fd 泄漏逃逸）；[[web-java-component-tomcat-multipart-tempfile-fd]]（临时文件 fd 利用）。
- 边界：fd 设置了 `CLOEXEC` 且子进程是 `exec` 启动、父进程在 fork 后关闭 fd、子进程与目标 fd 不在同一 fd 表、或 `/proc` 不可读时，无法直接读取；文件被覆盖/截断也会影响内容。

## 检测与防御

- 检测：低权限进程读取 `/proc/<pid>/fd/*`、出现 `lseek` 后大块 `read` 的异常行为；进程 fd 表中存在指向 `(deleted)` 文件的描述符；fork 后子进程保留 root 打开的敏感 fd。
- 防御：打开敏感文件时设置 `O_CLOEXEC`/`FD_CLOEXEC`；fork/exec 前显式关闭不需要的 fd；不要把 fd 传给低权限子进程；用最小权限账户打开文件；对 `/proc` 做访问限制（hidepid）；敏感脚本避免长期保持打开，或在使用后立即关闭所有 fd。
