# 容器

## 这层是什么

Docker、runc、镜像与运行时逃逸。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CopyEscape：docker cp 归档一致性破坏与解包包含性失效导致宿主机任意文件写入（CVE-2026-17106）](cloud-container-docker-cp-copyescape-archive-inclusion-escape.md) | verified | high | 2026-11-05 |
| [docker cp chroot 辅助进程 NSS dlopen 注入：容器内 libnss 以宿主机 root 执行（CVE-2019-14271）](cloud-container-docker-cp-chroot-nss-dlopen-rce.md) | verified | high | 2026-11-05 |
| [docker cp 符号链接 TOCTOU 逃逸：容器内换链使 daemon 以 root 读写宿主机文件（CVE-2018-15664）](cloud-container-docker-cp-symlink-toctou-escape.md) | verified | high | 2026-11-05 |
| [Docker devices cgroup 提权逃逸：改写 devices.allow=a + mountinfo 取宿主根分区 major:minor + mknod 块设备，ext 用 debugfs 直写/xfs 挂载后写计划任务](cloud-container-docker-devices-allow-mknod-debugfs-escape.md) | verified | medium | 2026-11-12 |
| [Docker Registry v2 未授权：/v2/_catalog 枚举私有仓库、insecure-registries 拉取镜像并从镜像层/配置提取密钥](cloud-container-docker-registry-v2-unauth-catalog-image-secret-dump.md) | verified | high | 2026-11-09 |
| [Docker Socket 挂载或 TCP 2375 暴露导致宿主机逃逸](cloud-container-docker-socket-tcp-escape.md) | verified | high | 2026-11-05 |
| [Docker TLS 2376 + 泄露 CA 私钥：自签客户端证书接管 Docker API 并进入容器](cloud-container-docker-tls-ca-key-client-cert-api.md) | verified | high | 2026-11-05 |
| [Docker 容器 cgroup v1 notify_on_release 逃逸：挂载 cgroup 改 release_agent 指向 overlay upperdir 的 payload，内核以宿主机 root 执行（含 CVE-2022-0492 无 CAP_SYS_ADMIN 绕过）](cloud-container-docker-cgroup-release-agent-escape.md) | verified | high | 2026-11-12 |
| [Docker 挂载宿主机 procfs 时通过 core_pattern 逃逸](cloud-container-docker-procfs-core-pattern-escape.md) | verified | high | 2026-11-05 |
| [Docker 特权容器逃逸：挂载宿主机磁盘并写入 crontab](cloud-container-docker-privileged-host-disk-escape.md) | verified | high | 2026-11-05 |
| [Docker 自定义网桥 br-* 被防火墙全放行：容器经泄露 Token 调用宿主机 Host Command API](cloud-container-docker-custom-bridge-firewall-host-command-api.md) | verified | high | 2026-11-05 |
| [Harbor CVE-2022-46463 未授权访问：列举项目并 dump 镜像，从镜像层翻出 flag 与 Spring Boot 数据库口令](cloud-container-harbor-cve-2022-46463-unauth-image-dump.md) | verified | medium | 2026-11-08 |
| [K8s 危险工作负载配置逃逸宿主机（privileged/hostPath/hostPID）](cloud-container-k8s-workload-config-escape.md) | verified | high | 2026-11-04 |
| [NVIDIA Container Toolkit nvc_driver_mount TOCTOU 符号链接逃逸：挂载宿主机根目录并借 docker.sock 提权（CVE-2024-0132）](cloud-container-nvidia-toolkit-nvc-driver-mount-toctou-escape.md) | verified | medium | 2026-11-06 |
| [OCI 镜像 whiteout 层恢复被删除文件内容](cloud-container-oci-whiteout-deleted-file-recovery.md) | verified | high | 2026-11-06 |
| [runc 文件描述符泄漏容器逃逸：/proc/self/fd/8 读写宿主机与覆盖二进制（CVE-2024-21626）](cloud-container-runc-fd-leak-escape.md) | verified | high | 2026-11-06 |
| [sudo 授权 runc 包装器 + 可控 OCI config.json：bind mount 宿主机 /root 启动 uid=0 shell](cloud-container-sudo-runc-wrapper-oci-config-root.md) | verified | high | 2026-11-06 |
| [判断当前是否在 Docker 容器内：/.dockerenv 空文件与 /proc/1/cgroup 的 docker 前缀两条判据](cloud-container-docker-environment-identification-dockerenv-cgroup.md) | verified | high | 2026-11-12 |
| [容器共享挂载目录软链读取宿主文件：替换宿主侧读取的 error.txt 指向 /flag](cloud-container-bind-mount-symlink-host-file-read.md) | verified | medium | 2026-11-12 |
| [容器内核漏洞逃逸（Dirty Cow CVE-2016-5195）：共享内核下在容器内利用 dirtycow-vdso 回写宿主 vDSO 获取宿主 root shell](cloud-container-kernel-exploit-dirtycow-vdso-container-escape.md) | verified | high | 2026-11-13 |
| [容器内泄露 DB 凭据 → 连宿主机 MySQL 以 secure_file_priv 写宿主 Web 目录 getshell](cloud-container-mysql-host-outfile-webshell-pivot.md) | verified | high | 2026-11-08 |
| [容器同时持有 SYS_PTRACE 能力与 --pid=host 共享进程命名空间时，ptrace 注入宿主机 root 进程弹 shell 逃逸](cloud-container-sys-ptrace-pid-host-process-injection-escape.md) | verified | high | 2026-11-08 |
| [容器持有 CAP_DAC_READ_SEARCH 时用 shocker 爆破 inode 经 open_by_handle_at 读取宿主机任意文件（/etc/shadow）](cloud-container-cap-dac-read-search-shocker-open-by-handle-host-file-read.md) | verified | high | 2026-11-13 |
| [容器挂载宿主机 procfs：CDK mount-procfs 直接写宿主机 /root/.ssh/authorized_keys 逃逸](cloud-container-docker-host-procfs-mount-write-authorized-keys.md) | verified | high | 2026-11-05 |
| [拿到 Portainer 控制台后创建宿主机目录挂载容器：容器 console 内 chroot /host 接管宿主机](cloud-container-portainer-console-host-mount-container-escape.md) | verified | medium | 2026-11-12 |
| [私有镜像仓库定时拉取镜像的场景下，用同一 tag 重新 push 恶意镜像接管目标主机](cloud-container-registry-polling-image-tag-repoison-escape.md) | verified | medium | 2026-11-08 |
| [镜像 config/history 泄露构建期凭据：crane config / docker history 中的 RUN 参数、ARG 与环境变量](cloud-container-image-config-history-secret-leak.md) | verified | high | 2026-11-12 |
| [非特权容器误挂宿主机目录（df -h 可见 /dev/xxx 下整套宿主文件树）：直接改写宿主机 /etc/crontab 定时任务逃逸](cloud-container-host-dir-bind-mount-etc-crontab-escape.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
