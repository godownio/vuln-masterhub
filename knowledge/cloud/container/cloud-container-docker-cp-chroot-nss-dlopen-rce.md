---
id: cloud-container-docker-cp-chroot-nss-dlopen-rce
title: docker cp chroot 辅助进程 NSS dlopen 注入：容器内 libnss 以宿主机 root 执行（CVE-2019-14271）
type: scenario
domain: cloud
path: cloud/container
technique: docker-tar-chroot-nss-dlopen-host-root-rce
aliases:
- CVE-2019-14271
- docker-tar NSS 注入
- docker cp 动态库劫持
- chroot 辅助进程逃逸
tags:
- docker
- container-escape
- chroot
- nss
- dlopen
- shared-library
- cve-2019-14271
cve:
- CVE-2019-14271
severity: critical
confidence: high
status: verified
affected_versions: Docker 19.03.0（NVD：19.03.x before 19.03.1）；修复于 19.03.1（2019-07-26），18.09 系列回溯至 18.09.9（2019-09-03）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:52:48+08:00'
  notes: 已对照原文全文核对：docker-tar chroot 后 Go archive/tar FileInfoHeader→os/user.LookupId→glibc NSS dlopen 加载容器内 libnss、constructor 以 host root 执行、Unit 42 PoC 骨架、19.03.1 预加载/19.03.8 fork/23.0 nosysFileInfo 三层修复均与原文一致；PoC 未在本机执行。原文称 19.03.0 为主要受影响正式版，18.09 回溯修复于 18.09.9（卡片相应表述据此）。
---

## 一句话结论

Docker 19.03.0 为修复 CVE-2018-15664 引入了 `docker-tar` 辅助进程：它先 chroot 进容器 rootfs、再在宿主机命名空间以完整 root 权限打包；打包时 Go 标准库为填充 tar 头的用户名会触发 glibc NSS `dlopen("libnss_*.so")`，而这次加载发生在 chroot 之后、从容器文件系统解析——攻击者用恶意 `libnss_*.so` 即可让构造函数在宿主机 root 上下文执行代码。

## 原理

- `docker-tar` 的两个属性叠加成本漏洞：
  1. 它 chroot 到容器 rootfs，但并不是容器化进程：运行在宿主机命名空间，拥有全部 root 能力，不受 cgroup/seccomp 限制；
  2. 它用 Go `archive/tar` 生成 tar 头，`tar.FileInfoHeader` 会通过 `os/user.LookupId` / `LookupGroupId` 把 UID/GID 解析为用户名/组名。
- `os/user` 的 cgo 实现调用 libc 的 `getpwuid_r`/`getgrgid_r`；glibc 第一次调用时按 `/etc/nsswitch.conf` 通过 NSS 机制 `dlopen` 对应模块（如 `libnss_files.so.2`）。
- 因为这次 `dlopen` 发生在 `docker-tar` chroot 之后，动态库路径解析落在容器文件系统内。容器内替换 `libnss_*.so` 即可注入代码。
- 触发链：
  ```text
  docker cp → daemon.archivePath → chrootarchive.Tar
    → reexec.Command("docker-tar", ...)
      → realChroot(容器 rootfs)
      → archive.TarWithOptions
        → FileInfoHeader → sysStat
          → user.LookupId → getpwuid_r → glibc NSS
            → dlopen("libnss_files.so.2")   // 从容器内解析
              → 恶意库 constructor 以 host root 执行
  ```
- 该漏洞的暴露迹象很直观：从 `debian:buster-slim` 这类不含 libnss 的镜像执行 `docker cp` 会让 `docker-tar` 加载失败崩溃（moby issue #39449）。
- 本质：chroot 只改变文件视图，不改变权限与能力；“chroot 之后按需加载的动态库”由新根属主（容器）决定，因此 chroot 不是沙箱。

## 触发条件

- Docker 19.03.0（同时具备 `docker-tar`、Go 1.11、glibc 组合的正式版）；18.09 早期回溯版本在修复前同样受影响。
- 攻击者可在容器内写入文件并控制容器 rootfs（普通容器权限即可）。
- 宿主机侧会对该容器执行 `docker cp`（从容器取文件）。
- 目标 glibc 使用 NSS 且会解析用户/组名（默认配置）。

## 利用步骤

1. 在容器内放置恶意 `libnss_files.so.2`（或 glibc 会按 nsswitch 加载的其他 `libnss_*.so`），并把原库改名备份。
2. 恶意库使用 GCC `__attribute__((constructor))` 定义构造函数，库被 `dlopen` 时先于其他代码执行。
3. 构造函数先判断自己是否运行在 `docker-tar` 上下文（例如能否打开 `/proc/self/exe`），避免污染普通进程。
4. 命中后把真正的 libnss 换回原位（避免影响后续进程），再 `fork` + `execve` 容器内预置的逃逸程序（挂载宿主机文件系统、写任意文件、反弹 shell 等）。
5. 宿主机执行 `docker cp <victim>:/logs /tmp/out`，触发 `docker-tar` 打包，坏库被加载，逃逸程序以宿主机 root 运行。

## PoC

恶意库最小骨架（Unit 42 思路）：

```c
__attribute__ ((constructor)) void run_at_link(void)
{
    if (!is_priviliged())          // 打开 /proc/self/exe 判断是否在 docker-tar 上下文
        return;
    rename(ORIGINAL_LIBNSS, LIBNSS_PATH);   // 先换回真库，避免影响后续进程
    if (!fork()) {
        char *argv[] = { "/breakout", NULL };
        execve("/breakout", argv, NULL);    // 容器内预置的逃逸程序
    }
}
```

宿主机触发：

```bash
docker cp victim:/logs /tmp/out
```

## 变体与关联

- 变体：任何“chroot 后在主机命名空间以 root 运行、并按需加载/执行容器内内容”的辅助进程都存在同类风险；CVE-2026-41567 中按容器内 PATH 解析解压器二进制就是同一模式的新变体。
- 变体：同源加载点还包括可执行文件、PATH 查找、语言运行时模块；修复时需逐一排查。
- 关联：[[cloud-container-docker-cp-symlink-toctou-escape]]（本漏洞是修复该 TOCTOU 时引入的 chroot 方案的副作用）。
- 关联：[[cloud-container-docker-cp-copyescape-archive-inclusion-escape]]（29.x 新架构下同源问题的另一形态）。
- 边界：19.03.1 起在 chroot 前预加载 NSS、19.03.8 起 fork archive/tar 禁用用户名查找、23.0 起用 `nosysFileInfo` 从源头禁止查找，多层修复后本链失效。

## 检测与防御

- 升级：Docker ≥ 19.03.1（18.09 系列 ≥ 18.09.9）；更彻底地使用 23.0+（移除 chroot 辅助进程）。
- 加固：不以 root 运行 `docker cp` 自动化；对不可信容器取数前先停止容器或使用一次性隔离环境。
- 根治：归档路径不在 chroot 后做任何按需加载（预加载、禁用 NSS 查找、使用内核/进程内视图）。
- 检测：容器内出现被替换/新增的 `libnss_*.so*`；`docker cp` 期间 `docker-tar` 进程加载容器路径下的动态库；容器内 `__attribute__((constructor))` 恶意库特征。
- 检测：`docker cp` 后宿主机出现异常 root 进程、异常挂载或文件写入；`/proc/self/exe` 访问与 `docker-tar` 生命周期重合。
