---
id: cloud-container-docker-cp-symlink-toctou-escape
title: docker cp 符号链接 TOCTOU 逃逸：容器内换链使 daemon 以 root 读写宿主机文件（CVE-2018-15664）
type: scenario
domain: cloud
path: cloud/container
technique: docker-cp-symlink-toctou-host-file-access
tags:
- docker
- container-escape
- symlink
- toctou
- race-condition
- cve-2018-15664
cve:
- CVE-2018-15664
severity: critical
confidence: high
status: verified
affected_versions: Docker through 18.06.1-ce-rc2（NVD/OSV）；修复随 18.09.7（2019-06-27）与 19.03.0（2019-07-22）发布
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:52:46+08:00'
  notes: 已对照原文全文核对：FollowSymlinkInScope→StatPath→TarWithOptions 的 TOCTOU 链、renameat2(RENAME_EXCHANGE)、读方向命中率<1%、写方向因 chrootarchive.Untar chroot 到目标父目录而更易命中、受影响 18.06.1-ce-rc2 及修复 18.09.7/19.03.0 均与原文一致；PoC 未在本机执行。
url: /docs/cloud/container/cloud-container-docker-cp-symlink-toctou-escape/
draft: false
kb_aliases:
- CVE-2018-15664
- docker cp 符号链接交换
- docker cp TOCTOU 逃逸
- FollowSymlinkInScope 竞态
---

## 一句话结论

Docker 18.06 及更早版本的 daemon 在处理 `docker cp` 时，先用 `FollowSymlinkInScope` 在“容器视角”解析路径并做安全检查，之后才以宿主机 root 视角真正打开/写入该路径；容器内进程在检查与使用之间把路径替换成指向宿主机目录的符号链接，即可让 `docker cp` 以 root 读写宿主机任意文件。

## 原理

- 容器隔离只约束“容器内进程 → 宿主机”，不约束“宿主机进程 → 容器文件系统”。因此 `docker cp` 这类由主机进程访问容器 rootfs 的操作，必须由用户态自行保证路径不逃出容器。
- 修复前 `daemon/archive.go` 的 `containerArchivePath` 流程是：
  ```text
  ① container.ResolvePath(path)
       └─ symlink.FollowSymlinkInScope(join(Root, path), Root)   // 按容器视角解析，保证不越界
  ② container.StatPath(resolvedPath, absPath)                   // 再次使用路径
  ③ archive.TarResourceRebaseOpts(...)
  ④ archive.TarWithOptions(sourceDir, opts)                     // 最终以宿主机视角打开
  ```
- `FollowSymlinkInScope` 本身是安全的解析器，但它只保证“解析那一刻”的结果不越界。解析（①）与实际打开（④）之间隔着 stat、rebase 计算等步骤，容器进程可以在这段窗口内修改文件系统（TOCTOU）。
- 攻击者放置一个“指向 `/` 的符号链接”，用 `renameat2(RENAME_EXCHANGE)` 与空目录循环交换；daemon 若在 ②/④ 阶段跟随了该链接，就会以宿主机 root 身份操作宿主机路径。
- 写方向更容易命中：当时 `chrootarchive.Untar` 会 chroot 到“归档目标目录的父目录”，而该父目录在写场景下由攻击者控制；一旦竞态命中，chroot 位置已经是攻击者选定的，后续写入必然逃逸。

## 触发条件

- Docker ≤ 18.06.x（含 18.06.1-ce-rc2），且 `docker cp` 可用。
- 攻击者能在容器内运行进程并反复执行 rename/renameat2 等文件系统操作（普通容器权限即可）。
- 攻击者知道或能触发宿主机侧执行 `docker cp`（CI/CD 自动复制、运维调试、取证等常见场景）。
- 读方向需要命中 daemon 解析与打开之间的窗口（概率低但可重复尝试）；写方向命中窗口小得多。

## 利用步骤

1. 在容器内准备两个对象：一个指向宿主机目标目录（如 `/`）的符号链接，和一个同名的空目录。
2. 容器内循环执行 `renameat2(AT_FDCWD, link, AT_FDCWD, dir, RENAME_EXCHANGE)`，不断交换二者。
3. 宿主机侧对容器执行 `docker cp`（读或写）：
   - 读：`docker cp victim:/watched/path /host/dest`
   - 写：`docker cp /host/src victim:/watched/path`
4. 命中窗口时，daemon 在宿主机视角跟随符号链接，读取或写入宿主机目标文件。
5. 反复尝试直至成功；读方向单次命中率低于 1%，写方向通常只需极少次迭代。

## PoC

最小思路（容器内竞态循环）：

```c
// 反复交换：link -> / 与空目录 dir
while (1) {
    renameat2(AT_FDCWD, "link", AT_FDCWD, "dir", RENAME_EXCHANGE);
}
```

宿主机侧触发：

```bash
docker cp victim:/watched/passwd /tmp/out        # 读方向
docker cp /tmp/authorized_keys victim:/watched/  # 写方向
```

公开 PoC 为 cyphar 在 oss-security 披露时附带的竞态程序；本卡不复述其完整源码。

## 变体与关联

- 变体：同类的“主机进程访问容器文件系统”功能（export、volume、备份恢复）都可复用同一模型：只要解析与使用之间存在窗口，就可尝试符号链接交换。
- 变体：Podman 的 copy 出现过同类问题（CVE-2019-10152 / CVE-2019-18466），Podman export volume 后续也重新暴露（CVE-2023-0778）。
- 关联：[[cloud-container-docker-cp-chroot-nss-dlopen-rce]]（同一 `docker cp` 管线在修复 chroot 后引入的新漏洞）。
- 关联：[[cloud-container-docker-cp-copyescape-archive-inclusion-escape]]（2026 年新架构下同源问题的回归）。
- 边界：修复版（18.09.7+/19.03.0+）把归档操作 chroot 到容器根，宿主机视角不再直接解析容器内符号链接，本链失效。

## 检测与防御

- 升级：Docker ≥ 18.09.7 或 ≥ 19.03.0；更彻底地使用 23.0+ 的进程内视图/29.x 的 openat2 实现。
- 缓解：不要在不可信容器运行期间对其执行 `docker cp`；复制前停止容器可消除竞态前提。
- 加固：`docker cp` 不以 root 运行（避免 `sudo docker cp`）；限制容器内可执行文件系统操作的能力。
- 检测：容器内高频 `renameat2(RENAME_EXCHANGE)`/`rename` 系统调用（auditd、Falco 规则）；宿主机在 `docker cp` 期间访问了预期之外的文件（如 `/etc/shadow`、`/root/.ssh`）。
- 检测：`docker cp` 的源路径在容器内是符号链接且指向绝对路径，尤其是短时间内反复出现同名链接/目录。
