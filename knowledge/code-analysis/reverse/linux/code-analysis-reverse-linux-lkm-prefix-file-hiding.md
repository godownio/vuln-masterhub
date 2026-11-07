---
id: code-analysis-reverse-linux-lkm-prefix-file-hiding
title: Linux 恶意内核模块按 secret_ 前缀隐藏文件：lsmod/dmesg 定位与原始文件系统枚举
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: linux-lkm-prefix-file-hiding
aliases:
- file_hider.ko
- Linux 内核模块隐藏文件
- LKM 按前缀隐藏文件
- getdents hook 隐藏文件
- dmesg Hiding files with prefix
- Linux rootkit 文件隐藏取证
tags:
- code-analysis
- reverse
- linux
- kernel-module
- lkm
- rootkit
- anti-forensics
- file-hiding
- dmesg
- lsmod
severity: medium
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T16:59:26+08:00'
  notes: 已对照原文问题32与图片38-40核对：file_hider.ko、secret_ 前缀隐藏、dmesg 日志与模块路径一致；原文无模块源码/二进制，PoC 为无，属取证定位卡。
---

## 一句话结论

攻击者加载自定义 Linux 内核模块（样例为 `file_hider.ko`），在目录枚举路径上过滤名字以 `secret_` 开头的条目，使常规 `ls`/`find` 看不到这些文件；通过 `lsmod`、`dmesg` 中的模块加载与隐藏日志可定位模块，再用离线镜像或跨系统枚举恢复被隐藏文件。

## 原理

- **内核态过滤**：可加载内核模块运行在 ring 0，可挂接 VFS 的目录遍历路径（如 `iterate_dir`/`filldir`、`getdents64` 系统调用或 syscall table hook），在把目录项返回给用户态之前丢弃名字匹配特定前缀的条目。
- **用户态工具同步失明**：`ls`、`find`、`rm`、杀毒/EDR 的文件枚举最终都走同一套内核目录读取接口；模块在更底层过滤后，这些工具看到的是被裁剪过的视图，因此“文件不存在”并不代表磁盘上没有。
- **样例行为**：模块加载时向内核日志打印 `Module loaded successfully, hooked at 0x...`，随后反复打印 `Hiding files with prefix 'secret_'`，并列出 `secret_txt.txt`、`secret_manager.py`、`secret_manager.cpython-310.pyc`、`secret_key` 等被隐藏文件名。模块文件位于 `/usr/lib/modules/5.15.0-161-generic/extra/file_hider.ko`。
- **为什么离线枚举能绕过**：隐藏发生在运行中的内核内存里，磁盘上的目录项和 inode 并未删除。把磁盘镜像只读挂载到未加载该模块的系统，或用 `debugfs`/`tsk`/`fls` 直接解析文件系统元数据，就能看到原始目录项。
- **前缀作为过滤条件**：模块只隐藏固定前缀，攻击者因此可以把敏感文件统一改名到该前缀下；防守方一旦知道前缀，就可以用 `find / -name 'secret_*'` 或原始介质枚举定向找回。

## 触发条件

- 攻击者已获得 root 权限，可执行 `insmod`/`modprobe` 加载模块（或模块被加入开机加载配置）。
- 模块针对目标内核版本编译（样例为 `5.15.0-161-generic`），且 Secure Boot/模块签名校验未阻止加载。
- 隐藏逻辑匹配固定文件名前缀；未覆盖的目录或未匹配的文件仍可能被常规工具看到。

## 利用步骤

1. 枚举已加载模块：`lsmod | grep -i hider`、`cat /proc/modules`，检查 `/sys/module/file_hider`。
2. 查看内核日志：`dmesg | grep -iE 'hider|hooked|Hiding files'`，提取隐藏前缀与被隐藏文件名列表。
3. 用前缀定向查找：`find / -name 'secret_*' 2>/dev/null`，比对常规目录列表与查找结果。
4. 对仍不可见的文件，将磁盘镜像只读挂载到干净系统，或用 `debugfs -R 'ls -l /path'`、`fls -r` 等直接解析目录项。
5. 检查模块文件：`modinfo /usr/lib/modules/$(uname -r)/extra/file_hider.ko`、`strings`、签名状态，并核对 `cat /proc/sys/kernel/tainted` 的 taint 标志。

## PoC

无 PoC（原文未提供模块源码或二进制，仅给出加载日志与隐藏文件名清单）。

## 变体与关联

- 变体：hook `sys_getdents64` 过滤任意前缀/后缀，或按 inode 精确隐藏单个文件。
- 变体：同类 LKM 还可过滤 `/proc` 隐藏进程、过滤网络接口或端口，形成完整 rootkit。
- 关联卡片：[[defense-forensics-overlayfs-mount-shadowing-log-hide]]、[[defense-forensics-linux-process-name-masquerade-comm-cmdline]]、[[defense-incident-response-linux-c2-watchdog-cleanup-order]]。

## 检测与防御

- 检测：`dmesg`/`journalctl -k` 出现未知模块的 `Module loaded successfully, hooked at`、`Hiding files with prefix` 等日志。
- 检测：`lsmod`/`/proc/modules` 出现非发行版、非硬件厂商模块；`/lib/modules/*/extra/` 存在无签名 `.ko`。
- 检测：同一目录在运行系统与离线镜像中的条目数量/名称不一致；`find` 结果与 `ls` 视图不一致。
- 防御：启用 Secure Boot 与内核模块签名强制；生产机设置 `kernel.modules_disabled=1`（在加载完必要模块后）；监控模块加载与 `dmesg` 告警；定期对关键目录做离线完整性比对。
