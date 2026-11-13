---
id: binary-pwn-kernel-sys-kernel-notes-kaslr-leak
title: /sys/kernel/notes 泄露内核基址：world-readable ELF notes 中的内核地址绕过 KASLR
type: scenario
domain: binary
path: binary/pwn/kernel
technique: sys-kernel-notes-kaslr-base-leak
tags:
- linux
- kernel
- pwn
- kaslr
- infoleak
- sysfs
- elf-notes
- ubuntu
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V593
  verified_at: '2026-11-12T15:34:13+08:00'
  notes: 已对照原文核对：Ubuntu 22.04 普通用户 xxd /sys/kernel/notes 可读出 ELF notes，原文 dump 中 0xffffffff82e611c0（0x80 处 Xen note desc）与 0xffffffff81e3a000（0x98 处）均与卡片引用一致，按 vmlinux readelf -n 对照固定偏移可反推内核基址，原理/利用步骤与原文一致；『默认 0444 world-readable』依据原文 Ubuntu 环境普通用户可读的实测（具体 mode 未独立复核），并已注明不同发行版/版本偏移不可硬编码。未验证点：原文只给 xxd 输出与地址，未给完整换算代码，PoC 未在本机执行。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-sys-kernel-notes-kaslr-leak/
draft: false
kb_aliases:
- /sys/kernel/notes
- sysfs 泄露 KASLR
- 内核 notes 泄露
- KASLR 基址泄露
- proc sys 地址泄露
---

## 一句话结论

Ubuntu 等发行版的 `/sys/kernel/notes` 默认 world-readable，内容是内核 ELF notes（Xen/GNU/Linux note 段），其中含有指向内核镜像的绝对地址（如 `0xffffffff82e611c0`）；本地攻击者 `xxd` 读出这些地址，减去对应符号/段的固定偏移即可算出 KASLR 内核基址，为后续内核漏洞利用提供基址。

## 原理

- **文件来源**：`/sys/kernel/notes` 是内核通过 sysfs/kernfs 暴露的二进制属性，返回内核镜像的 ELF notes（`.notes` 段），用于 kexec/崩溃转储/虚拟化环境识别（Xen、GNU build-id、Linux 版本等）。note 段中的 `desc` 字段可能直接包含内核虚拟地址。
- **为什么是泄露**：note 数据里的地址是链接时确定的绝对内核地址（KASLR 随机化后仍以 `0xffffffff8...` 形式写入 note desc），与内核基址的差值固定（由 vmlinux/目标内核的段布局决定）。攻击者读文件即可得到"基址 + 常量"的一个实例，反推基址。
- **权限面**：该属性默认 `0444`，普通用户可读；无需任何漏洞。文章在 Ubuntu 22.04 上 `xxd /sys/kernel/notes` 直接看到 `0xffffffff82e611c0` 等值（还有 `0xffffffff81e3a000` 等），据此计算内核镜像基地址。
- **为什么有价值**：本地内核 exploit 需要知道 `commit_creds`、gadget、`kernfs_pr_cont_buf`、伪造函数指针等地址；KASLR 泄露是链条第一步，且此手法比信息泄露型 UAF 更稳定、无副作用。
- **注意**：具体哪个 qword 是基址需要按目标内核的 vmlinux/`readelf -n` 对照偏移；不同发行版/内核版本 note 内容与偏移不同，不能跨版本硬编码。

## 触发条件

- 目标内核在 sysfs 暴露 `/sys/kernel/notes` 且权限允许当前用户读取（Ubuntu 默认；部分加固发行版会收紧）。
- 攻击者有本地代码执行（低权限用户即可）。
- 攻击者掌握目标内核的 vmlinux 或对应版本的符号/偏移表，用于把泄露地址换算成基址与目标符号地址。

## 利用步骤

1. `xxd /sys/kernel/notes`（或 `read()` 整个文件）导出二进制内容。
2. 解析 ELF note 结构：`namesz/descsz/type/name/desc`；收集 desc 中的 qword 值，筛出 `0xffffffff8xxxxxxx` 形态的内核地址。
3. 对照目标内核 vmlinux 的 `readelf -n` / 符号偏移，确定该地址对应的符号/段偏移，计算 `kernel_base = leaked - offset`。
4. 用基址 + 固定偏移计算 `commit_creds`、`prepare_kernel_cred`、gadget、全局缓冲区（如 `kernfs_pr_cont_buf`）等地址，进入后续利用。

## PoC

```bash
xxd /sys/kernel/notes | head -0x20
# 输出中可见（Ubuntu 22.04 实测）：
# ... 0xffffffff82e611c0 ...
# 取该值的固定偏移即可换算内核基址（按目标 vmlinux 的 readelf -n 对照）
```

原文只给出 `xxd` 输出与地址，未给出完整换算代码；PoC 未在本机执行。

## 变体与关联

- 变体：`/sys/kernel/kexec_*`、`/proc/kallsyms`（`kptr_restrict=0` 时）、`/sys/module/*/sections/*`、`dmesg`（`dmesg_restrict=0`）等 sysfs/procfs 泄露面；文章总结指出 `/sys`、`/proc` 下常有地址泄露，可迁移到其它 exploit。
- 关联卡片：[[binary-pwn-kernel-cve-2023-6546-n-gsm-race-dlci-uaf-sched-window]]（本泄露的实际使用场景）、[[binary-pwn-kernel-kernfs-pr-cont-buf-cgroup-path-data-placement]]（基址泄露后定位全局缓冲区）。

## 检测与防御

- **加固**：收紧 `/sys/kernel/notes` 权限（root-only 或 0400）；开启 `kptr_restrict=2`、`dmesg_restrict=1`；用 `hidepid`/sysfs 挂载限制减少未授权读取面。
- **检测**：普通用户进程读取 `/sys/kernel/notes`（audit/syscall 监控）；随后短时间内出现内核 exploit 行为链时可作为前兆信号。
