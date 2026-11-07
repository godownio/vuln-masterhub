---
id: binary-pwn-kernel-qemu-initramfs-gdb-workflow
title: 内核 pwn 环境搭建与调试：bzImage/initramfs/9P 共享与 GDB 符号加载
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-pwn-qemu-initramfs-gdb-workflow
tags:
- kernel
- pwn
- qemu
- gdb
- initramfs
- bzimage
- vmlinux
- debugging
- ctf
- environment
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:38:34+08:00'
  notes: 已对照原文与12张图核对：bzImage/rootfs.cpio.gz/init/run.sh 四件套说明、cpio --format=newc 解包打包与 070701 校验、9P virtfs 共享、vmlinux-to-elf/extract-vmlinux、qemu -s -S、gdb file vmlinux.elf+add-symbol-file kpark.ko 0xffffffffc0000000+target remote 均与原文一致（图07-11）。未验证点：未在本机执行整套环境；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-qemu-initramfs-gdb-workflow/
draft: false
kb_aliases:
- 内核题环境搭建
- bzImage 解包
- rootfs.cpio.gz 打包
- 9P 共享目录
- vmlinux-to-elf
- add-symbol-file
- qemu -s -S
---

## 一句话结论

内核 pwn 题通常由 `bzImage`（压缩内核）、`rootfs.cpio.gz`（initramfs 根文件系统）、`/init`（挂载文件系统、insmod 驱动、降权）和 `run.sh`（QEMU 启动命令）组成；掌握 cpio 解包/打包、9P 共享、`vmlinux-to-elf` 提取符号与 `qemu -s -S` + GDB 远程调试，才能稳定复现漏洞、改 exp、下断点并观察内核对象。

## 原理

- **bzImage**：压缩的内核镜像，QEMU `-kernel` 装入后由内核自解压；本身不带符号，需要 `vmlinux-to-elf`/`extract-vmlinux` 还原 `vmlinux` 才能用源码级符号调试。
- **rootfs.cpio.gz**：打包好的 initramfs，内核启动时解包进内存作为 `/`（不是挂载块设备），并执行 `/init`；`/init` 通常挂载 proc/sys/devtmpfs/tmpfs、`insmod /kpark.ko`、给 `/dev/xxx` 权限，再用 `setsid`/`su` 把 shell 降权到普通用户。
- **.ko**：漏洞驱动，`ioctl`/read/write 等入口在这里；模块加载基址通常可通过 `/sys/module/<name>/sections/.text`、`dmesg` 或 GDB 查看。
- **run.sh**：把以上拼成 QEMU 命令；常见参数 `-m 256M -kernel bzImage -initrd rootfs.cpio.gz -append "console=ttyS0 oops=panic panic=1 nokaslr quiet" -cpu qemu64,+smep,+smap -no-reboot -nographic -monitor none`；`-virtfs local,path=...,mount_tag=host0` 把宿主机目录以 9P 共享给 guest 的 `/mnt`；`-s -S` 开启 GDB stub 并在启动时暂停。
- **KASLR**：`nokaslr` 让内核/模块基址固定，便于下断点和计算偏移；真实利用若开 KASLR，需要先泄露基址，再计算函数/对象地址。
- **调试**：`gdb vmlinux.elf` 加载内核符号，`add-symbol-file kpark.ko <module_base>` 加载模块符号，`target remote :1234` 连接 QEMU；断点可按符号名、模块基址+偏移、或内核函数入口设置。
- **打包细节**：cpio 必须用 `--format=newc` 且输出 gzip；打包后校验 magic `070701` 和文件列表，避免 initramfs 损坏导致内核 panic。

## 触发条件

- 题目提供 `bzImage`、`rootfs.cpio.gz`、`.ko`、`run.sh`（可能还有 Makefile/README）。
- 本地有 QEMU、gdb、cpio、gzip、musl-gcc/交叉编译工具链。
- 需要修改 rootfs（放入 exp、改 init/flag）或调试内核/模块。
- 有权限运行 QEMU 与 GDB（本地实验环境）。

## 利用步骤

1. **清点与读脚本**：`ls -lh` 查看附件；`cat run.sh`、`cat README.md`；解包后查看 `/init` 的 insmod、设备权限与降权逻辑。
2. **解包 rootfs**：
   ```bash
   mkdir -p rootfs && cd rootfs
   zcat ../rootfs.cpio.gz | cpio -idmv --no-absolute-filenames
   ```
3. **放入 exp / 修改 init**：把静态编译的 exp 拷到 rootfs，`chmod 755`；必要时修改 `/init` 的权限或启动命令；注意保持软链接与设备节点。
4. **重新打包**：
   ```bash
   find . -print0 | cpio --null -o --format=newc | gzip -9 > ../rootfs-new.cpio.gz
   zcat ../rootfs-new.cpio.gz | head -c 6   # 应为 070701
   zcat ../rootfs-new.cpio.gz | cpio -t | grep -E '^(exp|init|kpark.ko|flag)$'
   ```
5. **编译 exp**：`musl-gcc -O2 -static -Wall -Wextra -o exp exp.c`（静态链接，避免 guest 缺库）。
6. **启动 QEMU**：
   ```bash
   qemu-system-x86_64 -m 256M \
     -kernel bzImage -initrd rootfs-new.cpio.gz \
     -append "console=ttyS0 oops=panic panic=1 nokaslr quiet" \
     -cpu qemu64,+smep,+smap -no-reboot -nographic -monitor none \
     -virtfs local,path="$PWD",mount_tag=host0,security_model=none,readonly=on \
     -s -S
   ```
7. **提取 vmlinux 并加载符号**：
   ```bash
   vmlinux-to-elf bzImage vmlinux.elf          # 或 extract-vmlinux bzImage > vmlinux
   gdb -q vmlinux.elf \
     -ex "set pagination off" \
     -ex "add-symbol-file kpark.ko 0xffffffffc0000000" \
     -ex "target remote 127.0.0.1:1234"
   ```
8. **guest 内使用 9P**：`mount -t 9p -o trans=virtio host0 /mnt`，把宿主机编译好的 exp 拷到 `/tmp` 执行；`ls -l /sys/module/kpark/sections/.text` 可查模块实际基址。
9. **下断点**：按符号 `b kpark_ioctl`、按地址 `b *0xffffffffc000039d`、或按内核函数 `b __x64_sys_ioctl`；用 `pwndbg`/`tele` 查看 slab 对象布局。
10. **排错**：端口占用 `lsof -i :1234`；QEMU 不启动检查 `-append` 控制台与 initramfs magic；内核 panic 检查 `/init` 是否可执行、设备节点是否缺失。

## PoC

```bash
# 解包
mkdir -p rootfs && cd rootfs
zcat ../rootfs.cpio.gz | cpio -idmv --no-absolute-filenames

# 放入 exp 并打包
cp /path/exp ./exp && chmod 755 ./exp
find . -print0 | cpio --null -o --format=newc | gzip -9 > ../rootfs-new.cpio.gz

# 校验
zcat ../rootfs-new.cpio.gz | head -c 6      # 070701
zcat ../rootfs-new.cpio.gz | cpio -t | head
```

```bash
# 启动并等待 GDB
qemu-system-x86_64 -m 256M -kernel bzImage -initrd rootfs-new.cpio.gz \
  -append "console=ttyS0 oops=panic panic=1 nokaslr quiet" \
  -cpu qemu64,+smep,+smap -no-reboot -nographic -monitor none \
  -virtfs local,path="$PWD",mount_tag=host0,security_model=none,readonly=on \
  -s -S

# 另一个终端
gdb -q vmlinux.elf -ex "set pagination off" \
  -ex "add-symbol-file kpark.ko 0xffffffffc0000000" \
  -ex "target remote 127.0.0.1:1234"
```

```text
# guest 内挂载 9P（若 init 未自动挂载）
mount -t 9p -o trans=virtio host0 /mnt
cp /mnt/exp /tmp/exp && chmod +x /tmp/exp && /tmp/exp
```

## 变体与关联

- 变体：rootfs 为 ext4 磁盘镜像时用 `-drive file=rootfs.img,format=raw` 与 `-append "root=/dev/sda"`；initramfs 为未压缩 cpio 时去掉 gzip。
- 变体：不同架构（aarch64/riscv）用对应 `qemu-system-*` 与交叉编译工具链；GDB 用 `gdb-multiarch`。
- 变体：开启 KASLR 时用 `nokaslr` 关闭，或先泄露内核/模块基址再计算偏移；SMEP/SMAP 开启时避免直接跳用户态。
- 关联：[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（同一题目的 UAF 利用）、[[code-analysis-reverse-windows-kernel-debugging-vmware-windbg]]（Windows 内核双机调试的另一套工作流）、[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（内核提权案例）。
- 边界：题目不提供 `run.sh`/`init`、使用自定义文件系统或安全启动时，需要自行构造启动参数；GDB stub 被禁用时可用 QEMU monitor/串口日志替代。

## 检测与防御

- 本卡是 CTF/研究环境工作流，不针对生产攻击面；生产环境应限制 QEMU/KVM 与 GDB 使用权限，避免调试接口暴露。
- 对内核模块开发：用 KASAN/KCSAN、`CONFIG_DEBUG_SLAB`、`init_on_free` 辅助发现 UAF/越界；模块加载前校验签名，设备节点最小权限。
- 对比赛/实验：每次修改 rootfs 后校验 cpio magic 与文件列表；保留原始镜像，避免打包错误导致题目环境损坏。
- 监控：生产主机上出现 `qemu-system` + `-s -S`、非授权内核模块加载、`/dev` 设备权限被修改等异常行为时告警。

