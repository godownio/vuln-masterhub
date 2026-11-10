---
id: code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch
title: 异构架构二进制（PowerPC/ARM/AArch64/MIPS）的 QEMU user-mode 运行与 gdb-multiarch 远程调试环境搭建
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: heterogeneous-arch-qemu-user-gdb-multiarch-setup
tags:
- qemu
- qemu-user
- gdb-multiarch
- cross-arch
- powerpc
- arm
- mips
- aarch64
- debugging
- endianness
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:34:49+08:00'
  notes: 已对照原文核对；本次核对未读取图片；qemu-user/-static 与 -L 交叉根、qemu -g 1234 起 gdbstub、gdb-multiarch 的 set architecture/set endian、以及 pwntools big-endian 打包均与正文命令一致。未验证点：未实际安装 qemu/gdb-multiarch，指令输出与截图未核对
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch/
draft: false
kb_aliases:
- qemu-ppc 调试
- gdb-multiarch 跨架构调试
- 异构 PWN 环境搭建
- qemu-user -L 交叉 libc
- arm mips ppc 仿真运行
- set endian big
---

## 一句话结论

面对非 x86 的 ELF（ppc/arm/aarch64/mips/mipsel）时，`qemu-<arch>`（动态链接需 `-L` 指定交叉根目录）或 `qemu-<arch>-static`（静态链接可直接跑）负责执行，`gdb-multiarch` 通过 `qemu -g <port>` 暴露的 gdbstub 远程接入，并在连上前后分别用 `set architecture` / `set endian` 声明架构与字节序，否则反汇编与寄存器解读全错。

## 原理

- QEMU 的 user-mode（`qemu-user`）只模拟 CPU 指令与系统调用层，不是整机模拟：它把目标架构的指令翻译执行，并把 syscall 转给宿主内核。因此进程的地址空间、文件系统仍是宿主的，速度足够做单二进制调试。
- 静态链接 vs 动态链接决定用哪个二进制与是否需要 `-L`：`qemu-<arch>-static` 自带所需库，可直接运行静态程序；动态链接程序需要目标架构的 ld.so 与 libc（`apt install libc6-<arch>-cross`，装到 `/usr/<arch>-linux-gnu[abihf]/`），再用 `-L <该目录>` 告诉 qemu 去哪找解释器与库。
- 架构与字节序是两件事：`gdb-multiarch` 需要先 `set architecture powerpc:common` / `arm` / `mips` 指定指令集，再对 PowerPC 这类大端目标 `set endian big`；只设架构不设端序会得到「能反汇编但值是反的」的错觉。
- `-g <port>` 让 qemu 在启动时监听 gdbstub，此时程序**停在入口**等 gdb `target remote` 后才继续，因此断点与寄存器检查都能从第一条指令开始；这比事后 attach 更稳定。
- 逐架构指令集差异决定了 exploit 写法：PowerPC 用 `LR`/`CTR`（`bl` 存返回地址、`mtctr`+`bctrl` 间接调用），ARM32 用 `r0-r3` 传参与 `LR`，MIPS 没有 `call/ret` 而是 `$ra` + 函数序言把 `$ra`/`$fp` 存栈。因此跨架构移植 exploit 时「返回地址在哪、参数怎么给」必须按目标 ABI 重算，不能照搬 x86 经验。
- 大端目标还要在 payload 侧对齐：pwntools 里 `context.endian='big'` 后再 `p32`，否则写入的地址字节序颠倒。

## 触发条件

- 目标二进制为 `file` 可识别的非本机架构 ELF，且需要动态观察（寄存器状态、断点、内存布局）。
- 已安装 `qemu-user`/`qemu-user-static` 与 `gdb-multiarch`；动态链接目标还需对应架构的交叉 libc。
- 需要编写或验证 ROP/exploit，必须确认 gadget 地址、传参寄存器与栈布局。
- 目标未加壳/未做反仿真（反仿真场景需另作处理）。

## 利用步骤

1. `file ./bin` 确认架构、字节序与链接方式（如 `ELF 32-bit MSB executable, PowerPC`、`ELF 32-bit LSB, ARM, statically linked, stripped`）。
2. 静态链接：直接 `qemu-<arch>-static ./bin`；动态链接：`apt search "libc6-" | grep <arch>` 装交叉库，再 `qemu-<arch> -L /usr/<arch>-linux-gnu ./bin`。
3. 调试启动：`qemu-<arch> -g 1234 -L <cross-root> ./bin`（静态则去掉 `-L`）。
4. 另开终端：`gdb-multiarch -q -ex "set architecture <arch>" ./bin`，随后在 gdb 内 `set endian <big|little>`（按需）与 `target remote :1234`。
5. 在关键指令（如 `bctrl`、`blx`、`jr $ra`）下断，`c` 继续，检查传参寄存器（PPC `r3`、ARM `r0`、MIPS `$a0`）与返回地址来源（`LR`/`LR`/栈上 `$ra`）。
6. 交叉库版本要与目标匹配：`/usr/<arch>-linux-gnu/lib/libc-<ver>.so` 可复制出来给 pwntools 做符号/偏移计算。

## PoC

```text
# 静态：PowerPC 32-bit 大端
$ qemu-ppc-static ./main

# 动态：ARM32，指定交叉根
$ qemu-arm -L /usr/arm-linux-gnueabihf/ ./chall

# 调试：qemu 侧监听 1234
$ qemu-ppc -g 1234 -L /usr/powerpc-linux-gnu ./main

# gdb 侧
$ gdb-multiarch -q -ex "set architecture powerpc:common" ./main
(gdb) set endian big
(gdb) target remote :1234
```

pwntools 侧大端打包：

```python
from pwn import *
context.endian = 'big'
p = process(['qemu-ppc-static', './main'])
```

判定：`target remote` 后 `info registers` 能读到合理值、`x/i $pc` 反汇编与 IDA 一致，即环境正确；若指令乱码先查 `set architecture`/`set endian`。

## 变体与关联

- 变体：整机/内核级场景改用 `qemu-system-<arch>`（需内核与 rootfs，配合 `-kernel`/`-hda`/`-append`），不适用 `-L`。
- 变体：无法装 `gdb-multiarch` 时可用 IDA 的 remote debug（`gdbserver`/`qemu -g` 均可），寄存器视图等价。
- 变体：固件场景把 squashfs-root 当根目录 `chroot` 后运行 `qemu-<arch>-static`，并需 `LD_PRELOAD` 伪造厂商库。
- 关联：[[binary-pwn-rop-powerpc32-indirect-call-hijack-register-arg]]（PPC `LR`/`CTR` 体系下的实测用法）。
- 关联：[[binary-pwn-rop-arm32-stripped-ret2libc-pop-r0-static]]（ARM32 `r0-r3` 体系下的实测用法）。
- 关联：[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（固件 + `LD_PRELOAD` 伪造厂商库的 MIPS 落地）。

## 检测与防御

- 说明（非攻击场景）：本卡是分析环境搭建，防御侧对应的是「设备/程序对非原生仿真的检测」。
- 检测（反仿真侧）：检查 `/proc/self/maps` 中的 qemu 痕迹、非原生 CPU 特性缺失、指令时序异常等。
- 加固：对关键校验逻辑加入架构/端序自检或反调试，抬高跨架构仿真分析的难度。
