---
id: ctf-pwn-gcc15-ubuntu2604-cet-no-libc-csu-adaptation
title: GCC 15 / Ubuntu 26.04 PWN 靶场适配：__libc_csu_init 消失、CET 默认开启、手动注入 pop rdi gadget 与栈对齐
type: scenario
domain: ctf
path: ctf/pwn
technique: gcc15-ubuntu2604-pwn-toolchain-cet-csu-adaptation
aliases:
- GCC 15 PWN
- Ubuntu 26.04 PWN
- __libc_csu_init 消失
- ret2csu 失效
- CET 默认开启
- fcf-protection=none
- 手动注入 pop rdi
- 栈对齐 ret gadget
tags:
- ctf
- pwn
- gcc
- ubuntu
- cet
- ret2csu
- rop
- stack-alignment
- toolchain
- environment
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:46+08:00'
  notes: 已对照原文与4张内嵌图核对：Ubuntu 26.04/GCC 15.2/glibc 2.43、__libc_csu_init计数为0、CET默认开启与-fcf-protection=none、内联汇编注入pop_rdi_ret、system前加ret对齐、-Werror行为变化均一致。属工具链环境适配卡，原文未给受影响组件版本区间，未设affected_versions。未验证点：未在GCC 15环境复跑PoC；原文Ubuntu代号noble与26.04不符但未写入卡片；frontmatter无sources/source_url。
---

## 一句话结论

在 Ubuntu 26.04 / GCC 15 上搭 PWN 靶场时，两处默认变化会让经典教程失效：`__libc_csu_init` 不再生成，依赖它的 ret2csu gadget（`pop rdi; pop rsi; pop rdx; ret` 等）全部消失；CET 默认开启，ROP `ret` 到没有 `endbr64` 的地址会直接 SIGILL。本地靶场用 `-fcf-protection=none` 关闭 CET，并用内联汇编手动注入 `pop rdi; ret`（或泄露 libc 后在 libc 中搜索 gadget）；`system` 前仍要加一个 `ret` 做 16 字节栈对齐。

## 原理

- **GCC 15 移除 `__libc_csu_init`**：该函数过去在 `main` 前初始化 libc 构造函数，其中包含一组可用于 ret2csu 的通用 gadget（`pop rbx/rbp/r12-r15; ret` 与 `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]`）。GCC 15 改用新的初始化方式，函数不再生成；`objdump -d | grep __libc_csu_init` 返回 0。
- **替代 gadget**：本地靶场可在 C 源码用内联汇编注入：
  ```c
  __asm__(".global pop_rdi_ret\npop_rdi_ret:\npop %rdi\nret\n");
  ```
  编译后 `e.symbols['pop_rdi_ret']` 可直接引用。远程 binary 不能改源码，只能在泄露 libc 基址后用 `ROP(libc).find_gadget(['pop rdi','ret'])` 从 libc 中找，或寻找二进制内其它等价 gadget。
- **CET 默认开启**：GCC 15 默认带 `-fcf-protection`，`readelf -n` 可见 CET 相关 note。CET 的 shadow stack/IBT 会检查 `ret` 目标是否有 `endbr64`；ROP 跳到任意 gadget 会触发 SIGILL（不是 SIGSEGV），表现为“地址算对了但 ret 就崩”。
- **本地关闭 CET**：编译靶场加 `-fcf-protection=none`；远程目标若开启 CET/SHSTK，需要寻找以 `endbr64` 开头的 gadget、使用 `call`/`jmp` 兼容路径，或改用不依赖任意 ret 的利用方式（视目标保护而定）。
- **`-Werror` 行为变化**：GCC 15 把 `implicit-function-declaration` 等警告变成错误；`read`/`write` 忘记 `#include <unistd.h>` 会直接编译失败。写靶场时先补齐头文件。
- **栈对齐**：x86-64 System V ABI 要求进入被调函数时 `RSP % 16 == 8`；`system` 内部使用 `movaps` 等 SSE 指令，若 `RSP % 16 == 0` 会在 `system` 内部 SIGSEGV（调用栈通常停在 `__GI___IO_do_write`/`_IO_new_file_overflow`）。在 `system` 前加一个 `ret` gadget 把 RSP 下推 8 字节即可修正；但要看溢出帧布局，可能需要加 0 或 1 个 ret。
- **区分 CET 与对齐**：SIGILL 发生在 `ret` 指令本身，多为 CET/IBT；SIGSEGV 发生在 `system` 内部，多为栈对齐或地址错误。

## 触发条件

- 在 Ubuntu 26.04 / GCC 15（或类似新工具链）上编译/运行 PWN 靶场，或打使用新工具链编译的远程题目。
- 经典教程依赖 `__libc_csu_init`/ret2csu、默认无 CET、默认有 `pop rdi; ret`。
- 需要本地复现 ret2libc/ret2win/ORW 等栈利用，且 binary 可能开启 CET/SHSTK。
- 目标 libc 版本与本地不同，需要泄露后从 libc 搜索 gadget。

## 利用步骤

1. `gcc --version`/`lsb_release -a` 确认 GCC 15 / Ubuntu 26.04；`objdump -d binary | grep -c __libc_csu_init` 确认是否为 0。
2. `readelf -n binary | grep -i cet` 检查 CET；本地靶场编译时加 `-fcf-protection=none`，远程目标保留原保护。
3. 本地需要 `pop rdi; ret` 时，在源码内联汇编注入并给符号命名；远程则在泄露 libc 后用 `ROP(libc).find_gadget` 搜索。
4. 构造 ret2libc 两阶段：`puts(puts@got)` 泄露 libc 基址，再 `pop rdi; /bin/sh; system`；在 `system` 前加一个 `ret` 做对齐。
5. 若在 `system` 内 SIGSEGV，尝试增删一个 `ret`；若在 `ret` 上 SIGILL，检查 CET/SHSTK 与 gadget 是否以 `endbr64` 开头。
6. 远程 libc 不匹配时，用泄露地址 + libc-database 反查，或使用题目附件 libc。

## PoC

```bash
# 本地靶场编译（关闭 canary/PIE/CET，栈可执行按需）
gcc vuln.c -o vuln -fno-stack-protector -no-pie -fcf-protection=none
gcc vuln_shellcode.c -o vuln_sc -z execstack -fno-stack-protector -no-pie -fcf-protection=none

# 检查
objdump -d vuln | grep -c __libc_csu_init   # 期望 0
readelf -n vuln | grep -i cet                # 关闭后应无 CET
```

```c
// 手动注入 pop rdi; ret
__asm__(".global pop_rdi_ret\npop_rdi_ret:\npop %rdi\nret\n");
```

```python
# ret2libc 两阶段（栈对齐：system 前加 ret）
pl1 = b'A' * 72 + p64(pop_rdi) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(e.symbols['main'])
# ... 泄露并计算 libc_base ...
pl2 = b'A' * 72 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
```

原文在 Ubuntu 26.04 / GCC 15.2 / glibc 2.43 上验证了上述流程；未在本库复跑。

## 变体与关联

- **工具链变体**：GCC 13/14（Ubuntu 24.04）仍有简化版 `__libc_csu_init`，CET 默认开启；GCC 11/12（22.04）大部分教程仍有效；GCC 9/10（20.04）经典 ret2csu 可用。
- **CET 变体**：`-fcf-protection=none` 本地关闭；远程若开启，寻找 `endbr64` gadget、使用 `call`/`jmp`、或改用数据/堆利用。
- **gadget 变体**：内联汇编注入、libc 搜索、`ROPgadget`/`ropper`、one_gadget、ret2dlresolve。
- **对齐变体**：加一个 `ret`、`win+1` 跳过 `push rbp`、调整溢出填充、用 `pop rbp; ret` 等。
- **关联卡片**：[[binary-pwn-stack-ret2text-win-plus-one-align]]（win+1 栈对齐）、[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]（经典 ret2csu）、[[binary-pwn-stack-ret2libc]]（ret2libc 基础）。

## 检测与防御

- **对 CTF 选手**：拿到 binary 先看 GCC/Ubuntu 版本线索、`__libc_csu_init` 是否存在、CET note；不要照搬旧教程的 gadget 偏移。
- **对靶场/题目作者**：明确编译选项与 libc 版本；本地靶场可关闭 CET，但远程题应说明保护；提供 libc.so 附件。
- **对防守方**：生产环境启用 CET/SHSTK、Full RELRO、PIE、canary，提高 ROP 门槛；但不要依赖单一保护，仍需代码审计与补丁。
- **检测**：SIGILL 在 ret 上（CET）、SIGSEGV 在 system 内部（对齐）、libc 基址与符号偏移不匹配等调试信号。
