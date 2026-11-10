---
id: code-analysis-reverse-linux-copy-from-user-stac-clac-access-ok
title: copy_from_user 源码链：access_ok → _copy_from_user → get_user_asm（STAC/CLAC）→ 异常表与页缺失
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: linux-copy-from-user-stac-clac-exception-table
aliases:
- copy_from_user 源码分析
- access_ok
- __get_user_asm
- STAC CLAC
- SMAP 用户态访问
- 异常表 exception table
- 用户态/内核态地址空间
- MMU 页表翻译
tags:
- reverse
- linux
- kernel
- uaccess
- copy_from_user
- smap
- mmu
- exception-table
- x86-64
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T09:32:41+08:00'
  notes: 已对照原文与 44/44 截图核对：copy_from_user→check_copy_size、_copy_from_user 的 might_fault/should_fail_usercopy/access_ok/raw_copy_from_user、copy_from_user_nocheck 按 1/2/4/8/10/16 字节分派(img29-32)、__get_user_asm 的 STAC/movb/CLAC/.fixup/_ASM_EXTABLE(1b,3b)(img33-44)、ASM_STAC=0F 01 CB 与 ASM_CLAC=0F 01 CA(img42)、MMU/VA→PA/CR3/TLB(img26-27) 均与原文一致。核对时修正一处技术错误：卡片原在 _copy_from_user 中写 access_ok(to, n)，但 copy_from_user 的用户侧指针是 from(原文正文亦写『在from参数上调用access_ok』)，img29 的 access_ok(to,n) 实际属于 _copy_to_user(方向相反，to 才是用户指针)；已将 _copy_from_user 中的两处改为 access_ok(from, n)，并将标题中不准确的 __copy_from_user 更正为 _copy_from_user。原文引用 latest/v4.3 等不同内核源码页，未给目标版本，affected_versions 已 clear。与既有内核 pwn/copy_to_user OOB/userfaultfd TOCTOU 等利用卡为机制分析 vs 利用视角，非重复。
---

## 一句话结论

内核不能直接解引用用户传入的指针：`copy_from_user` 先经 `check_copy_size`，再在 `_copy_from_user` 里用 `access_ok` 校验用户地址范围，然后 `raw_copy_from_user`/`copy_from_user_nocheck` 按 1/2/4/8/10/16 字节选择 `movb/movw/movl/movq` 的 `__get_user_asm` 完成拷贝；访问前后用 `STAC`/`CLAC`（SMAP）临时放行内核访问用户页，并用 `_ASM_EXTABLE` 异常表把缺页/非法访问重定向到 fixup 代码返回错误，真正的虚拟地址到物理地址翻译由 MMU/页表在 `mov` 执行时完成。

## 原理

- **用户态与内核态地址空间**：每个进程有自己的页表，相同的虚拟地址在不同进程中映射到不同物理页；MMU 用页表（根表地址在 CR3、TLB 缓存）把虚拟地址翻译为物理地址，并检查权限，非法/缺页时触发缺页异常。内核访问用户指针前必须确认该地址属于用户空间且当前进程有权访问。
- **`copy_from_user` 入口**（`include/linux/uaccess.h`）：
  - `copy_from_user(to, from, n)` 先 `check_copy_size(to, n, false)`（检查目标内核缓冲区大小/类型是否足够），通过后调用 `_copy_from_user`；
  - `_copy_from_user`：`might_fault()`；`if (should_fail_usercopy()) return n;`；`if (access_ok(from, n)) { instrument_copy_from_user(...); n = raw_copy_from_user(to, from, n); }`。
- **`access_ok`**：校验用户地址范围是否落在当前架构允许的用户空间（x86-64 通常要求地址 < TASK_SIZE_MAX，且范围不溢出）；它只做范围检查，不保证页已映射。
- **按大小分派的拷贝**：`raw_copy_from_user` → `copy_from_user_nocheck`；若 `size` 是编译期常量（`__builtin_constant_p`），`switch(size)` 选择：
  - 1 字节：`__get_user_asm(*(u8*)dst, (u8 __user*)src, ret, "b", "b", "=q", 1)`；
  - 2 字节：`movw`；4 字节：`movl`；8 字节：`movq`；
  - 10/16 字节：组合两次 8 字节 `movq`（如 8+2、8+8）；
  - 其他：`copy_user_generic`（rep movs 等）。
- **`__get_user_asm` 宏**（`arch/x86/include/asm/uaccess_64.h`）：
  - `asm volatile(ASM_STAC ... "1: mov"itype" %2,%"rtype"1 ... "2: " ASM_CLAC ...)`：在访问用户地址前后插入 `STAC`/`CLAC`；
  - `STAC`/`CLAC` 是 SMAP（Supervisor Mode Access Prevention）相关的指令，机器码分别为 `0F 01 CB` / `0F 01 CA`；SMAP 开启时，ring 0 默认不能访问用户页，STAC 临时置位 AC 标志放行，CLAC 清除；
  - 访问失败时不能直接崩溃：`.section .fixup,"ax"` 中的 label 3 把错误码写入 `err`、把目标寄存器清零、`jmp 2b` 跳过访问；`_ASM_EXTABLE(1b, 3b)` 在 `__ex_table` 中登记“访问指令 1b ↔ fixup 3b”的映射。
- **异常表与页缺失**：`mov` 访问的用户虚拟地址可能尚未映射（换出/未分配），会触发缺页异常；内核异常处理查 `__ex_table`，若地址在表中则跳到 fixup 返回错误，否则按普通缺页/非法访问处理。异常表让内核在访问用户指针失败时能安全返回 `-EFAULT`，而不是 oops。
- **为什么代码里看不到 VA→PA 翻译**：翻译由 MMU/页表在 `mov` 执行时硬件完成；内核只负责建立页表、校验范围和处理缺页。理解这一点是理解 `copy_from_user` 安全边界（用户地址可缺页、可非法、可跨进程）的关键。

## 触发条件

- 分析 Linux 内核源码中的 `copy_from_user`/`copy_to_user`/`get_user`/`put_user` 实现，或审计驱动/内核模块对用户指针的处理。
- 目标架构为 x86-64（STAC/CLAC、`__get_user_asm` 的 `movb/movw/movl/movq` 形态）；其他架构实现不同。
- 需要理解 SMAP、异常表、缺页处理、用户/内核地址空间隔离等机制。
- 有内核源码（对应版本）与 `objdump`/`gdb`/QEMU 等分析工具。

## 利用步骤

1. 从 `copy_from_user` 入口开始读：`include/linux/uaccess.h` 的 `copy_from_user` → `_copy_from_user`，确认 `check_copy_size` 与 `access_ok` 的位置。
2. 跟进 `raw_copy_from_user`/`copy_from_user_nocheck`：按 `size` 的 switch 分支看 1/2/4/8/10/16 字节分别调用哪个 `__get_user_asm` 实例。
3. 展开 `__get_user_asm` 宏：确认 `ASM_STAC`/`ASM_CLAC` 包裹 `mov`、`.fixup` 段 label 3、`_ASM_EXTABLE(1b,3b)`；对照 `smap.h` 的机器码 `0F 01 CB`/`0F 01 CA`。
4. 在编译产物/`vmlinux` 中用 `objdump -d` 找到对应 `copy_from_user` 函数，确认 `stac`/`clac` 与 `mov` 的实际指令序列。
5. 用 QEMU/gdb 在 `copy_from_user` 下断点，构造一个未映射的用户地址，观察缺页异常与异常表跳转到 fixup、返回 `-EFAULT`；构造合法地址观察正常拷贝。
6. 结合 MMU 页表（CR3/TLB）理解地址翻译与 SMAP 权限检查；如需验证 SMAP，可在关闭/开启 SMAP 的内核配置下对比访问行为。

## PoC

源码结构（伪代码/关键路径，按内核版本略有差异）：

```c
// include/linux/uaccess.h
static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
    if (likely(check_copy_size(to, n, false)))
        n = _copy_from_user(to, from, n);
    return n;
}

unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
    might_fault();
    if (should_fail_usercopy())
        return n;
    if (access_ok(from, n)) {
        instrument_copy_from_user(to, from, n);
        n = raw_copy_from_user(to, from, n);
    }
    return n;
}
```

```c
// arch/x86/include/asm/uaccess_64.h：按 size 选择 __get_user_asm
case 1: __get_user_asm(*(u8 *)dst, (u8 __user *)src, ret, "b", "b", "=q", 1);
case 2: __get_user_asm(*(u16 *)dst, (u16 __user *)src, ret, "w", "w", "=r", 2);
case 4: __get_user_asm(*(u32 *)dst, (u32 __user *)src, ret, "l", "k", "=r", 4);
case 8: __get_user_asm(*(u64 *)dst, (u64 __user *)src, ret, "q", "", "=r", 8);
```

```c
// __get_user_asm 关键结构（展开后）
asm volatile(
    "stac\n"
    "1: movb %2,%b1\n"
    "2: clac\n"
    ".section .fixup,\"ax\"\n"
    "3: mov %3,%0\n"
    "   xorb %b1,%b1\n"
    "   jmp 2b\n"
    ".previous\n"
    _ASM_EXTABLE(1b, 3b)
    : "=r"(err), "=q"(x) : "m"(*(addr)), "i"(errret), "0"(err));
```

```text
# 机器码：STAC = 0F 01 CB，CLAC = 0F 01 CA
# 异常表：__ex_table 中 [1b, 3b]，mov 触发异常时跳到 fixup 返回 -EFAULT
```

## 变体与关联

- **架构差异**：ARM64 用 `ldtr`/`ldp` + `uaccess` 的 PAN（Privileged Access Never）与 `ldxr` 等，机制类似但指令不同；x86-32 无 SMAP/STAC/CLAC，`__get_user_asm` 更简单。
- **`copy_to_user`/`get_user`/`put_user`**：同一套 `access_ok` + 异常表机制，方向相反；`strncpy_from_user`、`copy_from_user_nofault` 等有不同的大小/故障语义。
- **安全影响**：`copy_from_user` 返回值未检查、长度/类型不匹配、目标内核缓冲区溢出是常见驱动漏洞根因；`access_ok` 只做范围检查，不代表地址已映射或属于当前进程。
- **关联**：[[code-analysis-reverse-linux-syscall-user-kernel-entry-chain]]（系统调用如何进入内核、参数如何变成 `__user` 指针）、[[code-analysis-reverse-linux-lkm-prefix-file-hiding]]（内核模块开发/隐藏文件的对照）、[[binary-pwn-kernel-module-ioctl-magic-commit-creds]]（内核模块 ioctl 与用户指针交互的利用视角）。
- **边界**：源码版本差异大（`_copy_from_user` 的封装位置、`check_copy_size` 的引入、`copy_user_generic` 的实现）；必须按目标内核版本阅读，不能套用单一版本。

## 检测与防御

- 这是内核源码/二进制分析知识，不直接产生攻击面。防守/审计关注点：驱动是否检查 `copy_from_user` 返回值、是否用 `access_ok` 校验、长度是否与目标缓冲区匹配、是否在原子上下文/持锁时访问用户页导致休眠；开启 SMAP/SMEP/KPTI 等缓解。
- 分析侧：读 `__ex_table` 可定位所有可能访问用户指针的指令与 fixup；用 QEMU/gdb 构造缺页/非法地址验证错误路径；对照 `vmlinux` 的 `stac`/`clac` 序列确认 SMAP 支持。
- 防御：保持内核更新；对驱动做静态/动态审计（Coccinelle、KASAN、KCSAN）；限制不可信用户命名空间/设备访问；启用 lockdep/DEBUG_ATOMIC_SLEEP 检测在原子上下文访问用户页。
