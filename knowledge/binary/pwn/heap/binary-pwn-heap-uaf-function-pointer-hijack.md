---
id: binary-pwn-heap-uaf-function-pointer-hijack
title: UAF 函数指针劫持：释放后不置空，同大小分配复用旧块改写回调
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-uaf-function-pointer-hijack
aliases:
- UAF 函数指针
- use-after-free 控制流劫持
- 悬垂指针覆写回调
- tcache 复用 UAF
- 堆块重叠函数指针
tags:
- pwn
- heap
- uaf
- use-after-free
- function-pointer
- tcache
- control-flow-hijack
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:35:28+08:00'
  notes: 已对照原文与12张图核对：free(n1) 不置空→同尺寸 malloc 复用同地址（图06/07）→覆写偏移0函数指针为 secret_func（0x401196，图08/09）→再次 n1->print() 触发（图05），原文实机运行成功；GDB 结构布局与 chunk size 0x31 一致。未验证点：未在本机重新编译执行；原文未标 glibc/编译器版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

程序 `free` 堆对象后没有把指针置 NULL，随后用相同大小 `malloc` 会复用同一块内存；攻击者通过新指针覆写对象起始处的函数指针，再调用旧悬垂指针，就能把控制流劫持到任意函数（如 `secret_func`/`system`）。

## 原理

- glibc 的 tcache/fastbin 对小尺寸释放块采用 LIFO 管理：`free(p)` 后 `p` 进入对应 bin，下一次 `malloc` 相同大小（或落入同一 tcache bin 的大小）时优先返回最近释放的块，因此新指针 `n2` 与旧指针 `n1` 指向同一物理内存。
- C 结构体的函数指针通常位于对象起始偏移 0；若对象在释放后仍可被旧指针访问（悬垂指针），攻击者通过 `n2` 写入的 8 字节会直接改写 `n1->print`。
- 当程序再次执行 `n1->print()` 时，CPU 从该内存读取函数地址并调用，控制流转移到攻击者写入的地址（示例为 `secret_func`，实战中可指向 `system`/one-gadget/ROP 跳板）。
- 该场景不需要覆盖返回地址：UAF 提供了“合法指针访问已释放对象”的路径，堆分配器复用提供了“同一内存被两个指针别名”的条件，函数指针提供了直接控制流目标。
- 前提是对象大小与分配器的 bin 匹配、释放后未被清零/未被其他分配占用、攻击者能控制新分配内容；现代 glibc 的 tcache key 主要防 double free，不阻止“释放后通过悬垂指针读取/写入”的 UAF 本身。

## 触发条件

- 存在 UAF：对象 `free` 后指针未置 NULL，后续仍可调用其方法/回调；
- 攻击者能触发一次与旧对象同尺寸的 `malloc`，并控制写入内容；
- 对象内存在函数指针/虚表指针等可被调用的控制流目标；
- 二进制未启用 CFI 等控制流完整性保护，或目标地址合法可通过检查。

## 利用步骤

1. 识别 UAF：源码/逆向中看到 `free(p)` 后仍使用 `p`，或对象释放后仍可触发其虚函数/回调。
2. 确认对象大小与分配路径：记录 `malloc` 尺寸，确保后续能申请到同一 tcache/fastbin 大小。
3. 在释放后申请同尺寸对象，使分配器返回同一地址（GDB 中两个指针地址相同）。
4. 通过新对象写入目标函数地址到函数指针偏移（示例偏移 0）。
5. 触发旧悬垂指针的方法调用，控制流跳到目标函数；实战中可改为 `system("/bin/sh")` 或先泄露再写 GOT/one-gadget。
6. 验证 `id`/shell，或按题目要求读取 flag。

## PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Note {
    void (*print)();   // 偏移 0 的函数指针
    char content[24];
};

void secret_func() { puts("[!] UAF -> secret_func"); }
void normal_print() { puts("[+] normal_print"); }

int main() {
    struct Note *n1 = malloc(sizeof(struct Note));
    n1->print = normal_print;
    strcpy(n1->content, "Hello World");
    n1->print();

    free(n1);                        // 不置 NULL，形成悬垂指针
    char *n2 = malloc(sizeof(struct Note));  // 复用同一块
    *(void **)n2 = (void *)secret_func;      // 覆写函数指针
    n1->print();                     // UAF 触发，跳转 secret_func
    return 0;
}
```

```bash
gcc -g -no-pie uaf_demo.c -o uaf_demo
./uaf_demo
# [1] n1 地址 ... 函数指针 normal_print
# [3] n2 地址与 n1 完全相同
# [5] 调用 n1->print() 后执行 secret_func
```

## 变体与关联

- 变体：C++ 对象虚表指针（vptr）UAF，覆写 vptr 指向伪造 vtable，调用虚函数时劫持；或覆写回调/析构函数指针。
- 变体：UAF + tcache poisoning，把 fd 改成目标地址（GOT/__free_hook/栈），下一次 malloc 返回任意地址并写入。
- 关联：[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（UAF 清 key + tcache dup 覆写 GOT）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（UAF 泄露 libc）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 下的堆地址恢复）。
- 边界：对象释放后被清零/覆盖、分配器不复用同尺寸块、启用 CFI/指针认证（如 ARM PAuth）、旧指针在释放后被置 NULL 时，本路径不成立。

## 检测与防御

- 修复：`free(p); p = NULL;`；对象释放后禁止再访问；使用 RAII/智能指针管理生命周期。
- 加固：编译时启用 CFI、FORTIFY、ASLR/PIE；使用 hardened allocator（如 Scudo）或开启 tcache/堆检查；对敏感回调做完整性校验。
- 检测：GDB/ASAN 的 use-after-free 报告；堆分配器中同一地址被重复分配/释放；异常函数指针调用（CFI 告警）。
