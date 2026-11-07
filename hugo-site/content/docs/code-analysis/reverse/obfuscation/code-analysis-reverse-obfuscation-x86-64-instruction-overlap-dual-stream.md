---
id: code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream
title: x86-64 指令重叠：入口处无害指令流掩盖偏移执行的隐藏流
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: instruction-overlap-dual-stream
tags:
- x86-64
- instruction-overlap
- anti-disassembly
- obfuscation
- cfi
- code-integrity
- function-pointer
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T19:39:17+08:00'
  notes: 已对照原文与10张图核对：7字节 6A 51 58 48 FF C0 C3 在 +0/+1 的双解码（图2/3）、run_overlap 返回 0x52/0x1（图4）、20字节 jz/syscall/干净路径样本（图5/6/7）、--start/--stop-address 隔离（图8）、函数指针 +0/+1（图10）均与正文一致。未验证点：未实际复跑 PoC；原文图9 md5sum 实际比较的是两个不同样本文件、并未证明“同一字节序列哈希相同”，卡片未引用该图，相关表述按原理成立；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream/
draft: false
kb_aliases:
- 指令重叠
- instruction overlap
- 双重执行流
- 偏移入口
- 隐藏指令流
- 反汇编盲区
---

## 一句话结论

x86-64 变长指令的中间字节可以独立成为合法操作码，因此同一段字节从 +0 和 +1 解码会得到两条语义不同的合法指令流；攻击者只需把可控函数指针或间接跳转目标指向 `+1`，就能执行静态反汇编工具和字节哈希校验都看不到的隐藏指令流，例如一条包含 `syscall` 的路径。

## 原理

- x86-64 指令由“可选前缀 + 操作码 + 可选操作数”组成且长度可变；多字节指令的立即数、ModRM 等字节可能恰好是另一条单字节指令的操作码，从这个字节重新解码即可得到另一条合法指令。
- 示例字节 `6A 51 58 48 FF C0 C3`：
  - 从 +0 解码：`6A 51` 是 `push 0x51`（`0x51` 被当作 1 字节立即数），随后 `58`=`pop rax`、`48 FF C0`=`inc rax`、`C3`=`ret`；执行后 `rax=0x52`，`push/pop` 栈平衡。
  - 从 +1 解码：`51` 自身是 `push rcx` 的操作码，随后 `58`=`pop rax`、`48 FF C0`=`inc rax`、`C3`=`ret`；执行后 `rax=rcx+1`，栈同样平衡。
  - 两条流共享偏移 2 之后的指令，仅偏移 0-1 的差异就产生了不同的栈与寄存器语义。
- 条件分支可进一步把差异放大成完整路径：字节序列 `74 0E`（`jz +14`）… `0F 05`（`syscall`）… `EB 03`（`jmp +3`）… `48 31 C0`（`xor rax,rax`）… `C3`（`ret`）中，ZF=0 时从 +0 依次执行 `xor rdi,rdi; mov rax,1; syscall; jmp +3; ret`，而入口 +16 直接执行 `xor rax,rax; ret`，完全跳过 `syscall`。
- 反汇编器（objdump、IDA、Ghidra）默认从函数入口线性/递归扫描；不会主动从 `+1` 这类“非入口”地址重新解码，因此输出只显示执行流 A。哈希/签名校验只对字节序列计算摘要，两条流共享同一段字节，摘要完全相同。
- 这一手法本身不修改任何代码字节，只需要控制一个间接跳转目标（函数指针、回调、vtable、返回地址等）并加一个偏移；若目标地址来自攻击者可控数据，即可在“看起来正常”的入口之外执行隐藏流。

## 触发条件

- 攻击者能影响某个间接 `call`/`jmp` 的目标地址（函数指针、回调表、vtable、JIT 代码指针等），并能把目标设为合法入口之外的小偏移。
- 目标代码区域中存在可被重叠解码的字节；或攻击者能写入/生成机器码（JIT、RWX mmap、自修改代码、加壳器）。
- 入口处的“正常流”需要能通过预期行为检查或哈希/签名校验；隐藏流所需的寄存器、栈、内存状态可由调用方或前置指令满足。
- 目标未启用 CFI、CET/IBT、Shadow Stack、BTI 等间接分支目标校验，函数入口也未做严格对齐与填充。
- 防御方依赖线性反汇编或纯字节哈希做完整性判断时，该手法可直接绕过。

## 利用步骤

1. 找到可控的间接调用点，确认攻击者能决定其目标地址（或其低字节偏移）。
2. 在可达代码中寻找“入口解释无害、偏移解释有用”的字节序列；可用 `objdump -D -b binary -m i386:x86-64 --start-address=<off>` 分别从不同偏移反汇编比对。
3. 设计隐藏流：让偏移入口处的指令完成需要的行为（如设置参数并触发 `syscall`），同时保证入口路径仍能正常返回、不破坏调用方的栈和寄存器约定。
4. 把函数指针/跳转目标设置为 `base + offset`（示例为 +1），必要时先设置好隐藏流依赖的寄存器（如示例中的 `rcx`/`ZF`）。
5. 在同等权限的本地环境用 RWX 映射验证两条流的返回值和系统调用行为，再用于真实目标；若目标有 CFI/CET，先确认偏移目标是否会被拦截。

## PoC

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/* 从 +0: push 0x51; pop rax; inc rax; ret  -> rax = 0x52
   从 +1: push rcx; pop rax; inc rax; ret  -> rax = rcx + 1 */
static const unsigned char code[] = {
    0x6A, 0x51, 0x58, 0x48, 0xFF, 0xC0, 0xC3,
};

typedef long long (*fn_t)(void);

int main(void) {
    void *exec = mmap(NULL, sizeof(code),
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(exec, code, sizeof(code));

    fn_t normal = (fn_t)((unsigned char *)exec + 0);
    printf("normal (+0): rax = 0x%llx\n", normal());

    fn_t hidden = (fn_t)((unsigned char *)exec + 1);
    long long r;
    __asm__ volatile ("xor %%rcx, %%rcx\n call *%[e]"
                      : "=a"(r) : [e] "r"(hidden) : "rcx", "r11", "memory");
    printf("hidden (+1): rax = 0x%llx\n", r);   /* 0x1 */
    return 0;
}
```

```text
实测输出：normal (+0): rax = 0x52；hidden (+1): rax = 0x1
条件分支变体：入口 +0 在 ZF=0 时执行 syscall（write 返回 -14/EFAULT），入口 +16 直接返回 0。
```

## 变体与关联

- 变体：偏移不限于 +1，可在多字节指令的任意中间字节落入合法操作码；一个字节序列可嵌入多条重叠流，形成多层隐藏路径。
- 变体：用 `jz`/`jmp` 组合按标志位选择 syscall 路径与干净返回路径，使同一入口在不同输入下表现不同。
- 变体：把重叠流与 JOP/COP、返回地址偏移、vtable 劫持结合；隐藏流可承载反调试、检测绕过或实际 payload。
- 关联：反汇编/反编译盲区、控制流平坦化、字节哈希完整性校验的局限；防御侧与 CFI、CET/IBT、BTI、函数入口对齐同属控制流保护范畴。

## 检测与防御

- 检测：不只看入口的线性反汇编，对每个间接分支目标做递归反汇编并检查是否落在指令中部；对可执行段做多偏移解码比对，发现同一字节区的歧义解码；运行时用 ptrace/硬件断点或 Intel PT 校验实际执行地址与预期函数入口一致。
- 修复：编译启用 CFI（`-fsanitize=cfi`/LLVM CFI）与 `-fcf-protection`（CET IBT/Shadow Stack）；函数按固定边界对齐并在入口间填充 `int3`/`nop`，使偏移入口落入陷阱或填充区。
- 加固：启用 ARM BTI 或 x86 CET 硬件校验间接分支目标；对 JIT/RWX 内存执行 W^X 与代码签名；完整性校验从“字节哈希”升级为“实际执行指令序列 + 控制流校验”。
