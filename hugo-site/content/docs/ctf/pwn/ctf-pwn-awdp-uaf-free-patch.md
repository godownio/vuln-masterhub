---
id: ctf-pwn-awdp-uaf-free-patch
title: AWDP fix：UAF 释放点的二进制级补丁（原地压缩 / 弹栈 / jmp）
type: scenario
domain: ctf
path: ctf/pwn
technique: awdp-uaf-free-binary-patch
tags:
- ctf
- pwn
- awdp
- uaf
- binary-patching
- ida
- keypatch
- assembly
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:50:11+08:00'
  notes: 已对照原文核对：UAF free 不置空、原地压缩（原文自述实战可能不成立）、jmp 与 pwn03 弹栈方案均一致；卡内弹栈示例补上了置空写入并提示按实际验证；未复跑
url: /docs/ctf/pwn/ctf-pwn-awdp-uaf-free-patch/
draft: false
kb_aliases:
- AWDP UAF 修复
- free 后置空补丁
- IDA 原地汇编压缩
- KeyPatch 改 call free
- 二进制补丁 jmp 方案
---

## 一句话结论

AWDP 的 fix 环节遇到“`free(ptr)` 后没有把指针置空”的 UAF，且没有源码时，可以在 IDA/KeyPatch 里对释放点做三种二进制补丁：原地压缩指令腾出空间写入 NULL、用栈保存槽位地址后再回写、或直接 `jmp` 到一段安全代码；核心是让释放后的槽位不再指向已释放内存。

## 原理

- UAF 根因：删除函数只执行 `free(global_array[idx])`，没有把 `global_array[idx] = NULL`；后续 `show/edit/use` 仍解引用悬空指针，攻击者可在 chunk 被重新分配后读写新对象。
- AWDP 只能提交二进制补丁，因此要在“释放点”这条指令序列上做文章。难点是原指令空间有限，新增的“置空”指令放不下，需要在同一段字节内重排指令（压缩），或跳转到别处执行。
- **原地压缩**：用一条 `xchg` 把“取指针”和“把槽位置零”合并：先把 `edi` 清零，再 `xchg rdi, [global + idx*8]`，于是 rdi 得到待释放指针、槽位变成 0，随后 `call free`。这比“先 mov 再 mov 0”省指令。文章提示该写法在实战中可能不成立（可能只清了寄存器/地址而非解引用内存），**必须在调试器中逐条核对语义**。
- **弹栈方案**：`push` 保存槽位地址 → `mov rdi,[slot]` → `call free` → `pop` 取回槽位地址 → 再写入 NULL/安全值。栈用于跨 `free` 保存“槽位地址”这个调用会被破坏的寄存器值；注意 `free` 可能改写 rdi，不能想当然把 rdi 回写。
- **jmp 方案**：不改原函数细节，直接把释放点或整个函数 `jmp/call` 到一段已有的安全例程（如负责清空全局数组的函数，或代码洞中的自定义 stub），执行完再跳回。通常还要修改标志位/比较结果，让后续分支走安全路径。
- 补丁后要保证：调用约定与栈平衡不变；释放后所有读/写路径都检查槽位是否为 NULL；同一对象可能有多个释放点，需全部覆盖。

## 触发条件

- AWDP/CTF 修复环节，只能提交二进制补丁；
- 目标存在“free 后未置空”的 UAF，且能定位释放函数与全局指针数组；
- 有 IDA + KeyPatch（或等效汇编/十六进制补丁工具）；
- 目标函数附近有足够可重排空间，或存在可复用的安全例程/代码洞；
- 能本地运行目标做回归验证（含攻击 PoC）。

## 利用步骤

1. 在 IDA 中定位释放函数：确认 `free` 的实参来自全局数组 `global[idx]`，且 free 后没有 `mov [global+idx*8], 0`。
2. 记录原指令序列与可用字节空间，选择补丁方案：
   - 空间足够重排 → 原地压缩，把“取指针 + 置零”合并到 `xchg`；
   - 需要跨 `free` 保存槽位地址 → 弹栈方案；
   - 原函数复杂或空间不足 → jmp 到安全例程/代码洞。
3. 在 IDA 反汇编窗口右键 → Assemble/KeyPatch，逐条改写并确认机器码字节同步更新。
4. 若使用 jmp：修改目标地址与调用目标，检查 `test/cmp` 等标志位是否需要跟着改，避免跳转后走错分支。
5. 保存二进制，打包 `update.tar`，本地用原攻击 PoC 回归：释放后再次 show/edit 应失败或返回空，程序不崩溃。
6. 测试正常功能（增删改查、边界索引、重复释放），确认补丁没有破坏业务路径。
7. 若原地汇编在某版本上语义不成立（文章提示的风险），退回 jmp/清空例程方案，不要强行提交未验证的补丁。

## PoC

```asm
; 方案 A：原地压缩（xchg 同时取指针并置零槽位）
; 原序列：mov eax,[rbp+var_4] / cdqe / lea rdx,[rax*8] / lea rax,unk_A080
;         mov rax,[rdx+rax] / mov rdi,rax / call free
movsxd  rdx, dword ptr [rbp-4]
lea     rax, [rip+0x8ABC]          ; unk_A080
xor     edi, edi
xchg    rdi, qword ptr [rax+rdx*8] ; rdi = ptr, slot = 0
call    _free
```

```asm
; 方案 B：弹栈保存槽位地址（示意；free 后 rdi 可能被改写，回写值需按实际验证）
mov     rax, [rbp+var_4]
shl     eax, 3
lea     rdx, qword_A080
add     rdx, rax
push    rdx
mov     rdi, [rdx]
call    _free
pop     rdx
mov     qword ptr [rdx], 0        ; 关键：置空槽位，而不是写回 rdi
```

```asm
; 方案 C：jmp 到安全例程/代码洞
; 释放点改为：
call    0x1160                    ; 安全例程负责 free + 置空
; 或 jmp 0x1160，并按需要修正后续分支标志位
```

## 变体与关联

- 结构体型 UAF（`ptr/size` 两个字段）：释放后要同时清空 ptr 与 size，避免 size 泄露或越界读；可参考文章 pwn03 的“取 chunk 地址 → free → 清空”补丁。
- 多释放点：同一对象可能在删除、替换、退出清理等多处被 free，需逐一补丁。
- 若目标是 C++ 对象，置空指针还不够，虚表/引用计数等字段也要处理。
- 关联卡片：[[ctf-pwn-awdp-format-string-patch]]、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]、[[binary-pwn-heap-uaf-function-pointer-hijack]]。

## 检测与防御

- 检测：源码审计搜索 `free(` 后未置空的路径；二进制中检查 `call free` 后是否对全局槽位写入 0；用原 PoC 回归验证。
- 防御：开发时 free 后立即 `ptr = NULL`，并把长度/状态一起失效；使用带生命周期检查的容器；AWDP 补丁要覆盖所有释放路径。
- 注意：原地汇编压缩依赖具体编译器生成的指令序列，换编译器/优化级别就不适用；文章也提示其汇编版本在实战中可能不成立，必须调试验证。
