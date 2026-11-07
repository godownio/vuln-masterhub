---
id: binary-pwn-awdp-uaf-patch-clear-pointer-slot
title: AWDP UAF 二进制补丁：free 后清零全局指针槽，压缩代码区注入汇编修复
type: scenario
domain: binary
path: binary/pwn
technique: awdp-uaf-patch-clear-pointer-slot
aliases:
- AWDP patch
- UAF patch
- 堆指针清零补丁
- 二进制汇编补丁
- 代码洞 patch
- 免费后置空
tags:
- pwn
- uaf
- heap
- binary-patching
- awdp
- assembly
- code-cave
- defense
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:27+08:00'
  notes: 已对照原文与6张图核对：free 后清 heaplist[idx]、压缩函数腾代码空间注入汇编、IDA 反编译出现 heaplist[v0]=0，与图05/06一致。未复跑二进制。注意原文补丁用 mov qword ptr ds:sign[rax*4],0 写 int 数组，会连带清零 sign[index+1]，卡内沿用该写法；实际修复建议改 dword，但不影响 heaplist 槽位清零主链。
---

## 一句话结论

在 AWDP/CTF 只能提交二进制补丁的场景下，若 UAF 的根因是 `free(heaplist[idx])` 后没有把该指针槽置空，最小修复不是清空 chunk 内容，而是用汇编补丁在 `free` 之后把 `heaplist[idx]` 写 0；通过在函数内压缩已有指令、把新指令塞进腾出的代码空间（或代码洞），即可在不改源码的前提下阻断悬空指针被再次使用。

## 原理

- **漏洞根因**：删除功能只执行 `free(heaplist[idx]); sign[idx]=0; count--;`，`heaplist[idx]` 仍保存已释放 chunk 的地址。后续 Edit/Show/Delete 再用同一下标时，程序会把该地址当作有效 chunk 使用，形成 UAF（可配合 tcache/堆布局演化为任意读写或任意地址分配）。
- **最小修复点**：在 `free` 返回后立刻 `heaplist[idx] = 0`。只要所有使用路径都会检查槽位是否为空，悬空指针就不会再被解引用；这比清空 chunk 内容更可靠（后者无法覆盖所有释放后的复用路径）。
- **为什么是“槽位”而不是“chunk 内容”**：`free` 的参数 `rdi` 是 chunk 地址；要修复的是保存该地址的全局指针数组元素 `heaplist[idx]`，即 `heaplist + idx*8`（64 位指针）或 `+idx*4`（32 位）。清空 chunk 内容不会让程序忘记这个地址。
- **二进制补丁约束**：AWDP 不给源码，只能改汇编/字节，且通常要求原有功能（Add/Show/Edit/Delete）仍可用。补丁思路是保留原有功能块，在其前后插入“指针清零”指令；若函数空间不足，就把原有多条指令压缩成等价短指令（如 `mov al, byte ptr [rbp+idx]`、寄存器缩放寻址），或用 NOP 掉不参与检测的非核心功能，腾出代码空间。
- **SysV x86-64 约定**：`free` 的第一个参数在 `rdi`。补丁应从局部变量/参数取出 `idx`，按指针宽度缩放，加载全局数组基址，然后 `mov qword ptr [base + idx*8], 0`。IDA 的 Assemble 对语法较敏感，常需要显式写 `qword ptr` 与 `[]`；`lea` 只算地址，`mov` 才读写内存。
- **检测器为何常可通过**：AWDP 的 patch 检测通常只跑原 exp，确认漏洞不再成功、服务不崩溃；因此“让原利用链中的悬空指针变为 NULL”就足以通过，不要求实现完整的安全分配器或消除所有竞态。

## 触发条件

- 题目/目标程序存在 UAF，释放路径未将保存指针的全局槽位置空。
- 用户可控的 index 有范围检查（如 `idx <= 7`），全局数组 `heaplist` 与 `sign` 的基址可在反汇编中定位。
- 二进制允许 patch 并重新提交；代码段可写或可重打包。
- 函数内或附近有可压缩指令或未被使用的代码洞，能容纳新增的几条指令；没有空间时可 NOP 掉不影响检测的检查/提示代码。

## 利用步骤

1. 反汇编定位删除函数，找到 `free` 调用点，确认其前序指令如何计算 `heaplist[idx]`（如 `mov rax,[rbp+index]; lea rdx,[rax*8]; lea rax,heaplist; mov rax,[rdx+rax]; mov rdi,rax; call free`）。
2. 用 gdb 在 `call free` 下断，确认 `rdi` 等于 `heaplist[idx]`，并记录 `idx` 在栈上的位置（如 `[rbp-8]`）及全局数组基址。
3. 备份原汇编字节，规划补丁：`mov al, byte ptr [rbp+index]` 取 index（index 小于 256 时可用 AL 压缩）→ `mov ds:heaplist[rax*8], 0` 清槽位（32 位则 `*4`、`dword ptr`）→ 保留或重置 `sign` 与 `count` 逻辑。
4. 若原函数空间不足，把原有 `sign[idx]=0`/`count--` 等指令压缩为等价短指令，腾出连续空间；仍不足则 NOP 掉非关键代码或移到代码洞，并修正跳转。
5. 在 IDA 的汇编视图用 Assemble/Keypatch 写入指令；若无法识别，补上 `qword ptr`、`[]`、段前缀等多试几次。
6. 反编译确认新增了 `heaplist[v0] = 0;`；运行原 exp 验证 UAF 不再成功，同时回归 Add/Show/Edit/Delete/Quit 正常。

## PoC

原文未给出可直接复制的补丁字节，以下为按文章汇编片段整理的模板（地址/偏移需按目标二进制替换）：

```asm
; 原逻辑（示意）
mov     rax, [rbp+index]
lea     rdx, ds:0[rax*8]
lea     rax, heaplist
mov     rax, [rdx+rax]
mov     rdi, rax
call    free

; 补丁：free 后把 heaplist[index] 清零
mov     al, byte ptr [rbp+index]      ; index < 256，压缩取值
mov     ds:heaplist[rax*8], 0         ; 64 位指针槽置空；32 位改 *4/dword
; 如原逻辑还需 sign[index]=0：
mov     qword ptr ds:sign[rax*4], 0
dec     dword ptr cs:count
```

```c
// 补丁后反编译效果（文中）
free((void *)heaplist[index]);
LOBYTE(v0) = index;
heaplist[v0] = 0;
*(_QWORD *)&sign[v0] = 0;
LODWORD(count) = count - 1;
return puts("Done!");
```

## 变体与关联

- 变体：只清 `heaplist[idx]`，不修改 `sign`；或把 `sign` 也作为“已释放标记”使用，后续操作先检查标记再访问指针。
- 变体：若 index 可能大于 255，不能用 `mov al` 压缩，需保留完整 `mov rax,[rbp+index]` 并按 64 位缩放。
- 变体：空间不足时把清零逻辑放到代码洞，在原位置写 `jmp` 到洞内再跳回；或 NOP 掉仅用于提示/重复检查的代码。
- 关联：[[ctf-pwn-awdp-uaf-free-patch]]（同主题通用三方案：原地压缩/弹栈/jmp）；本卡补充 `index < 256` 时用 AL 压缩取下标、按指针宽度 `*8` 清全局槽位，以及 IDA Assemble 需补 `qword ptr`/`[]` 的实操细节。
- 关联：[[binary-pwn-single-byte-code-patch-leave-to-push-rcx-loop]]（另一种二进制代码 patch 思路）、[[binary-pwn-heap-negative-size-malloc-failure-stale-pointer-house-of-cat]]（悬空指针/失败路径相关堆利用）、[[binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack]]（堆指针劫持利用）。
- 边界：如果其他路径也会保存 chunk 地址（副本、链表、缓存），只清 `heaplist` 不足以修复；多线程竞态下仍需加锁或原子操作；PIE/ASLR 下需确认补丁使用相对寻址而非硬编码绝对地址。

## 检测与防御

- 补丁验证：运行原始 exp，确认删除后再次 Edit/Show/Delete 不再命中已释放 chunk；用 gdb 观察 `heaplist[idx]` 在 `free` 后为 0；回归所有菜单功能。
- 源码修复：`free(p); p = NULL;` 并把指针槽置空；所有释放路径统一走封装函数；使用 SafeLink/智能指针或带隔离的分配器。
- 加固：开启 ASLR/PIE、FORTIFY、堆隔离（如 Scudo/mimalloc 硬化）、CFI；代码段只读，防止运行时被改写。
- 检测：二进制补丁后代码段哈希变化、函数内出现异常跳转/代码洞；运行期监控已释放 chunk 被再次读写；AWDP 场景下对比补丁前后 exp 行为。
