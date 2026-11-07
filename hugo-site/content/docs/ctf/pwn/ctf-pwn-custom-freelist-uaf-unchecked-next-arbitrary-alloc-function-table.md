---
id: ctf-pwn-custom-freelist-uaf-unchecked-next-arbitrary-alloc-function-table
title: 自研空闲链表 UAF + 不校验 next：任意地址分配并覆盖后端函数表
type: scenario
domain: ctf
path: ctf/pwn
technique: custom-freelist-uaf-unchecked-next-arbitrary-alloc
tags:
- pwn
- heap
- uaf
- freelist
- custom-allocator
- function-pointer
- no-pie
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:19+08:00'
  notes: 已对照原文核对；free 不清槽位 + alloc 信任 next 的组合、0x402000 函数表覆盖 0x401210 audit 序列一致
url: /docs/ctf/pwn/ctf-pwn-custom-freelist-uaf-unchecked-next-arbitrary-alloc-function-table/
draft: false
kb_aliases:
- 空闲链表投毒
- freelist poisoning
- 自研堆 UAF
- 函数表劫持
- bump 分配器
---

## 一句话结论

自研堆在 `free` 后不清理槽位里的用户指针，形成可写的悬挂指针；`alloc` 摘下空闲节点时又把节点首 8 字节直接当作下一个空闲块地址、不做范围与对齐校验。两个缺陷叠加，攻击者可以指定任意地址作为下一次分配结果，把非 PIE 程序的函数指针表当成“空闲块”交付并覆盖，劫持后端调用。

## 原理

- **对象与布局**：配方帧缓存管理器用静态堆，`slot[16]` 保存每块用户数据指针，`freelist_head` 指向空闲链表，节点复用用户数据区头部。后端函数表在 0x402000，依次是 `render`、`export`、`diag`、`audit`。
- **缺陷一：free 不清槽位**：释放时只做链表插入，`slot[i]` 仍保存原块地址且可写，等价于 UAF 写原语。
- **缺陷二：alloc 信任节点内容**：分配时把空闲块首 8 字节读作 `next`，不检查是否落在堆区间、是否对齐、是否指向合法空闲块。攻击者改写该字段即可让链表头指向任意地址。
- **组合效果**：第一次 `alloc` 摘走真实空闲块，第二次 `alloc` 把伪造的 `next`（如 0x402000）当成空闲块返回给调用者；调用者随后写入的数据就落在函数表上。
- **为什么危害成立**：程序非 PIE、无 RELRO，函数表地址固定且可写；把 `render` 覆盖成 `audit`（或其他后端）后，后续渲染/导出路径会调用攻击者选择的函数，形成控制流劫持。索引检查“只放行 index <= 1”检查的是索引而非指针，函数表一旦可写，所有后端都处于可调用状态。

## 触发条件

- 目标使用自研分配器：bump 分配 + 单向空闲链表，节点元数据写在用户数据区。
- `free` 不擦除槽位指针，且槽位在释放后仍可由用户写。
- `alloc` 对节点 `next` 不做合法性校验（范围、对齐、双链表完整性）。
- 函数指针表/敏感指针位于固定地址（非 PIE）或可被推出地址，且可写。

## 利用步骤

1. 分配 0 号槽：`alloc 0`。
2. 释放 0 号槽：`free 0`；此时 `slot[0]` 仍是悬挂指针且可写。
3. 通过 UAF 写覆盖已释放块首 8 字节为函数表地址：`write 0 0020400000000000`（小端 0x402000）。
4. `alloc 1`：摘走原来的真实空闲块（0x4040a8 一带）。
5. `alloc 2`：链表头此时为 0x402000，管理器把后端函数表当作空闲块返回。
6. 向该“块”首写入目标函数地址（如 0x401210 = audit），覆盖函数表第一项 `render`。
7. 触发 render 路径，控制流跳到 audit 或攻击者选择的函数。
8. 题目中另有 `recipe_policy.json` 的 `status=valid` 裁决与 selftest/diag 诱饵 flag，需要按业务状态读取真正结果；索引限制不能阻止函数表覆盖。

## PoC

利用序列（原文格式）：

```text
alloc 0
free 0
write 0 0020400000000000
alloc 1
alloc 2
# alloc 2 返回 0x402000（后端函数表）
write 2 0012400000000000   # 0x401210 audit 覆盖 render
```

对应漏洞代码形态：

```asm
; free: 只插入链表，不写 slot
mov  rax, [rbx+8]      ; 取被释放块的 next
mov  [rax], rsi
mov  [rsi], rax
; alloc: 直接把节点首 8 字节当 next，无校验
```

原文未在本机复跑，但地址布局、两个缺陷与分配序列均来自题目逆向与利用记录。

## 变体与关联

- **只修一个缺陷不够**：单独 UAF 只能做重叠写；单独不校验 `next` 需要先控制空闲块内容。两者结合才是任意地址分配。
- **glibc 对照**：tcache 在分配时会校验 chunk size，单纯 UAF 很难一步到任意写；自研堆省掉的正是这类安全裕度。
- **目标选择**：函数指针表、GOT（无 RELRO）、atexit 数组、堆管理器自身元数据、命令缓冲区。
- **变体**：双向链表缺少 `prev->next`/`next->prev` 一致性校验、bump 指针可被覆盖、空闲块大小字段未校验导致 overlap。
- **关联**：与 glibc tcache poisoning、House of 系列思路同源，但利用点从 chunk 头校验转移到自研管理器的信任假设。

## 检测与防御

- `free` 后将槽位置空并置为不可写（如 `NULL` + 只读索引），消除悬挂指针。
- `alloc` 对 `next` 做三重校验：必须落在堆区间内、按块大小对齐、指向的空闲块头可读且 size 合法；使用带 cookie 的 safe-linking。
- 函数指针表放入只读段（RELRO/`mprotect`），或改为不可预测的句柄表。
- 开启 PIE、RELRO、canary；对堆元数据做完整性校验（前后哨兵、双链表一致性）。
- 检测特征：连续 `alloc/free` 后出现指向代码段/数据段的“分配”返回；空闲链表指针落在堆区间外；函数表项在运行期被改写。
