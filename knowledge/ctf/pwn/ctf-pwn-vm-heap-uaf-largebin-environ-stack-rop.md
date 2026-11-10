---
id: ctf-pwn-vm-heap-uaf-largebin-environ-stack-rop
title: VM pwn 全链：变长 opcode 驱动堆 UAF，largebin 泄 libc → tcache 劫持 environ 泄栈 → 再劫持返回地址写 ROP
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-opcode-heap-uaf-largebin-environ-stack-rop
aliases:
- VM 套堆全链
- 变长操作码堆题
- 重新读入 vmcode
- write_to_memory 泄地址
- tcache 打 environ 泄栈
- VM 题栈上 ROP
tags:
- ctf
- pwn
- vm
- opcode
- heap
- uaf
- largebin
- tcache
- environ
- rop
cve: []
severity: high
confidence: high
status: verified
created: '2026-02-26'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:58:30+08:00'
  notes: 已对照原文核对：mmap 三段固定地址 0x64617461000/0x7063000/0x73746163000、sub_132D 取码与低2位格式(3/2/1/0 对应前进 10/3/2/4 字节)、外层 switch(*context&3) 与内层 >>2 分派、case53 走 sub_12E8+sub_1837 的六功能(read/write/exit/add_heap/free_heap/read_from_memory/write_to_memory)、free 不清指针构成 UAF、add 上限 16、三段链(largebin 泄 libc/heap -> tcache 打 environ 泄栈 -> 再打返回地址写 ROP)与原文 exp 的偏移 0x21b110/0x2b0/0x2a3e5/0x29139 均与原文及图 02/08/21/22/23/24 一致。未验证点：完整 exp 未执行；libc/heap/栈偏移为原文环境值，卡片已注明换环境需重新对齐。
---

## 一句话结论

自定义 VM 把「操作码流」当输入、把宿主堆函数当指令执行：首字节低 2 位决定操作数宽度（4/3/2/10 字节），高 6 位选 handler，其中一条 handler 直接把 `qword_6120[]` 里的值当 `add_heap/free_heap/read_from_memory/write_to_memory` 的参数，而 `free` 不置空指针构成 UAF；于是用纯 opcode 就能：big chunk 进 largebin 泄 libc/heap、tcache 投毒把 `environ` 分配到堆块泄栈、再投毒到某函数返回地址写 ROP——中途靠「把堆数据搬进固定 mmap 的 data 段再用 write handler 打出来」获得回显，并靠「程序会继续读下一段 opcode」反复重写字节码完成三段利用。

## 原理

- **VM 布局**：`main` 里 `mmap` 三段固定地址——`0x64617461000`（data，0x30000）、`0x7063000`（code，0x10000）、`0x73746163000+0x10000`（stack）；`qword_6120` 指向 data，`qword_6128` 指向 code，`qword_6160` 指向 stack。三段地址固定不随机，所以 VM 字节码里可以直接写死绝对偏移当"指针"。
- **取码函数（sub_132D）**：读 1 字节到 `context[0]`，`context[1] = context[0] & 3`，再由 `context[1]` 决定后续操作数：
  - `==3`：取 1 字节到 `context+4`，再取 8 字节 qword 到 `context+8`，指针前进 10 字节；
  - `==2`：取 1 字节到 `context+4`，再取 1 字节到 `context+8`，前进 3 字节；
  - `==1`：只取 1 字节到 `context+4`，前进 2 字节；
  - `==0`：三次各取 1 字节，前两次为 0 时第三次即期望值，前进 4 字节（等价于 3 字节大端拼一个 24 位整数）。
  这解释了"为什么每条指令长度不同"：同一套 handler 既需要「寄存器索引」这种小立即数，也需要「大小/地址」这种 8 字节立即数，于是把宽度信息塞进首字节低 2 位。
- **分派**：外层 `switch(*context & 3)` 进 4 个函数（3→`sub_2A49`、2→`sub_23A7`、1→`sub_2142`、0→`sub_19AD`），内层再用 `*context >> 2` 选具体操作。3/2/1 三个分支基本只是对 `qword_6120[]` 做赋值/比较/自增，属于"给算术和参数搬运"服务；**真正有用的是赋值（`case 3`：`qword_6120[8*(*(context+4)+2)] = *(context+8)`，下标 ≥2 全部可控）与 `case 0`（`sub_19AD`）**。
- **漏洞点（sub_19AD → sub_1837）**：`case 53` 先 `sub_12E8(qword_6120+0x18)` 校验，然后调 `sub_1837(*(context+4), qword_6120+0x10, qword_6120[0x18/8]+qword_6120[0], ...)`。由于第三参是 `qword_6120[3] + qword_6120[0]` 这类**可控下标相加**，可以直接指到 `0x64617461000` 之后的地址，功能号则由 `content+4` 决定：0=read(fd,buf,len) 把 stdin 读进 data 段、1=write(fd,buf,len) 把 data 段打到 stdout、2=exit、3=add_heap(size)、4=free_heap(idx)、5=read_from_memory（data→heap）、6=write_to_memory（heap→data）。
- **为什么能"打印"**：VM 里没有直接的输出原语，输出是拼出来的——先 `write_to_memory(heap→data+off)`，再 `write(fd=1, data+off, len)`，泄露值才能回到脚本手里。同理输入先进 data 段，再由 `read_from_memory` 搬进堆块。
- **UAF**：`sub_15FE` 里 `if (qword_6060[a1]) free(qword_6060[a1]);`，free 后**不清空 `qword_6060[idx]` 也不清 `dword_60E0[idx]`（size）**，所以同一 index 在 free 之后 `read_from_memory`/`write_to_memory` 依旧能访问已释放块，这就是全链的基础原语。堆块数量上限 16（`for i<15 && qword_6060[i]`，i==16 返回 0），add 大小受 `sub_12E8` 限制（该分支要求 `qword_6120[3] <= 0x30000`）。
- **为什么需要"重新读入 vmcode"**：泄漏到的 libc/heap/栈地址在攻击者侧才知道，必须第二次、第三次把新算好的地址写进 opcode 流再喂给程序；而程序本身就是循环读 opcode（第一段 vmcode 里就包含"打印 Please input your opcodes"和读入的逻辑），因此只要上一段字节码末尾不触发 exit，就能继续发下一段，天然支持多轮。
- **三段链的整体成立原因**：largebin 的 freed chunk 里残留 `fd/bk` 指向 libc 与 heap，用 UAF 的 `write_to_memory` 把整块内容搬到 data 段再 write 出来即得两个基址；tcache 的 `fd` 是攻击者可控的下一块指针，改成 `environ` 就能让下一次 malloc 返回 `environ` 所在地址，读出来即栈地址；再改 `fd` 指向某个确定会返回的函数的返回地址（原文选 `sub_132D` 失败返回 -1 的那条路径），malloc 拿到栈地址后写 ROP 链，等该函数返回即 execve shell。

## 触发条件

- 目标为自定义 VM 题：`mmap` 固定地址（code/data/stack）并从标准输入循环读取 opcode 流解释执行。
- 首字节低 2 位为操作数格式位、高 6 位为 handler 号；存在"给 `qword[]` 数组任意下标赋值"的指令（用于摆参数）。
- VM 的某个 handler 把可控参数直接传给宿主 `malloc/free/read/write`，且 `free` 不置空指针（UAF）。
- data 段地址固定，且存在「data→heap」「heap→data」的搬运指令（用作输入/输出通道）。
- 目标 glibc 存在 tcache（≥2.26），且 `environ` 与可用返回地址位置在当前 libc 中可解析。
- 程序在一条 handler 返回后仍继续解释下一条 opcode（不会在失败时直接退出），从而可多轮发包。

## 利用步骤

1. 逆清取码规则后，写最小封装：`assign(index, value)` = `p32((3<<2|3)...)` 形态的 10 字节指令（低 2 位=3，高 6 位=3 即"赋值"，第二字节是数组下标，后 8 字节是 value）；`op(caseno, fn, a, b, c)` 用于调用 `sub_1837` 类 handler。
2. 泄漏 libc/heap：`assign(0, 0x500)` 设大块大小 → `add` 块 0 → 改成 `0x90` 再 `add` 块 1（挡住 top chunk 合并）→ 把 index 设 0 → `free(0)` → 设 `0x600` 再 `add`（块 0 进 largebin，块 2 占用它，freed 块残留 fd/bk）→ `assign` 设 index/offset/length → `write_to_memory` 把块 0 前 0x20 搬进 data+0x20 → `assign` 设 fd=1/offset/length → `write` 打出，脚本收 6 字节：`libc = leak - <对应偏移>`，`heap = 后续 6 字节 - <偏移>`。
3. 泄漏栈：重新读入新 opcode，`assign(0, 0x90)` → `add` 块 3 → `add` 块 4 → `free(1)`、`free(4)` 造 tcache 链 → 读入 `p64((heap+off)>>12 ^ environ)` 写进块 1 的 fd → 再 `add` 两次，第二次 `malloc` 即返回 `environ` 地址 → `write_to_memory` 搬出 → `write` 打出，得栈地址。
4. 写 ROP：第三次读入，`0x80` 大小 `add` 块 7/8/9 → `free(7)`、`free(8)` → 读入 `p64((heap+off)>>12 ^ stack_target)` 改块 8 的 fd → 两次 `add`，第二次返回 `stack_target` → 读入 ROP 链（`stack_addr*4 + pop_rdi + ret + pop_rdi + "/bin/sh" + system`）→ `write_to_memory` 写入 → 发送 `p64(0)` 触发该栈帧返回，拿 shell。
5. 每轮用固定输出串（如 `Please input your opcodes:`）同步脚本的 `sendlineafter`/`recvuntil`，`write` 后的固定长度 `recv` 取泄露值。

## PoC

```python
from pwn import *
io = process('./vm')
libc = ELF('./libc.so.6')

def send_vmcode(code): io.sendlineafter('opcodes:\n', code)

# 制造 largebin freed chunk 并把其 fd/bk 搬到 data 段
code  = p32(0x0500000f).ljust(10, b'\x00')   # 低2位=3,高6位=3 -> assign(idx0)=0x500
code += p32(0x030000cc)                      # 低2位=0,高6位=51 -> add_heap(size)
code += p32(0x0090000f).ljust(10, b'\x00')   # assign(idx0)=0x90
code += p32(0x030000cc)                      # add（挡住合并）
code += p32(0x0000000f).ljust(10, b'\x00')   # assign(idx0)=0
code += p32(0x040000cc)                      # free(0)
code += p32(0x0600000f).ljust(10, b'\x00')   # 放大 size 后再 add，0x500 块进 largebin
code += p32(0x030000cc)
# 设 index/offset/length 后 write_to_memory + write 打出
code += p32(0x0000000f).ljust(10, b'\x00')
code += p32(0x0020010f).ljust(10, b'\x00')
code += p32(0x0020020f).ljust(10, b'\x00')
code += p32(0x060000cc)                      # write_to_memory(heap->data)
code += p32(0x0001000f).ljust(10, b'\x00')
code += p32(0x0020010f).ljust(10, b'\x00')
code += p32(0x0020020f).ljust(10, b'\x00')
code += p32(0x010000d4)                      # write(fd=1, data+off, len)
send_vmcode(code)

libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x21b110   # 偏移随题目 libc 而定
heap_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x2b0
# 第二轮：tcache 投毒 -> environ，泄栈地址
# 第三轮：tcache 投毒 -> 返回地址，写 ROP
```

（完整 exp 的长字节码按上述封装逐段拼装；偏移 `0x21b110`/`0x2b0`/`0x2a3e5`/`0x29139` 为原文环境 libc，换环境需重新对齐。）

## 变体与关联

- 变体：handler 直接暴露"任意地址读写"（寄存器当宿主指针）时不需要 data 段中转，可用 VM 自带的 read/write 原语直接泄地址（见 [[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]）。
- 变体：若 tcache 投毒被 safe-linking 挡住，可先泄 heap 再按 `(addr>>12)^target` 编码，或用 largebin/unsorted 打 `_IO_list_all`、`__free_hook`（视 glibc 版本）。
- 变体：栈目标若在返回前被其它指令覆盖（本例试过 add heap 等地址失败），改用"失败返回 -1 的早退路径"返回地址最稳。
- 关联：[[ctf-reverse-vm-opcode-low2-format-high6-dispatch]]（前置：还原本族 opcode 编码）。
- 关联：[[ctf-pwn-vm-opcode-heap-primitive-wrapper-uaf-leak]]（同为 VM 套堆；该卡的 handler 是对外暴露的 add/free/edit/show 封装、止步于 UAF 泄 libc/heap，本卡是 handler 直通 read/write/add/free 六功能，并打通 largebin→environ→栈 ROP 的完整三段链，触发条件与 PoC 不同）。
- 关联：[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（堆侧通用手法）。

## 检测与防御

- 出题/防守视角：VM handler 不要把虚拟寄存器直接喂给宿主 `malloc/free/memcpy`，功能号与每个参数都要白名单与范围校验；`free` 后必须置空指针与 size，`read/write` 的长度必须不超过块大小并检查目标偏移落在 data 段内。
- 加固：data/code/stack 段不要用固定地址 `mmap`（随机化后 opcode 无法写死偏移）；对 opcode 流做长度与操作数合法性预校验，拒绝非法 `(case,fmt)` 组合。
- 检测（分析视角）：出现「`& 3` 与 `>> 2` 配对的分派 + 固定地址三段 mmap + 四参数直通堆函数」即为 VM 套堆题的强特征；`free` 后未 `memset` 槽位是 UAF 的判定点。
- 检测（利用痕迹）：程序被同一进程反复喂入多段 opcode、短时间内大量 `add/free` 交替、`write` 输出的内容呈 `0x7f...`/`0x55...` 指针形态，是典型的三段链节奏。
