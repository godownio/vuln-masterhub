---
id: binary-pwn-heap-heap3-negative-size-fastbin-unlink-puts-got-shellcode
title: Protostar heap3 负数 size 触发 fastbin unlink：伪造 fd/bk 覆盖 puts@GOT 跳堆上 shellcode
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap3-negative-size-unlink-got-shellcode
tags:
- pwn
- heap
- fastbin
- unsafe-unlink
- got
- shellcode
- protostar
- heap3
- glibc211
- 32bit
cve: []
severity: high
confidence: high
affected_versions: glibc 2.11.2（原文 GDB 映射 /lib/libc-2.11.2.so，32 位；旧版 glibc，现代版本有 unlink 完整性检查）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T12:08:51+08:00'
  notes: 已对照原文 content.md 与 61 张图片核对：img41-59 为 heap3 chunk 结构/unlink 图示/三次 malloc(32)+strcpy+free(c,b,a)/负数 size 0xfffffffc 伪造 fd=puts@GOT-12、bk=0x804c040/shellcode push winner;ret/puts@GOT 被写成 0x804c040/输出 that wasn't too bad now；与卡内偏移与 payload 完全一致。affected_versions 为原文 GDB 映射的 libc-2.11.2（32 位，旧版无 unlink 校验），非猜测。技术原子独立、粒度合格；dedup 除自身外仅 related（glibc2.23 unsafe unlink 劫持 chunks 数组→GOT 泄露→system，版本/触发/链不同），并列保留。未验证点：未复跑 exp，GOT/堆地址随二进制变化。
url: /docs/binary/pwn/heap/binary-pwn-heap-heap3-negative-size-fastbin-unlink-puts-got-shellcode/
draft: false
kb_aliases:
- heap3
- Protostar heap3
- 负数 size
- fastbin unlink
- unsafe unlink
- puts@GOT 覆写
- 堆上 shellcode
- unlink 任意写
---

## 一句话结论

Protostar heap3 中连续 `malloc(32)` 的 a、b、c 三个 chunk 按 `free(c); free(b); free(a);` 释放；b 的 32 字节数据紧邻 c 的 chunk 头，`strcpy(b, argv[2])` 溢出可把 c 的 `prev_size`/`size` 改为 `0xfffffffc`。该 size 最低位为 0，free(c) 误判前一个 chunk 空闲并执行无校验的 `unlink`：`FD->bk = BK; BK->fd = FD`。把伪造 chunk 的 `fd = puts@GOT-12`、`bk = 堆上 shellcode 地址`，即可让 `puts@GOT` 被写成 shellcode 地址，随后 `puts` 调用跳到 6 字节 shellcode `push winner; ret`。

## 原理

- **chunk 布局**：32 位下 `malloc(32)` 返回的 chunk 大小为 0x28（8 字节 header + 32 字节 data）。a、b、c 连续分配时，b 的 32 字节 data 正好覆盖到 c 的 `prev_size`/`size` 字段，因此 `strcpy(b, argv[2])` 是控制 c 头的溢出点。
- **fastbin 释放顺序**：三个 0x28 chunk 属于 fastbin 范围；`free(c)`、`free(b)`、`free(a)` 后，fastbin 单链表按后进先出串起，便于后续 unlink 使用伪造的相邻关系。
- **负数 size 的作用**：`size` 字段按无符号数处理，`-4 = 0xfffffffc`；最低位（PREV_INUSE）为 0，free 认为前一个 chunk 空闲，需要执行向后合并并调用 `unlink`。由于 `prev_size` 也是负数，前一个 chunk 的地址通过 `当前 chunk 起始 - (-4)`（即 `+4`）计算，落回攻击者可写的区域。
- **unlink 任意写**：旧版 glibc 的 `unlink(P, BK, FD)` 为 `FD = P->fd; BK = P->bk; FD->bk = BK; BK->fd = FD;`，没有 `FD->bk == P && BK->fd == P` 校验。把 `P->fd = puts@GOT - 12`、`P->bk = shellcode 地址`，则 `FD->bk = BK` 等价于 `*(puts@GOT) = shellcode`；同时 `BK->fd = FD` 会覆盖 `shellcode+8` 处，因此 shellcode 必须不超过 8 字节并放在 `bk` 指向处。
- **shellcode 与收尾**：`push 0x08048864; ret`（`\x68\x64\x88\x04\x08\xc3`）把 winner 地址压栈后 ret，等价于调用 winner。第三个参数还要把下一个相邻 chunk 的 size 的 PREV_INUSE 置奇数（原文用 0xff 填充），避免 free 继续对下一个块做合并/unlink 而破坏。
- **触发点**：三个 free 完成后 main 调用 `puts`（原文 GDB 显示 printf 被解析为 puts），puts@GOT 已被改写为堆上 shellcode 地址，直接跳转执行。

## 触发条件

- 32 位、非 PIE 或固定加载地址的 ELF，Partial RELRO（GOT 可写），程序用 `strcpy` 把命令行参数写入 32 字节堆块且无长度校验；
- glibc 版本未引入 unlink 完整性检查（原文环境 libc-2.11.2；2.27+ 的 `FD->bk == P && BK->fd == P` 会阻断该链）；
- 攻击者能指定三个参数，且堆地址/puts@GOT 地址可预测或已知（ASLR 关闭或可泄露）；
- winner 或目标函数地址已知（非 PIE）。

## 利用步骤

1. `checksec`/GDB 确认 32 位、GOT 可写；定位 `puts@GOT`（原文 0x804b128）与 `winner`（0x8048864）。
2. 第一个参数随意（如 `AAAA`）。
3. 第二个参数覆盖 b 的 32 字节数据，并在末尾写 c 的 `prev_size`/`size` 为 `0xfffffffc`：前 16 字节垃圾 + 6 字节 shellcode + 填充到 32 字节 + 两个 `p32(0xfffffffc)`。
4. 第三个参数写入 c 的数据区：4 字节垃圾 + `p32(puts@GOT-12)` + `p32(shellcode 地址)`，作为伪造 chunk 的 fd/bk。
5. 运行 `./heap3 "$(cat A)" "$(cat B)" "$(cat C)"`；观察 puts@GOT 变为 0x804c040，程序输出 winner 的提示。
6. 若 winner 不可达，可把 bk 指向任意可执行地址（如 one-gadget/系统命令函数），按同样 unlink 写完成劫持。

## PoC

原文 Python payload 生成逻辑：

```python
import struct

buf1 = 'AAAA'

buf2 = ''
buf2 += '\xff' * 16
buf2 += "\x68\x64\x88\x04\x08\xc3"      # push 0x08048864; ret (winner)
buf2 += '\xff' * (32 - len(buf2))
buf2 += struct.pack('I', 0xfffffffc) * 2  # c 的 prev_size / size

buf3 = ''
buf3 += '\xff' * 4
buf3 += struct.pack('I', 0x804b128 - 12)  # puts@GOT - 12
buf3 += struct.pack('I', 0x804c040)       # shellcode 在堆上的地址

for name, buf in zip(['/tmp/A', '/tmp/B', '/tmp/C'], [buf1, buf2, buf3]):
    open(name, 'wb').write(buf)
```

执行：`./heap3 $(cat /tmp/A) $(cat /tmp/B) $(cat /tmp/C)`。原文实测 puts@GOT 被覆盖为 0x804c040，随后输出 `that wasn't too bad now, was it?`。

## 变体与关联

- **关联**：`binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system` 是同一 `unlink` 任意写在 glibc 2.23 上的另一形态（溢出伪造 chunk → 劫持 chunks 数组 → GOT 泄露 → system）；本卡是 32 位旧版 glibc、用负数 size 触发 fastbin unlink、直接把 puts@GOT 改成堆 shellcode，环境与 PoC 不同。
- **变体**：把 `bk` 指向 `__free_hook`/`__malloc_hook`/`.fini_array` 或栈上返回地址；把 shellcode 换成 one-gadget；若目标无 winner，可用 GOT 覆写调用 system。
- **边界**：现代 glibc 的 unlink 校验、Full RELRO、PIE/ASLR、`_FORTIFY_SOURCE` 会显著提高难度；本卡依赖旧版分配器语义，不可直接套用到 2.27+。

## 检测与防御

- **防御**：升级 glibc（unlink 完整性检查）、开启 Full RELRO/PIE/ASLR、使用 `strncpy`/`snprintf` 等有界拷贝、编译加固（`-D_FORTIFY_SOURCE=2`、stack protector）。
- **检测**：监控进程对 GOT 区域的写操作；非预期 `free` 负数/超大 size、堆头 `prev_size/size` 被改写；崩溃点集中在 `unlink`/`free` 且 GOT 指向堆地址。
- **分析**：用 GDB 断在 free/unlink，检查 chunk 头与 fastbin 链表；核对 `puts@GOT` 是否指向堆；必要时用 Valgrind/ASan 复现。
