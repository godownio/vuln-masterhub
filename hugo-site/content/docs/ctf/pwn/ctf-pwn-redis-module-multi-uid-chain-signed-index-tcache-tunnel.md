---
id: ctf-pwn-redis-module-multi-uid-chain-signed-index-tcache-tunnel
title: Redis 模块多级 UID 隔离链：对象复用泄密、有符号索引写 route 头、负索引读控制块、tcache safe-linking 投毒与六层隧道
type: scenario
domain: ctf
path: ctf/pwn
technique: redis-module-multi-uid-service-chain-signed-index-tcache-tunnel
tags:
- pwn
- ctf
- redis
- module
- multi-stage
- uid-isolation
- signed-index
- negative-index
- tcache
- safe-linking
- protocol-tunnel
- rop
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:56:09+08:00'
  notes: 已对照原文核对；六层 UID 拓扑、relay 对象复用泄密、broker 有符号索引、vault 负索引、ledger/council tcache 投毒与隧道规则一致
url: /docs/ctf/pwn/ctf-pwn-redis-module-multi-uid-chain-signed-index-tcache-tunnel/
draft: false
kb_aliases:
- redisrelay
- Redis 模块多级链
- 六层 UID 隔离
- 有符号索引越界
- 负索引读控制块
- tcache safe-linking 投毒
- 协议隧道
- relaybroker
- routeattestor
- routevault
- routeledger
- routecouncil
---

## 一句话结论

redisrelay 用六个 UID/地址空间把 flag 锁在最深一层：Redis 模块 → relaybroker → routeattestor → routevault → routeledger → routecouncil，选手只能在同一条 Redis 连接里逐层取得“能力”。可复用的核心是：每层用对象释放-复用/负索引/有符号索引泄漏本层随机 key 与地址，用 tcache safe-linking 或相对写把伪造对象写进 `.bss` 的 ready/gate 字段，再把下一层帧塞进当前层的隧道操作里，一层层把 TCP 字节流转接下去。

## 原理

- **拓扑与隔离**：六者分属六个 UID/六个独立地址空间，只有每会话的 council worker 持有动态 flag 的只读 fd（fd4）。每层监听 unix socket，父进程 `accept` 后 `fork`，子进程先连下一层并替他写好 16 字节握手前缀，再 `dup2` + `execve --serve`；所以选手从 Redis 侧只用一条 TCP，往下每一层都是“上一层隧道里塞下一层的帧”。
- **统一帧格式**：除 Redis RESP 外，五层共用 `u32 total_len + 16 字节头`：`magic(4 ASCII) | op | idx | idx2 | zero | bodylen(u32) | seq(u32)`，`bodylen == total_len-16`，`seq` 必须严格递增；回包同构，只换 magic。任何长度/魔数/seq 不合法，会话直接退出。
- **第 0 层 Redis 模块**：每客户端 session 字段含 `obj/bound/ledger/stamps/broker fd` 等；`relay.begin <seed>` 分配 512 字节 route 对象。`relay.retire` 释放 obj 但保留 `session+0x10` 悬垂指针，`relay.ledger` 分配 512 字节，当且仅当返回地址等于旧 obj 时登记为 ledger（jemalloc 512 类复用），于是 `relay.snapshot` 读到的 80 字节就是 ledger 头，泄露 key3/模块基址/key2/key1；再与 retire 前 snapshot 的 `obj ^ key3` 异或得到 obj 地址。`relay.stampinfo i` 返回 stamp 的 `+0x10`，与 key3 异或直接得到 stamp 自地址，不需要预测 jemalloc 布局。
- **第 1 层 relaybroker**：probe 释放后别名不清空，`0x14` 可整块重写已释放的 0x90 块；`0x15` 用 probe 头做相对代码 ±0x20000 的任意 qword 读（每次成功后清别名槽，需重新 `0x10→0x11→0x13→0x14→0x15` 链）。读 `0x7048/0x7050/0x70C0/0x7060` 得到 key2/key1/route/slice 指针；`0x22` 写 route 时索引是 `movsx` 有符号字节，只做 `sil > 0x37` 的上界检查，负数全部通过，`0xFC..0xFF` 分别写 `route+0x20/+0x28/+0x30/+0x38`；把 route 的 `+0x20` 改成 `sub_4000` 的运行地址编码、`+0x28` 改成 slice chain、`+0x30=1`、`+0x38` 重算 mix，`0x23` 通过后连上 attestor。
- **第 2 层 routeattestor**：`0x30/0x31/0x32` 建/链/释放 tauil，`0x40` 再建一个复用同块，`0x33` dump 出字段反 key（K60/K58/base）；seal 门正常路径永远算 `sub_2400`、调不到 `sub_4000`，所以用 `0x41` 的相对写：目标 `u32(obj+0x28)+off+(ror(v48,19)^K60^obj)`，校验 self、mix、长度后 `memcpy` 到目标；把 4 字节 1 写到 `.bss` 的 `dword_7040`，`0x51` 即通过，`0x60` 把帧转进 vault。
- **第 3 层 routevault**：opcode 5 是字节码“查询”，body 为 16 字节记录序列，其中 `'-'` 记录把**有符号字节**累加到游标，`'C'` 记录读 `*(u64*)(qword_71E0 + 8*cursor + 0x30)`；游标没有下界检查，传 `val=0xFA..0xFF` 即可读控制块 `+0x00..+0x28`，拿到 key0/key8/key16/self/&sub_2680/key40，`base=key32-0x2680`；`pass=rol(key0^key24^key32^key40^0x452821E638D01377,19)`，opcode 6 解锁。伪造 RTICKET3/RCNTEXT3 时把 `+0x20` 的函数指针改成 `base+0x2670`（`lea rsp,[rdi+0x40]; ret`），opcode 46 通过后栈迁到 A+0x40 执行 ROP；`sub_4000` 校验伪造 `RLEDGER5` 后把 `dword_704C=1`，opcode 96 即可向 ledger 发完整帧。
- **第 4 层 routeledger**：`0x7F` ping 返回 `ctx+0x200` 的 keyE[4] 与 `LGMODMV5`；`0x10` 的 manifest VM 记录格式 `[op][idx][off][0][u16 chk][...]`，`'q'` 游标有符号且只查上界，`ctx+0xC0+8*cursor` 可负索引，4 次调用 dump 12 对 `(tag,value)`，反推 key0/key1/key2[4]/keyD0/keyD1/keyF 与 PIE base；`0x11` 用两个哈希解锁。真正的门是两次 tcache safe-linking 投毒：`0x20` 建 0x98 的 `RLGMANF5` 对 → `0x21` free → `0x22` dump 解自地址 → `0x23` 写 `body0=&0x6270^(obj>>12)`、`body1=H("bLGMANF5",...)` → `0x24` 两次 `malloc(0x98)`：第一块拿回 obj、第二块落到 `.bss 0x6270` 写入假 `LPERMIT5`；同法把假 `RLRELAY5` 写到 `0x6070`；`0x40` 通过后 `0x60` 把帧转进 council。
- **第 5 层 routecouncil**：`0x10 idx=0xFC..0xFF` 利用 `(u8)(ptra-4)==idx` 且 `(signed)idx<=3` 的符号差，连续 4 次泄漏 `::buf_[0..15]`，解码 nonce/K0..K5/ALT0/ALT1；`0x7F` ping 用两个 XOR 式泄漏 PIE base 并互验；`0x20` 的 body 是 1024 字节 RLE（必须 512 组、每组 count=1），展开 512 字节写到 `.bss 0x5260`，前 0x100 是 32 个 plan hash、后 0x100 是 `CNCPRMT5` permit 对象，`sub_2740` 校验通过后 `dword_5070=1`；`0x30/0x31/0x32/0x33/0x34` 再用 tcache safe-linking 投毒，把 `CNCGATE5` gate 写进 `.bss 0x50D0`；`0x40` 九项校验全过后 `sub_2C80` 执行 `lseek(4,0); read(4,buf,0x100); reply(0xC0,buf)`，读出 flag。
- **集成的四条硬规则**：1）每层握手前缀由父进程代发，选手永远不要自己发；2）`seq` 跨层接续（如 ledger 已用 council seq=1 ping，council 阶段从 2 开始）；3）注意帧长上限（vault opcode 96 body/回包都限 0x600，最大 council 帧刚好过）；4）远端失败不要重启 Redis，只 sleep 后新开连接重试。

## 触发条件

- 目标是 Redis 模块 + 多级 broker/协议链的 CTF PWN 题或类似的多进程隔离服务；每层独立 UID/地址空间，只有最后一层持有 flag fd。
- 每层有对象创建/释放/dump/整块写接口，存在 UAF、相对读/写、有符号索引或负索引。
- 二进制开启 Full RELRO/Canary/NX/PIE/SHSTK/IBT，但每层都留有“能读控制块”或“能写 `.bss`”的口子。
- 能在同一条连接里嵌套多级帧，并满足各层 seq/长度/魔数校验。

## 利用步骤

1. 第 0 层：`relay.begin`、`relay.bind`、`relay.retire`、`relay.ledger` 制造 512 类复用，`relay.snapshot` 反推 key1/key2/key3/模块基址/obj；`relay.stampinfo` 拿 stamp 地址；`relay.fragment` 填 512 字节 route 镜像，`relay.commit` 得到 broker 能力。
2. 第 1 层：建 probe/route/slice，UAF + 相对读泄露 key1/key2 与 route/slice 指针；用 `0x22` 的负索引写 route 头，伪造 `sub_4000` 地址与 digest，`0x23` 过 gate。
3. 第 2 层：tauil 复用 dump 反 key，用 `0x41` 相对写把 `.bss` 的 `dword_7040` 置 1，`0x50/0x51` 过 seal，`0x60` 进 vault。
4. 第 3 层：opcode 5 负索引读控制块，算口令解锁；伪造 RTICKET3/RCNTEXT3，把函数指针改成 `base+0x2670` 栈迁移 ROP，`sub_4000` 置 `dword_704C=1`，opcode 96 进 ledger。
5. 第 4 层：manifest VM 负索引泄露 key 表，算两个哈希解锁；两次 tcache safe-linking 投毒把 permit/relay 模板写进 `.bss`，`0x40` 过 gate，`0x60` 进 council。
6. 第 5 层：`0x10` 有符号 idx 泄漏 `::buf_`，解码 nonce/key；`0x7F` 泄漏 PIE；`0x20` RLE 计划过 `sub_2740`；`0x30..0x34` 投毒写 gate；`0x40` 调 `sub_2C80` 读 fd4 拿 flag。
7. 按四条规定拼接各层帧；每层先用 ping/hello 验证隧道，再跑下一层 stage。

## PoC

统一帧构造（按原文头格式；各层 magic 不同）：

```python
def frame(magic, op, idx=0, idx2=0, body=b"", seq=0):
    hdr = magic + bytes([op, idx, idx2, 0])
    hdr += struct.pack("<I", len(body)) + struct.pack("<I", seq)
    return struct.pack("<I", len(hdr) + len(body)) + hdr + body
```

负索引泄露控制块的核心（vault opcode 5）：

```python
rec = b""
for rel in range(-6, 0):
    rec += bytes([ord("-"), rel & 0xff, ...])   # '-' 记录：有符号累加游标
    rec += bytes([ord("C"), 0, ...])            # 'C' 记录：读 qword_71E0+8*cursor+0x30
    rec += bytes([ord("y"), 0, ...])
send(0x05, rec)
```

tcache safe-linking 投毒（ledger 0x23/0x24）：

```python
body0 = (base + 0x6270) ^ (obj >> 12)   # glibc 2.35 safe-linking
body1 = H("bLGMANF5", ...)
send(0x23, p64(body0) + p64(body1))
send(0x24, b"")   # 两次 malloc(0x98)：第一块回 obj，第二块落到 .bss 0x6270
```

原文完整 exp 未在本库复跑；各层偏移/密钥公式见原题附件与 `ledger_lib.py`/`council_poc.py`。

## 变体与关联

- **索引变体**：`movsx` 有符号字节只查上界、`'-'` 记录有符号累加无下界、`(u8)(ptra-4)==idx` 的符号差；凡是“索引被当作有符号/截断”都可能越界。
- **对象复用变体**：释放后不置空、同尺寸分配复用、dump 读已释放对象；用于泄露 key/地址或改写 ready 字段。
- **写 `.bss` 变体**：相对写、tcache safe-linking 投毒、RLE 展开写；目标通常是 permit/relay/gate 对象或 ready 标志。
- **隧道变体**：每层用 `u32 len + frame` 或 `0x60/0x96` 操作码转发；注意前缀、seq、帧长上限。
- **关联卡片**：[[ctf-pwn-vaultcache-redis-module-rdb-off-by-8-sds-oob]]（vaultcache 的 RDB off-by-8 + broker longjmp，复用同一套 ledger/council 协议）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 编码）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 函数指针）。

## 检测与防御

- **对象生命周期**：释放后置空指针、清除别名与读/写标志；dump 接口不得返回已释放对象。
- **索引/长度**：所有索引和长度使用完整位宽并做上下界检查；不要把用户可控字节当有符号索引直接参与指针运算。
- **写目标**：`.bss` 中的 key/gate/ready 对象应只读或带完整性校验；tcache fd 不应能指向 `.bss`/槽位数组。
- **协议**：每层握手前缀、seq、长度、magic 必须严格校验；隧道转发要限制嵌套深度与帧长。
- **隔离**：每层独立 UID/命名空间；flag 只对最后一级可读；禁止 `/proc/<pid>/root`、`/proc/<pid>/mem` 横向访问。
- **检测**：Redis 模块出现异常 512 类对象复用、broker/attestor 出现负索引或相对写、ledger/council 出现 tcache 投毒与 `.bss` gate 改写。
