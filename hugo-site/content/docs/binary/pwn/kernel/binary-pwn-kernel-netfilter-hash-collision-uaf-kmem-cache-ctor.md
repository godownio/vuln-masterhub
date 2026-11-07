---
id: binary-pwn-kernel-netfilter-hash-collision-uaf-kmem-cache-ctor
title: netfilter 模块 8bit hash 冲突 UAF：伪造 sec_conn AAR/AAW，改 kmem_cache->ctor 执行 slab shellcode
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-netfilter-hash-collision-uaf-kmem-cache-ctor
tags:
- kernel
- pwn
- netfilter
- hash-collision
- uaf
- aar-aaw
- kmem-cache
- ctor
- set-memory-x
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:53:08+08:00'
  notes: 已对照原文 netsec 核对：hash_table[0x100]+HASH 公式、create 覆盖/destroy 释放不清表项且 get 只比 hash、get_sec_conn_buf 0x28 走 kmalloc、伪造 sec_conn 的 in_key/out_key/buf 做 AAR/AAW、.bss in_key+0x800/cache+0x820、cache+0x78=slab_caches 推 kbase、ctor 在 cache+0x50 并先 set_memory_x(+0x2ba1a0) 再 slab2 shellcode、filp_open+0x48e190/kernel_read+0x490ab0 读 /flag.txt 均一致；原文有实测 flag，未本机复跑。内核 6.18.7 为题目环境，不作为 affected_versions。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-netfilter-hash-collision-uaf-kmem-cache-ctor/
draft: false
kb_aliases:
- netsec
- 8bit hash collision
- sec_conn UAF
- 伪造 sec_conn
- kmem_cache ctor 劫持
- set_memory_x
- slab shellcode
---

## 一句话结论

netfilter 模块用 8bit hash 表保存 `sec_conn`，查找只比较 hash 不比较完整 `(ip,port)`，销毁时释放 `sec_conn`/`out_key` 却不清 `hash_table[h]`；攻击者制造 hash 冲突让一条活连接命中已释放对象，再通过伪造 `sec_conn` 的 `in_key/out_key/buf` 指针获得内核 AAR/AAW，读取模块全局与 kernel base 后把 `kmem_cache->ctor` 改成 `set_memory_x` 使 slab 页可执行，最终把 ctor 指向 slab 中的 shellcode，读 `/flag.txt`。

## 原理

- 模块创建 `kmem_cache("netsec", sizeof(struct sec_conn)=0x20, ...)`：
  ```c
  struct sec_conn {
      uint8_t *in_key;
      uint8_t *out_key;
      uint8_t *buf;
      uint buf_len;
  };
  ```
  收包方向用 `in_key` 解密，发包方向用 `out_key` 加密；两条 key 都由公开 KDF（端口/固定 seed）生成，用户态可复算。
- 连接表 `hash_table[0x100]`，索引：
  ```c
  HASH(ip, port) = ((ip>>24)^(ip>>16)^(ip>>8)^ip^(port>>8)^port) & 0xff;
  ```
  `get_sec_conn(ip,port)` 只返回 `hash_table[HASH(ip,port)]`，不比较完整 IP/port。
- 生命周期缺陷：
  - `create_sec_conn`：`hash_table[h] = sconn`，冲突时直接覆盖旧指针。
  - `destroy_sec_conn`：释放 `out_key`、`buf`、`sconn`，但不清 `hash_table[h]`。
- 攻击：找两个源端口 `p1`、`p2` 同 hash。开 p1 创建 S1/K1，开 p2 创建 S2/K2 覆盖 `hash_table[h]`，关闭 p2 释放 K2/S2；此后 p1 仍活着，但模块按 hash 取到已释放的 S2 → UAF。
- `get_sec_conn_buf()` 在 `buf_len < len` 时 `kfree(buf)` 并重新分配：`len<=0x20` 从 netsec cache 取，`len>0x20` 走 `kmalloc`。先发 0x28 走 kmalloc，不立即占回 netsec 对象，保留 dangling S2 的旧字段。
- 利用旧 `out_key` 指针与已释放 K2 中的 allocator 元数据，可泄漏 slab/heap 地址；把 freed S2 重占为可控 0x20 对象后，模块把它解释成新的 `sec_conn`。
- AAR：伪造 `in_key=NULL`（输入不 XOR）、`out_key=target`（输出把 target 内容当 key 与 0 异或）、`buf=dummy`、`buf_len=0x20`；发送 8 个 0，回包即 `*(target)`。
- AAW：伪造 `in_key=NULL`、`out_key=NULL`、`buf=target`、`buf_len=len`；输入方向把 payload 直接 copy 到 target。
- 模块 `.bss` 布局：`hash_table +0x000`、`in_key +0x800`、`cache +0x820`；从 slab 附近读 `in_key` 地址，再读 `in_key+0x20` 得全局 `cache` 指针。
- kernel base：`struct kmem_cache` 挂在全局 `slab_caches` 链表；`cache+0x78` 读出 KASLR 后的 `slab_caches`，减去 `_text+0x10e1560` 得 kbase。
- `kmem_cache` 字段：`ctor` 在 `cache+0x50`（原为 NULL），`name` 在 `cache+0x68`（可读 "netsec" 校验），`list` 在 `+0x70/+0x78`。把 `ctor=set_memory_x`，下一次 `kmem_cache_alloc(cache)` 会以新对象地址为 `rdi` 调用 `set_memory_x(object)`，把 slab 页改为可执行。
- 再把 `ctor=slab2_addr`，在 slab2 写入 shellcode，下一次分配触发 `ctor(object)` → RIP 跳到 shellcode；shellcode 调 `filp_open("/flag.txt")` + `kernel_read` 读 flag，重置 `ctor=0` 后返回。
- 这是数据-only + 控制流劫持结合：先 AAR/AAW 拿任意读写，再借 SLUB constructor 回调作为稳定调用入口。

## 触发条件

- 存在 netfilter/内核模块，用 hash 表保存连接对象，查找只比较 hash 不比较完整键。
- 销毁路径释放对象但不清表项，或存在其他 UAF/悬垂指针。
- 对象来自独立 `kmem_cache`，大小可控，且可被跨 cache/同 cache 重占。
- 攻击者能建立多条 TCP 连接并控制源端口，制造 hash 冲突。
- 内核符号偏移已知（同版本 vmlinux/BTF/kallsyms），或可通过泄漏计算 kbase。
- 模块允许通过数据包路径触发对象分配/释放。

## 利用步骤

1. 复现 hash 冲突：计算 `HASH(local_ip,p1)`，从 2000 起找同 hash 的 p2；开 p1、p2，再关闭 p2，使 `hash_table[h]` 悬垂到已释放 S2。
2. 泄漏 slab：向 p1 发 0x28 字节（走 kmalloc），利用旧 `out_key`/释放元数据与已知 KDF 反推得到 heap/slab 地址。
3. 重占 S2：构造与 `sec_conn` 同大小的可控对象，写入伪造字段；后续 p1 发包路径把该对象当 `sec_conn` 使用。
4. 建立 AAR/AAW：用 `in_key/out_key/buf` 三种伪造组合读取模块 `.bss` 与写入目标地址；注意两层 XOR 要先预抵消。
5. 读 `in_key` 地址 → `cache` 指针 → `cache+0x78` 得 `slab_caches` → 计算 kbase 与 `set_memory_x`/`filp_open`/`kernel_read` 地址。
6. 改 `cache->ctor = set_memory_x`，触发一次 netsec cache 分配，使对应 slab 页可执行。
7. 再制造一次冲突/UAF 拿到 slab2 地址，改 `cache->ctor = slab2_addr`，把 shellcode 写入 slab2。
8. 触发一次 netsec cache 分配，SLUB 调用 ctor → 执行 shellcode，读 `/flag.txt` 到可读地址；用户态用 AAR 分段读回。
9. shellcode 内把 `cache->ctor` 重置为 0，避免后续分配再次跳转。

## PoC

```c
#define HASH(addr, port) (((addr >> 24) ^ (addr >> 16) ^ (addr >> 8) ^ (addr) ^ (port >> 8) ^ (port)) & 0xff)
#define CACHE_SIZE 0x20

// 找同 hash 的源端口
short get_collision(short port) {
    int i = 2000, target_hash = HASH(LOCAL_IP, port);
    while (HASH(LOCAL_IP, i) != target_hash) i++;
    return i;
}

// AAR：out_key=target，发送 0，回包即 *(target)
primitive.in_key = 0;
primitive.out_key = (uint8_t *)target;
primitive.buf = (uint8_t *)dummy_addr;
primitive.buf_len = 0x20;
```

```c
// kernel base 与 ctor 劫持
kbase = arb_read(cache + 0x78, ...) - 0x10e1560;
uint64_t set_memory_x = kbase + 0x002ba1a0;
arb_write(cache + 0x50, (uint8_t *)&set_memory_x, 8, ...);
open_tcp(p4 + 1);          // 触发一次分配，slab 页变可执行
arb_write(cache + 0x50, (uint8_t *)&slab2_addr, 8, ...);
arb_write(slab2_addr, shellcode, sizeof(shellcode), ...);
open_tcp(p4 + 4);          // SLUB 调用 ctor -> shellcode
```

完整 EXP 见原文（含 sec_conn 伪造、KDF/XOR、模块 .bss 与 kernel 偏移、shellcode 汇编）。PoC 未在本机执行；内核版本/符号偏移需与目标一致。

## 变体与关联

- 变体：hash 冲突可换成任意“表项不唯一/查找不比较完整键”导致的悬垂指针；不限于 netfilter。
- 变体：没有 `kmem_cache->ctor` 时可改 `modprobe_path`、`core_pattern`、函数指针表、`n_tty_ops` 等；ctor 只是本题最稳入口。
- 变体：`set_memory_x` 也可换成 `set_memory_rwx`/`text_poke`；或用 `vmalloc` 可执行内存。
- 关联卡片：[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（kmem_cache UAF 回调劫持）、[[binary-pwn-kernel-sock-refcount-race-lock-sock-double-free]]（网络对象 double free）、[[binary-pwn-kernel-splice-external-page-crc-commit-page-cache-write]]（同系列内核模块利用）。
- 注意：本例为 Hackropole FCSC 2026 netsec 题（Linux 6.18.7 自定义 netfilter 模块）；真实内核模块需具体审计 hash/生命周期/字段布局。

## 检测与防御

- 防御：查找表必须比较完整键（IP+端口+协议），不能只比 hash；删除时清空表项并置空指针；使用引用计数/RCU 保护生命周期。
- 防御：对象释放后毒化/清零；开启 KASAN/KFENCE 检测 UAF；对 netfilter 模块做代码审计与签名。
- 防御：限制 unprivileged 用户创建大量连接/绑定源端口；监控异常端口扫描式连接。
- 检测：KASAN 报 use-after-free；同一 hash bucket 频繁创建/销毁；模块对象被非预期重占；`kmem_cache->ctor` 等只读内核数据被改写（CR0/写保护异常、KASAN/CFI）。
- 响应：卸载模块、重启、检查内核完整性、更新模块、限制网络攻击面。
