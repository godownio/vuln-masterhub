---
id: binary-pwn-heap-stale-slot-create-failure-uaf
title: CREATE 失败路径先写全局槽再 free：稳定 stale slot 制造 UAF 读写
type: scenario
domain: binary
path: binary/pwn/heap
technique: stale-slot-uaf
aliases:
- 失败路径 UAF
- stale slot
- 槽位未清空
- create 失败 UAF
- 悬空槽位
tags:
- pwn
- heap
- uaf
- stale-pointer
- ctf
- glibc
- protobuf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:50:47+08:00'
  notes: 已对照原文及17张图核对：CREATE 伪代码为 calloc→qword_82C0[id]=dest→strncpy/长度校验→失败 free(dest) 不清槽（图04/06 IDA 与原文一致），READ/UPDATE 围绕槽位工作，可形成 UAF 读/写；PoC 的 key_size=0x100+0x120 超长失败序列与原文一致。未验证点：EXP 未本机复跑；卡片为通用模式，未设 affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

CREATE 类接口若按“先分配 → 先写入全局槽位 → 再校验输入 → 校验失败 free 但不清槽位”的顺序实现，攻击者只要构造一个能通过分配、却在校验阶段失败的超长输入，就能稳定留下一个指向已释放堆块的 stale slot；后续 READ/UPDATE 再按该槽位工作，即得到 UAF 读、UAF 写与重复释放能力。

## 原理

- 典型错误顺序：`p = calloc(key_size, 1); value[id] = p;` 然后才检查 `len(secret_key) <= key_size`；失败分支执行 `free(p)`，却没有 `value[id] = NULL`。
- 分配与校验分离后，失败路径释放的对象仍被全局数组引用。全局槽位是“逻辑上的对象”，但堆块已经归还 allocator，形成 dangling pointer。
- READ 通常只检查 `value[id] != NULL`，再按记录的长度把整块内存打包返回，因此可直接读回 free 后写入的 `fd/bk` 等 allocator 元数据，泄露 libc/堆地址。
- UPDATE 若只检查槽位非空与长度上限，就会对已释放块 `memcpy`，形成受长度约束的 UAF 写；DELETE 再次 `free(value[id])` 则可制造 double free 或释放伪造块。
- 该模式不依赖某一具体协议；protobuf-c、JSON、自定义二进制协议只要把“对象创建”与“字段校验”拆成先发布后校验的两步，都可能复现。

## 触发条件

- 服务端存在按 id 索引的全局对象槽位（如 `void *value[16]`），创建流程先登记指针、后校验字段；
- 校验失败分支 `free` 对象但不把槽位置空；
- 有 READ/SHOW 接口按记录长度返回槽位内容，或有 UPDATE/EDIT 接口对槽位写；
- 分配的块大小可控，且失败输入的长度可超过声明的 `key_size`；
- 目标 glibc 的 tcache/unsorted 行为可预测（本例为 glibc 2.35）。

## 利用步骤

1. 正常创建一个对象占住槽位，或先做 tcache 预热固定分配行为。
2. 发送 CREATE 请求：`key_size = 0x100`，`secret_key` 实际长度 `0x120`；程序分配约 `0x110` 的 chunk 并登记到 `value[id]`，随后因 `0x120 > 0x100` 进入失败分支 `free(p)`，槽位仍保留。
3. 立即用另一个 id 申请同尺寸对象，复用刚释放的 chunk，使两个槽位指向同一块内存（一个 stale、一个 live）。
4. 通过 stale 槽位 READ 读回 free 后的内容（`fd/bk`、堆指针），或通过 UPDATE 写入；也可以再用 stale 槽位 free 掉 live 槽位的 chunk，制造 UAF/overlap。
5. 把得到的 UAF 读写接入后续堆利用（如 unsorted bin 泄露、tcache 毒化、largebin attack 等）。

## PoC

最小请求序列（伪代码，`add` 封装 protobuf `Credential{id, key_size, secret_key}`；实际长度由序列化后的 bytes 决定）：

```python
add(0, 'aaa', 0x100, b'a'*0x100)     # 正常占用槽位
free(0)                              # 放回 tcache/bin

add(0, 'aaa', 0x100, b'a'*0x120)     # 失败 CREATE：分配 0x110 后 free，槽位 0 变 dangling
add(3, 'aaa', 0x100, b'a'*0x100)     # 复用同一 chunk，槽位 3 成为 live 拥有者

show(3)                              # 通过 live/stale 重叠读取 allocator 元数据
```

关键伪代码：

```c
void *p = calloc(req->key_size, 1);
value[req->id] = p;                  // 先发布
if (req->value && req->key_size >= req->value_len) {
    memcpy(p, req->value, req->value_len);
    value_len[req->id] = req->key_size;
    return ok;
}
free(p);                             // 失败：释放但不清 value[req->id]
return error;
```

## 变体与关联

- 变体：先校验长度再分配、但分配失败时仍保留旧槽位；或 DELETE 释放后不清槽位——同样形成 stale 引用。
- 变体：槽位保存的是对象指针而长度单独保存，导致释放后 READ 仍按旧长度输出，泄露范围更大。
- 关联：unsorted bin 泄露 libc（利用本卡的 UAF 读）；tcache 毒化；largebin attack；double free。
- 利用延伸：本卡只覆盖“制造 stale slot”；从 UAF 到 getshell 的完整链见关联的 largebin/_IO_list_all 卡片。

## 检测与防御

- 防御：创建流程改成事务式——先完成全部校验，再分配并发布槽位；失败分支统一执行 `value[id] = NULL; value_len[id] = 0;`。
- 防御：删除接口释放后立即清空槽位与长度；使用带所有权语义的容器/句柄，避免裸指针数组。
- 检测：审计所有 `alloc → 全局登记 → validate → free` 的顺序；对同一 id 的连续失败创建后紧跟 READ/UPDATE 的请求序列告警。
- 检测：开启 ASan/Valgrind 或 glibc 的堆检查，观察 free 后仍被读写的对象；对重复 free 与异常 bin 状态做监控。
