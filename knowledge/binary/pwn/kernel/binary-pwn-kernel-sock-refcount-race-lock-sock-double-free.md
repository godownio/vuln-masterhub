---
id: binary-pwn-kernel-sock-refcount-race-lock-sock-double-free
title: sock UAF 的 refcount 竞态：利用 lock_sock 双层锁阻塞把 1→2→1 制造 double free
type: scenario
domain: binary
path: binary/pwn/kernel
technique: sock-refcount-race-lock-sock-double-free
aliases:
- sock_hold/sock_put 竞态
- lock_sock 双层锁
- sk_lock.slock 忙等
- sk_lock.wq 等待队列
- refcount 1→2→1
- 内核 sock double free
- sock UAF 转 double free
tags:
- kernel
- pwn
- linux
- uaf
- refcount
- double-free
- race
- lock-sock
- sock
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T20:09:30+08:00'
  notes: 已对照原文与17张图核对：tipc_nl_sk_walk 的 hold→walk_stop→lock_sock→...→release_sock→walk_start→sock_put 顺序、lock_sock_nested 两层锁（自旋锁忙等/等待队列睡眠）、sk_lock.wq 偏移0x148、sk_prot/sk_wmem_alloc/sk_destruct 约束、GDB 1→2→1 改写与 __sk_destruct 断点（图14-17）均与卡片一致；卡片明确用户态完整 PoC 未给出、原文只做到控制流劫持。未验证点：未复现竞态；frontmatter 无 sources/source_url。
---

## 一句话结论

当内核在一条 sock UAF 路径上按 `sock_hold()` → `lock_sock()` → … → `release_sock()` → `sock_put()` 的顺序操作一个已被释放、可被攻击者回收改写的 `struct sock` 时，可以利用 `lock_sock` 的两层阻塞点把线程卡在引用计数递增之后、递减之前，趁机把 `refcnt` 从 2 改回 1，线程恢复后 `sock_put()` 把计数减到 0 并释放该对象，从而把 UAF 升级为可控的 double free（或对伪造对象的释放），再接到 `sk_free()` → `sk_destruct()` 的回调劫持。

## 原理

- `sock_hold()` 本质是 `refcount_inc(&sk->sk_refcnt)`；`sock_put()` 是 `refcount_dec_and_test(&sk->sk_refcnt)`，减到 0 时调用 `sk_free()`。如果对象已经处于 UAF 状态、内存被攻击者复位/伪造，这个引用计数就不再反映真实生命周期，可以被当成可利用的状态变量。
- 以 TIPC 的 `tipc_nl_sk_walk()` 为例，代码在取到 `tsk` 后执行：
  ```c
  sock_hold(&tsk->sk);          // refcnt +1
  rhashtable_walk_stop(iter);
  lock_sock(&tsk->sk);          // 可阻塞点
  err = skb_handler(skb, cb, tsk);
  ...
  release_sock(&tsk->sk);
  rhashtable_walk_start(iter);
  sock_put(&tsk->sk);           // refcnt -1，减到 0 即释放
  ```
  `lock_sock()` 位于 hold 与 put 之间，且可能长时间阻塞，是竞态窗口。
- `lock_sock_nested()` 里实际有两层锁：
  ```c
  mutex_acquire(&sk->sk_lock.dep_map, subclass, 0, _RET_IP_);
  might_sleep();
  spin_lock_bh(&sk->sk_lock.slock);          // 第一层：自旋锁
  if (sock_owned_by_user_nocheck(sk))
      __lock_sock(sk);                       // 第二层：等待队列睡眠
  sk->sk_lock.owned = 1;
  spin_unlock_bh(&sk->sk_lock.slock);
  ```
  - 第一层 `sk_lock.slock` 是自旋锁：如果 `locked=1`，线程会在 `spin_lock_bh` 上忙等（不睡眠），适合做“短暂改内存后放行”的竞态。
  - 第二层 `sk_lock.owned` 让 `__lock_sock()` 把当前线程挂到 `sk_lock.wq` 等待队列并让出 CPU；如果攻击者不 `wake_up`，线程基本不会再往下走，适合把临时修改变成永久修改。
- 利用序列（原文在 GDB 中模拟）：
  1. fake sock 的 `skc_refcnt = 1`，`sk_lock.slock` 的 `locked = 1`；dump 线程执行 `sock_hold()` 后 `refcnt = 2`，随后在 `lock_sock` 的锁上阻塞。
  2. 阻塞期间把 `refcnt` 改回 1，把 `locked` 清 0（必要时清 `pending`/唤醒）。
  3. 线程继续 `release_sock()`、`sock_put()`，`refcount_dec_and_test()` 看到 1 并减到 0，调用 `sk_free()` → `__sk_free()` → `sk_destruct()` → `__sk_destruct()`；若 `sk->sk_destruct` 被伪造，内核会执行它，形成控制流劫持；若目标是内存管理，则得到一次对攻击者选定对象的释放（double free）。
- 要让 `release_sock()` 不崩溃，fake sock 必须满足若干约束：`sk->sk_lock.wq` 要自指（默认指向自身，否则 `waitqueue_active()`/`wake_up()` 解引用空指针）、`sk->sk_prot` 要指向合法 `proto`（否则 `sk->sk_prot->release_cb` 空指针解引用）、`sk_wmem_alloc` 的引用计数也要为 1（`sk_free()` 用 `refcount_dec_and_test(&sk->sk_wmem_alloc)` 决定是否调用 `__sk_free()`），且 `sk_destruct` 位于可控区域之后，需一并伪造。
- `msg_msg` 的 0x30 字节头不可控，且 `sk_prot`（偏移 0x28）、`sk_wmem_alloc`、`sk_destruct` 等字段与可控区域的关系会限制“只喷一小段”的方案；原文因此改用 skb 数据或 NPerm 在 `.init` 段布置完整 fake sock。
- 这是一个通用的 sock UAF 升级手法：只要漏洞路径对已释放/可伪造的 sock 做 hold→lock→put，并且攻击者能在阻塞窗口内改内存，就可能复用。原文用 CVE-2026-64563 的 TIPC 路径验证，但机制本身不绑定该 CVE。

## 触发条件

- 存在一个 sock UAF 或可伪造 `struct sock` 的路径，且该路径在 `sock_hold()` 与 `sock_put()` 之间调用可阻塞的 `lock_sock()`。
- 攻击者能回收并改写已释放的对象（同 cache 复用、跨 cache 堆喷、NPerm 等），并能控制 `skc_refcnt`、`sk_lock.slock.locked` 等字段。
- 需要按目标内核版本确认 `struct sock` 字段偏移：`sk_lock.slock`、`skc_refcnt`、`sk_wmem_alloc`、`sk_lock.wq`、`sk_prot`、`sk_destruct` 等（示例中 `sk_lock.wq` 约在 0x148～0x158，`sk_destruct` 约在 0x2d0，均需用 pahole/GDB 现场核对）。
- 需要让 dump/操作线程在 `lock_sock` 处真正阻塞（第一层自旋锁被别人持有，或 `owned=1` 触发等待队列）；单核/无抢占环境下自旋锁忙等可能把 CPU 占满，需结合环境调整。
- `release_sock()` 的 `sk_backlog.tail`、`sk_prot->release_cb`、`sk_lock.wq` 等字段必须合法，否则在到达 `sock_put()` 前就崩溃。

## 利用步骤

1. 在漏洞路径上确认对象是 `struct sock`（或首字段为 `struct sock` 的对象），记录 `sock_hold()`、`lock_sock()`、`sock_put()` 的位置与调用顺序。
2. 用 GDB 在 `lock_sock` 前后下断点，确认该对象在 hold 后 refcnt 的值、锁字段状态与可阻塞时间窗口。
3. 回收已释放的 sock 对象，写入 fake sock：
   - `skc_refcnt = 1`
   - `sk_lock.slock.rlock.raw_lock.locked = 1`（制造第一层阻塞）
   - `sk_wmem_alloc = 1`
   - `sk_lock.wq` 的 `next`/`prev` 指向自身（`&sk->sk_lock.wq`）
   - `sk_prot` 指向目标内核中合法的 `proto`（其 `release_cb` 为 NULL）
   - `sk_destruct` 写入 gadget/ROP 目标
4. 触发漏洞路径，让内核执行 `sock_hold()`；观察 refcnt 变为 2，线程在 `lock_sock` 阻塞。
5. 在阻塞窗口内把 refcnt 改回 1，并把 `locked` 清 0（第二层方案还要 `wake_up` 或直接改等待队列状态）；放行线程。
6. 线程执行 `sock_put()`，refcnt 减到 0，`sk_free()`/`__sk_free()`/`sk_destruct()` 被调用；在 `__sk_destruct()` 断点确认 `sk->sk_destruct(sk)` 跳到了控制的目标。
7. 之后可接 ROP（`commit_creds(prepare_kernel_cred(...))`）或 data-only 路线；原文只做到控制流劫持，未给出完整 root 链。

原文 GDB 模拟的关键内存布局（地址为示例，需按目标内核重算）：

```gdb
memset 0xffffffff836c2000 0 0x400
set ((struct sock *)0xffffffff836c2000)->sk_lock.slock.rlock.raw_lock.locked=1
set ((struct sock *)0xffffffff836c2000)->__sk_common.skc_refcnt.refs.counter=1
set ((struct sock *)0xffffffff836c2000)->sk_wmem_alloc=1
set {long}0xffffffff836c2158=0xffffffff836c2150   # sk->lock.wq.prev 指向自身
set {long}0xffffffff836c2150=0xffffffff836c2150   # sk->lock.wq.next 指向自身
set {long}0xffffffff836c2028=0xffffffff8360bda0   # sk->sk_prot = tipc_proto
set {long}0xffffffff836c22d0=0xffffffff810e9f20   # sk->sk_destruct = gadget
# 继续到 sock_hold 之后、lock_sock 忙等时：
set ((struct sock *)0xffffffff836c2000)->__sk_common.skc_refcnt.refs.counter=1
set ((struct sock *)0xffffffff836c2000)->sk_lock.slock.rlock.raw_lock.locked=0
set ((struct sock *)0xffffffff836c2000)->sk_lock.slock.rlock.raw_lock.pending=0
b __sk_destruct
```

## PoC

无独立用户态 PoC。原文用上面的 GDB 脚本配合 CVE-2026-64563 的 TIPC dump 触发程序模拟 fake sock 与两次内存改写，验证线程在 `lock_sock` 阻塞后继续执行到 `__sk_destruct`；实际利用需要先完成对象回收和 fake sock 布置（`msg_msg`/skb/NPerm），该部分原文只给出思路与简化代码。可参考主卡 `binary-pwn-kernel-cve-2026-64563-rhashtable-stale-iter-p-tipc-uaf-lpe` 的最小 UAF 触发程序。

## 变体与关联

- **第一层 vs 第二层阻塞**：`sk_lock.slock` 自旋锁忙等时线程仍占 CPU，适合短窗口改内存；`sk_lock.owned` 等待队列睡眠时线程让出 CPU，修改可以保持更久，但需要处理 `wake_up`/等待队列状态。
- **其他 sock 路径**：任何在 hold 与 put 之间 `lock_sock` 的内核路径都可尝试，例如带 `sock_hold()` 的 netlink dump、协议 walker、workqueue 回调；不限于 TIPC。
- **对象回收方式**：同 cache 直接复用（最稳定）、`msg_msg`/skb 跨 cache 堆喷、NPerm 复用 `.init` 段；不同方式对 `sk_prot`/`sk_lock.wq` 等不可控字段的覆盖能力不同。
- **后续利用**：控制流劫持可接 `sk_destruct` gadget、`commit_creds` ROP、`modprobe_path`/`core_pattern` 覆写；也可走 data-only，把这次可控释放变成任意对象释放/重叠。
- **关联卡片**：[[binary-pwn-kernel-cve-2026-64563-rhashtable-stale-iter-p-tipc-uaf-lpe]]（该手法的原始 TIPC UAF 场景）、[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（内核 UAF 回调劫持）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（用户态 UAF 回调改写，可对照思路）。
- **边界**：若漏洞路径在 hold 之前就崩溃、对象回收后无法控制关键字段、或内核开启 `init_on_free`/强隔离导致 fake sock 布置失败，则竞态无法成立；若 `refcount_t` 检测到 addition-on-0 之前就 panic，也拿不到窗口。

## 检测与防御

- **修复根因**：优先修复 sock UAF（引用计数、生命周期与释放路径），不要只依赖堆布局。
- **内核加固**：开启 `CONFIG_REFCOUNT_FULL`/`refcount_t` 检查、KASAN、`CONFIG_DEBUG_LIST`、`init_on_free=1`、`CONFIG_SLAB_FREELIST_HARDENED/RANDOM`，使 double free/UAF 更容易被检测、fake sock 更难布置。
- **检测**：`dmesg` 中 `refcount_t: addition on 0; use-after-free`、`refcount_t: underflow`、`slab-use-after-free`、`__sk_destruct` 附近异常调用栈；高频 `sock_hold`/`sock_put` 与 fd 创建/关闭的异常模式可作为辅助信号。
- **监控**：对非 root 进程访问 TIPC/其他协议 netlink dump、异常 socket 创建/关闭风暴做审计；生产环境禁用不需要的协议族与内核调试接口。
