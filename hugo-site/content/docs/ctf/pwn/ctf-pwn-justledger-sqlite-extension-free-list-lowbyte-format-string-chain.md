---
id: ctf-pwn-justledger-sqlite-extension-free-list-lowbyte-format-string-chain
title: justledger 多级链：SQLite 扩展自定义 free-list 任意写 + 低字节长度校验绕过 + 格式化字符串密文参数泄露
type: scenario
domain: ctf
path: ctf/pwn
technique: sqlite-extension-free-list-arbitrary-write-lowbyte-check-format-string-chain
tags:
- pwn
- ctf
- sqlite
- extension
- free-list
- arbitrary-write
- function-pointer
- format-string
- low-byte-check
- stack-overflow
- rop
- multi-stage
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:55:58+08:00'
  notes: 已对照原文核对；ledgerprobe free-list 任意写、0x5110 函数指针、window 低字节越界、vault 0x91/0xa7 ROP 链一致；PoC 为结构重写
url: /docs/ctf/pwn/ctf-pwn-justledger-sqlite-extension-free-list-lowbyte-format-string-chain/
draft: false
kb_aliases:
- justledger
- SQLite 扩展 pwn
- ledgerprobe.so
- 自定义 free-list 任意写
- ledger_fire 函数指针
- window 低字节校验
- 0x91 格式化字符串
- 0xa7 栈溢出
- 多级 UID 隔离
---

## 一句话结论

justledger 用三层隔离服务把 flag 藏在 vault：先用 SQLite 扩展 `ledgerprobe.so` 的自定义 free-list 把 `next` 指针改成任意地址，两次 `ledger_make` 得到 0x60 字节任意写，覆盖 `ledger_fire` 函数指针跳到扩展内闲置的 poll 转发函数；再用 broker 的 window `off+len` 只比较低字节的漏洞越界读写、泄露 secret 并伪造 ROUTE3 函数指针跳到转发函数；最后用 vault 的 `0x91` 格式化字符串泄露经 secret 混淆的 8 个 vararg（含 flag fd、canary、PIE、libc），用 `0xa7` 的 `len & 0xff <= 0x80` 低字节检查绕过喂入 0x200 字节栈溢出，ROP 读 flag fd。

## 原理

- **三层隔离**：`justledger`（SQLite + `ledgerprobe.so`）→ `ledgerbroker` → `ledgervault` → `/home/ctf/flag`；三层都不能直接读写 flag，必须利用每层“未使用”的转发函数作为跳板，逐层建立字节流隧道。
- **SQLite 扩展 arming**：`ledger_seed()` 返回 `ledger.lease` 类型 pointer value；虚拟表 `ledger(x, seal HIDDEN)` 的 xFilter 把 RHS 的 `sqlite3_value*` 记录到全局，并用扩展随机 secret 做异或；xClose 置位；`ledger_bind()` 校验 lease 后才把扩展置为 armed，之后 `ledger_make/mark/drop/audit/touch/fire` 才可用。
- **ROUT 对象泄露**：`ledger_make(idx,type,blob)` 创建 0x2d8 对象，前 0x60 字节来自 blob；type=1 的 ROUT 在 `+0x20` 放 `ext_base+0x1260`、`+0x28` 放自身地址、`+0x30` 放 `(ext_base+0x1260) ^ secret2 ^ ror(obj,12)`。`ledger_audit()` 返回 `obj+0x20` 的 32 字节，一次拿到 ext_base、obj、secret2。
- **自定义 free-list 任意写**：`ledger_drop(idx)` 把对象压入释放链表：`[obj] = (obj>>12) ^ old_head; head=obj; count++`；`ledger_make` 弹出时 `head=[0x5408]; next=(head>>12)^[head]; [0x5408]=next; count--; zero(head..head+0x2d8); copy 0x60 blob -> head`。`ledger_touch(blob8)` 可写当前对象首 8 字节。于是：先 drop(1)、drop(0) 让 head 为已知 obj0；mark(0)；`touch((obj0>>12) ^ target)` 改写 obj0 的 next；两次 `ledger_make`：第一次弹出 obj0 并把 head 设为 target，第二次弹出 target，先清零 `target+8..target+0x2d8`，再把 0x60 字节 blob 复制到 target，得到 0x60 字节任意写。
- **覆盖 ledger_fire 指针**：`ledger_fire` 校验 `rax=[0x5110]^[0x53f0]^0x91e10da5c79b43f2`、`rol(rax,23)==[0x5118]`，然后 `jmp [0x5110]`。用任意写把 `0x5110` 改成扩展内闲置的 poll 转发函数 `ext_base+0x1c10`，校验值 `check=rol(secret2 ^ proxy ^ 0x91e10da5c79b43f2,23)` 一并写入；执行 `ledger_fire()` 后 TCP 连接变成裸字节流，可以开始说 broker 协议。
- **写目标的选择**：不要写 `0x5020` 的 module struct——`ledger_make` 复制前会清零 `target+8..target+0x2d8`，若 target=0x5020 会覆盖 `0x5100` 的 `sqlite3_api` 指针，下一次调用 API 时崩溃；写 `0x5110` 的清零范围从 `0x5118` 开始，刚好不碰 `0x5100`。
- **broker window 低字节校验**：WINDOW3 是 `calloc(0x200)`，读写目标 `dest=window+off+0x40`；检查为 `off+len <= 0x70`，但汇编只比较 `(off+len)` 的低字节（`cmp r9b,0x70`），`off=0x100,len=0x400` 时低字节为 0，越界读通过；`off=0x100,len=0x100` 时低字节为 0，越界写通过。堆布局稳定为 window W、route W+0x210、slice W+0x420，读起点 `W+0x140`，route tag 在数据偏移 0xd0、slice tag 在 0x2e0。
- **泄露 broker secret 与伪造 ROUTE3**：SLICE3 创建时 `[slice+0x10]=(slice+0x80)^rol(S,9)`、`[slice+0x20]=slice`，反推 `S=ror(q0 ^ (q1+0x80),9)`；ROUTE3 创建时 `E=rol((broker_base+0x1770)^S^route,29)`，反推 broker_base。把 E 改成 `rol((broker_base+0x2120)^S^route,29)`、digest 重算，window 越界写打补丁，发 `0x7e` 即跳到 broker 的 poll 转发函数，TCP 流接到 vault。
- **vault 格式化字符串**：`0x91` 读入格式化字符串，经过滤后调 `__dprintf_chk(1,1,fmt,...)`；8 个 vararg 全部用 secret 混淆：`(base+0x1ac0)^S`、`rol(S,13)^read_addr`、`flag_fd^ror(S,9)`、`rol(S,31)^canary`、`S^0x58df37a91c62e40b`、`arg1^arg2`、`arg3^arg4`、常量。发 `"AAAA" + ".%p"*8` 即可恢复 S、flag_fd、canary、base、libc。
- **vault 栈溢出**：`0xa7` 把输入读到 `rbp-0x120`；长度检查 `len & 0xff <= 0x80` 且 `len <= 0x400`，`0x200` 通过（低字节 0）。布局：canary 在 buffer+0x108、saved rbx +0x118、saved rbp +0x120、ROP +0x128；canary 已泄露，ROP 用 `pop rdi/rsi/rdx` 调 `read(flag_fd, buf, 0x200)` 再 `write(1, buf, 0x200)`，flag 沿 broker→justledger→TCP 原路返回。

## 触发条件

- 目标为多级 UID/进程隔离的 PWN 题或服务：SQLite 扩展 + broker + vault，每层只与下一层通信，只有最后一层持有 flag fd。
- 扩展提供对象创建/释放/审计/写接口，释放链表用“地址右移 12 异或”编码且用户可控 next；存在可覆盖的函数指针。
- broker 的 window/偏移长度检查只比较低字节，允许越界读写；堆布局稳定可预测。
- vault 存在格式化字符串（参数被 secret 混淆）与长度检查只比较低字节的栈溢出；能泄露 canary/PIE/libc/flag fd。

## 利用步骤

1. 完成 SQLite 扩展 arming：`SELECT * FROM ledger WHERE seal=ledger_seed(); SELECT ledger_bind(ledger_seed(),0);`。
2. 创建 ROUT 对象并 `ledger_audit()`，泄露 `ext_base`、`obj0`、`secret2`。
3. 按 `drop(1)→drop(0)→mark(0)→touch((obj0>>12)^target)` 布置释放链表 next，两次 `ledger_make` 把 0x60 字节写到 `0x5110`：填入 `ext_base+0x1c10` 与重算的校验值。
4. `SELECT ledger_fire();` 跳到 poll 转发函数，连接切换到 broker 协议。
5. broker：创建 window/route/slice，用 `off=0x100,len=0x400` 越界读泄露 route/slice tag，反推 secret S 与 broker_base；用 `off=0x100,len=0x100` 越界写把 route 的 E/digest 改成 `broker_base+0x2120` 的编码；发 `0x7e` 跳到 poll 转发函数，连接切换到 vault 协议。
6. vault：发 `0x91` + `"AAAA" + ".%p"*8`，恢复 secret、flag_fd、canary、PIE、libc；发 `0xa7` + `0x200` 字节 ROP（canary 用泄露值），执行 `read(flag_fd, buf, 0x200)` + `write(1, buf, 0x200)`。
7. 从返回字节中匹配 `DASCTF{...}`/`flag{...}`。

## PoC

关键原语（按原文结构重写，偏移为原题示例，未在本库复跑）：

```python
# 1) 扩展 arbitrary write：改写 obj0 的 next 到 target
drop(1); drop(0); mark(0)
touch(p64((obj0 >> 12) ^ target))
make(0, 2, b"")          # 弹出 obj0，head = target
make(1, 2, blob60)       # 弹出 target，清零后复制 0x60 字节

# 2) 覆盖 ledger_fire 指针
proxy = ext_base + 0x1c10
check = rol(secret2 ^ proxy ^ 0x91e10da5c79b43f2, 23)
arb_write(0x5110, p64(proxy) + p64(check))

# 3) broker window 越界读/写
read_win(off=0x100, len=0x400)    # off+len 低字节 = 0，绕过 <=0x70
write_win(off=0x100, len=0x100)   # 打补丁 route 的 E/digest

# 4) vault 格式化字符串 + 栈溢出
send(0x91, b"AAAA" + b".%p" * 8)
send(0xa7, b"A" * 0x108 + p64(canary) + b"B" * 0x10 + rop_read_flag)
```

原文实测 `ledger_audit` 泄露 `ext base/obj0/secret2`，broker 泄露 `base/secret/route`，vault 格式化泄露 `secret/fd/canary/base/libc`，最终读取 flag；未在本库复跑。

## 变体与关联

- **free-list 变体**：`next = (obj>>12) ^ old_head` 是 safe-linking 风格的自定义链表；只要能改写 next，就能把任意地址变成“下一个对象”，再借 `make` 的清零+复制得到任意写。
- **低字节校验变体**：`off+len <= 0x70` 只比较低字节、`len & 0xff <= 0x80` 只比较低字节；同类还有 `cmp al`、`test r9b`、`(u8)(a+b)` 等，都是“完整长度校验被截断”的漏洞模式。
- **格式化字符串变体**：参数被 secret 异或/旋转混淆时，仍可通过 `%p` 一次性泄露多个值，再线性反推；注意参数顺序与 `__dprintf_chk` 的调用约定。
- **关联卡片**：[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 函数指针劫持）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 编码）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化字符串泄露 canary/libc + ROP）。

## 检测与防御

- **长度/偏移校验**：所有 `off+len`、`len`、索引检查必须使用完整位宽，并同时检查上界与下界；不要用 `cmp r9b`/`& 0xff` 截断。
- **对象池**：释放链表应校验 next 是否落在对象池内；不要用用户可控的 next 直接当对象指针；复制前校验目标范围，避免清零破坏相邻全局/函数表。
- **函数指针**：可写 .bss 中的函数指针应加完整性保护（只读表、指针认证、随机 cookie）；转发函数不应作为可被覆盖的跳板。
- **格式化字符串**：不要把用户输入直接当 format；固定格式或使用 `%s` 参数；敏感参数不要只靠可逆混淆。
- **隔离**：每层服务使用独立 UID/命名空间；flag 只对最后一级可读；禁止通过 `/proc/<pid>/root`、`/proc/<pid>/mem` 横向访问。
- **检测**：SQLite 扩展出现异常对象释放/复用、broker 出现 `off+len` 低字节绕过的越界访问、vault 出现 `%p` 链式格式化与异常 ROP 栈迁移。
