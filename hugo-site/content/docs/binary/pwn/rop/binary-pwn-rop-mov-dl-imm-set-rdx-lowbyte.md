---
id: binary-pwn-rop-mov-dl-imm-set-rdx-lowbyte
title: 无 pop rdx 的 ORW 第三参数：用 mov dl, imm; ret 设置 rdx 低字节
type: scenario
domain: binary
path: binary/pwn/rop
technique: mov-dl-imm-rdx-lowbyte-orw
tags:
- pwn
- rop
- orw
- gadget
- rdx
- libc
- seccomp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T22:47:53+08:00'
  notes: '已对照原文核对：libc 2.39 无 pop rdx 时用 0x1a1fab: mov dl,0x65;ret 与 0x1a22b1: mov dl,0x66;ret 设置 read/write 第三参数，rdx 高位需为 0 的前提已注明；gadget 偏移随版本变化'
url: /docs/binary/pwn/rop/binary-pwn-rop-mov-dl-imm-set-rdx-lowbyte/
draft: false
kb_aliases:
- mov dl, 0x65
- 无 pop rdx
- ORW 设置 rdx
- 第三参数 gadget
- glibc 2.39 ORW
---

## 一句话结论

在 seccomp 只允许 open/read/write 的 ORW 场景里，`read`/`write` 的第三个参数（长度）需要 rdx；当 libc 中找不到干净的 `pop rdx; ret` 时，只要当前 rdx 为 0（或高位已知），用 `mov dl, imm; ret` 把 rdx 的低 8 位设成任意小的正数（如 `mov dl, 0x65; ret`）即可满足 ORW，长度具体是多少不重要。

## 原理

- **ORW 的参数需求**：`open(path, flags)` 用 rdi/rsi；`read(fd, buf, size)` 与 `write(fd, buf, size)` 的 size 在 rdx。ROP 链通常用 libc 的 `open`/`read`/`write` 符号，调用前需把 rdx 设为可读长度。
- **现代 libc 缺少 pop rdx**：glibc 2.39 等版本中，ropper/ROPgadget 往往搜不到 `pop rdx; ret`，但存在大量 `mov dl, imm; ret` 片段（示例 `libc+0x1a1fab: mov dl, 0x65; ret`、`libc+0x1a22b1: mov dl, 0x66; ret`）。
- **只需低字节**：`dl` 是 rdx 的最低 8 位。如果调用 `open` 后 rdx 为 0（或高位为 0），`mov dl, 0x65` 得到 rdx=0x65=101，足够读取 flag；`write` 再用一次同样的 gadget。若 rdx 高位非 0，需要先用 `xor edx, edx; ret`/`mov edx, imm` 清零，或换 `mov edx, imm; ret`。
- **为什么可行**：ORW 的 size 只决定“最多读/写多少字节”，101 字节足以覆盖 flag；不需要精确长度，也不需要 rdx 为 0x1000 等大值。对 `read(3, buf, 0x65)` 后 `write(1, buf, 0x65)`，flag 会完整输出（不足 101 字节时按实际读取长度）。
- **边界**：若目标 flag 超过 101 字节，改用 `mov dl, 0xff` 或 `mov edx, imm`；若 rdx 在 open 后不是 0，需先清零；gadget 偏移随 libc 版本变化，需在目标 libc 中重新搜索。

## 触发条件

- 存在栈迁移/ROP 执行能力（如 FSOP + setcontext、栈溢出等）。
- seccomp 或目标环境要求 ORW（不能直接 system）。
- libc 中没有可直接使用的 `pop rdx; ret`，或不想依赖它。
- 调用链中 rdx 在设置前为 0 或高位可控。
- 能定位目标 libc 中的 `mov dl, imm; ret` gadget。

## 利用步骤

1. 用 ROPgadget/ropper 在 libc 中搜索 `mov dl,` 或 `mov edx,` 片段；确认偏移与字节。
2. 构造 ROP：`open("/flag", 0)` → `mov dl, 0x65; ret` → `read(3, buf)`（rdi=3、rsi=buf，rdx 已设为 0x65）→ 再 `mov dl, 0x65; ret` → `write(1, buf)`。
3. 若 `open` 后 rdx 非 0，在 gadget 前插入清零 gadget（`xor edx, edx; ret` 或 `mov edx, 0; ret`）。
4. 发送 ROP 链，读取输出中的 flag。
5. 授权测试只读本地 `/flag` 或测试文件，不修改目标。

## PoC

原文（glibc 2.39，pwntools）：

```python
# 0x00000000001a1fab : mov dl, 0x65 ; ret
mov_dl_0x65_ret = libc.address + 0x00000000001a1fab
buf = fp + 0x150
rop = ROP(libc, fp)
rop.open("/flag", 0)
rop.raw(mov_dl_0x65_ret)
rop.read(3, buf)
rop.raw(mov_dl_0x65_ret)
rop.write(1, buf)
s(rop.chain())
```

对应的汇编语义：

```asm
mov dl, 0x65   ; rdx 低 8 位 = 101，其余位保持不变
ret
```

## 变体与关联

- `mov dl, 0xff; ret` 读更大文件；`mov dx, imm16; ret` 设置 16 位；`mov edx, imm32; ret` 设置完整 32 位（若找得到）。
- 若 rdx 高位非 0：先 `xor edx, edx; ret`，再 `mov dl, imm`；或直接找 `mov edx, imm; ret`。
- 没有 libc 泄露时，可在二进制/固定 libc 中找同类 gadget；不同 libc 版本偏移不同，需重新搜索。
- 关联：[[binary-pwn-heap-nullbyte-stdin-buffer-expand-stdout-fsop]]（本 gadget 所在的 FSOP + setcontext ORW 链）。
- 关联：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（另一条 setcontext ORW 链，rdx 由 bridge gadget 设置）。

## 检测与防御

- 这是利用侧 gadget 技巧，防御重点是阻止 ROP 执行：开启 CET/Shadow Stack/IBT、完整 ASLR、seccomp 白名单、栈保护与 CFI。
- 检测 ROP 链中的 `open`/`read`/`write` 调用序列与异常 `mov dl` gadget 地址；监控进程读取 `/flag` 等敏感文件后立即 write 到 stdout/socket。
- 若业务使用 seccomp，确保沙箱同时限制 openat 的路径/参数（如只允许特定目录），避免 ORW 直接读 flag。
