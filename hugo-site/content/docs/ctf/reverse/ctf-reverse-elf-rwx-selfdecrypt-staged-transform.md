---
id: ctf-reverse-elf-rwx-selfdecrypt-staged-transform
title: ELF 三阶段加密逆向：位交换/加减/XOR + .data 代码块复制到 RWX 页自解密
type: scenario
domain: ctf
path: ctf/reverse
technique: elf-rwx-selfdecrypt-staged-transform
tags:
- ctf
- reverse
- elf
- self-modifying-code
- rwx
- mprotect
- xor
- bit-swap
- obfuscation
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:04:51+08:00'
  notes: 已对照 91111 原文第五题与图 01-03 核对：三阶段（位运算/RWX 自解密/循环 XOR）、key=0x6e72、0x84 字节 .data 代码块与逆映射均一致。PoC 未在本机复跑。
url: /docs/ctf/reverse/ctf-reverse-elf-rwx-selfdecrypt-staged-transform/
draft: false
kb_aliases:
- RWX 自解密代码块
- mprotect 可写可执行
- 三阶段加密逆向
- 位交换 + XOR 6
- 嵌入 2 字节密钥
- info_81bedab
---

## 一句话结论

样本把 0x84 字节变换代码放在 `.data`，运行时 `malloc(0x1000)` + `mprotect(RWX)` 后复制过去，用缓冲区里嵌入的 2 字节 key（0x6e72）循环 XOR 解密再执行；整体加密由“高位字节置 0xFF/否则左移 1 位”“半字节交换 + XOR 0x13 + 加 6”“8 字节固定 key 循环 XOR”三阶段组成，按逆序逐层求逆即可还原明文。

## 原理

- **文件流程**：程序读取 `./info_81bedab.ori`，对每字节依次做 Stage A、B、C，写出 `.ori.en`；逆向时按 C → B → A 逆序。
- **Stage C（循环 XOR）**：`.rodata` 中的 8 字节 key `e6911c24` 与数据按 `i % 8` 循环异或。逆操作是同一 XOR。
- **Stage B（RWX 自解密代码）**：`sub_401276` 内 `malloc(0x1000)`、`mprotect(page, 0x1000, 7)`，从 `.data:0x404060` 复制 0x84 字节代码块到该页；代码块入口先 `call` 到尾部解密 stub，stub 用 `rsi` 指向的 2 字节 key 循环 XOR 0x43 字节被加密代码，然后 `jmp` 执行解密后的变换。key 取自数据缓冲区 `buf+0x339` 的 2 字节（小端 0x6e72）。
- **Stage B 变换**：解密后的代码对每个输入字节执行 `(x-3) & 0xFF`，交换高低 4 位，`^0x13`，`+6`，返回低 8 位。该变换是 256 个字节上的双射，可预先构建逆映射表。
- **Stage A（位运算）**：若最高位为 1 则输出 `0xFF`，否则输出 `b << 1`；逆操作是 `0xFF` 保持 `0xFF`，其余右移 1 位（原始字节的高位在加密时被丢弃，但样例数据满足可逆条件）。
- **key 的约束**：Stage C 逆向后，B 缓冲区 `0x339/0x33A` 为 `0xEB/0xAB`；经 Stage B 逆映射后对应 A 缓冲区 `0x72/0x6E`，即小端 key `0x6E72`，用于确认自解密代码块的 XOR key 正确。
- **可复用点**：静态分析发现 `mprotect(..., 7)` + 从数据段 `memcpy` 代码块 + 循环 XOR stub，就应把“数据段代码块”当作待解密 shellcode/函数，先还原其内容再反编译；不要直接对加密字节做反汇编。

## 触发条件

- 目标是 stripped ELF，导入表出现 `malloc`、`mprotect`、`memcpy` 等，且存在 RWX 页或数据段可执行复制行为。
- 加密流程是逐字节可逆变换（异或、加减、位交换、映射表），没有强 KDF/随机 IV。
- 密钥要么硬编码，要么嵌入在可控缓冲区/数据段中，能从明文约束或已知值反推。

## 利用步骤

1. `file`/`readelf` 确认 64 位 ELF、stripped；在 IDA/Ghidra 中定位 `main` 与核心函数，识别文件读写和 `sub_401276`。
2. 在核心函数中标记 `malloc`、`mprotect(...,7)`、`memcpy` 源地址（0x404060）与长度（0x84），把该代码块 dump 出来。
3. 分析尾部解密 stub：找到 `pop` 得到的代码起始偏移、key 指针（`rsi`）、循环计数与 XOR 逻辑；确认 key 来自 `buf+0x339`。
4. 恢复 key：利用已知明文位置或密文/明文约束求出 2 字节 key；本例为 `0x6E72`。
5. 用 key 循环 XOR 解密 0x43 字节代码块，反汇编得到 Stage B 变换；构建 256 字节逆映射。
6. 对密文先 XOR `e6911c24`（Stage C 逆），再查逆映射（Stage B 逆），最后右移/保留 0xFF（Stage A 逆），拼接并解码文本。
7. 用第 8 行/目标列验证结果，必要时检查尾部填充和编码。

## PoC

```python
STAGE_C_KEY = b'e6911c24'

def stage_b_transform(x):
    x = (x - 3) & 0xFF
    low = x & 0x0F
    high = (x >> 4) & 0x0F
    swapped = (low << 4) | high
    return ((swapped ^ 0x13) + 6) & 0xFF

inv = {stage_b_transform(x): x for x in range(256)}

def decrypt(ciphertext):
    n = len(ciphertext)
    b = bytearray(ciphertext[i] ^ STAGE_C_KEY[i % len(STAGE_C_KEY)] for i in range(n))
    a = bytearray(inv[x] for x in b)
    return bytearray(0xFF if x == 0xFF else x >> 1 for x in a)

plain = decrypt(open('info_81bedab.ori.en', 'rb').read())
open('info_81bedab.ori', 'wb').write(plain)
print(plain.decode('utf-8', errors='ignore').splitlines()[7].split()[1])
```

自解密代码块的关键指令（解密前）：

```text
41 54              push r12
41 53              push r11
e8 45 00 00 00     call +0x45        ; 跳到解密 stub
... 0x43 字节密文 ...
41 5b              pop r11           ; 代码起始
4d 31 e4           xor r12, r12
45 31 c0           xor r8d, r8d
43 0f b6 04 23     movzx eax, [r11+r12]
42 8a 1c 06        mov bl, [rsi+r8]
30 d8              xor al, bl
43 88 04 23        mov [r11+r12], al
...
41 ff e3           jmp r11
```

说明：以上为原文算法的等价 Python 实现；本卡未在本机复跑样本。

## 变体与关联

- **变换变体**：半字节交换、位反转、加减常量、ROL/ROR、S-box/映射表、按索引变化的 XOR key；只要是双射，都可构建逆表。
- **代码块变体**：不一定是 Stage B，可能是 VM handler、解密函数、反调试 stub；关键识别点是 RWX + 从数据段复制 + 运行时 XOR/解密。
- **密钥变体**：key 可能在数据缓冲区、资源段、注册表/配置文件，或由已知明文反推；多字节 key 按索引循环。
- **关联卡片**：[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（自修改 VM）、[[pentest-c2-linux-mmap-rwx-rolling-xor-shellcode-loader]]（mmap RWX + 滚动 XOR 加载器）、[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（运行时解密 dump）、[[ctf-reverse-vm-encryptor-core-context-two-stage-inverse]]（多阶段逆变换）。
- **边界**：若变换不是双射（如 Stage A 的高位丢弃导致多对一），只能恢复满足约束的子集；若 key 由随机数/强 KDF 派生且无泄露，不能直接逆。

## 检测与防御

- **检测**：二进制中出现 `mprotect`/`VirtualProtect` 设为 RWX、随后从 `.data`/资源段 `memcpy` 并调用；静态特征包括短小的 XOR 解密 stub、循环 key 指针、`jmp` 到刚写入的页。
- **分析**：在调试器中于 `mprotect` 返回后、`jmp` 前下断点，dump 解密后的代码页；或用 IDA 脚本模拟 stub 的 XOR 还原代码块。
- **防御（软件保护视角）**：自解密/多阶段变换只能提高逆向成本，不能替代服务端密钥与完整性校验；不要把关键算法和密钥都放在客户端。
- **取证**：保留原始样本与哈希，记录 key 推导过程；对解密后的代码块单独反编译，避免把数据段密文误判为指令。
