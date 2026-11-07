---
id: ctf-reverse-embedded-shellcode-builds-aes256-key-cbc-decrypt
title: 逆向嵌入 shellcode 生成 AES-256 密钥：从 .rodata 机器码提取 32 字节 key 并用 AES-CBC 解密
type: scenario
domain: ctf
path: ctf/reverse
technique: embedded-shellcode-builds-aes256-key-cbc-decrypt
tags:
- ctf
- reverse
- shellcode
- aes
- aes-256-cbc
- key-recovery
- rodata
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:24+08:00'
  notes: 已对照原文核对：.rodata 嵌入 shellcode 构造 32 字节 AES-256 key（th1_1s_th3_valu3_0f_k3y+9 NUL）、strncpy IV='1337'+12 NUL、AES-CBC 解 flag.enc，与原文 IDA/exp 一致。未验证点：未本机复跑样本；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-embedded-shellcode-builds-aes256-key-cbc-decrypt/
draft: false
kb_aliases:
- Baby_Reverse_Revenge
- call_embedded_shellcode
- 嵌入 shellcode 生成密钥
- AES-256-CBC 解密 flag.enc
- .rodata shellcode 分析
- th1_1s_th3_valu3_0f_k3y
---

## 一句话结论

加密程序用 `call_embedded_shellcode(keybuf, 32)` 执行嵌在 `.rodata` 的机器码来生成 AES-256 密钥，随后用 `strncpy(iv, "1337", 0x10)` 构造 IV 并 AES-CBC 加密 flag；逆向这段 shellcode 的逐字节写入（`mov` 立即数/`stosb` 序列）即可还原 32 字节 key（示例为 `th1_1s_th3_valu3_0f_k3y` + 9 个 NUL），再用同 IV 解密 `flag.enc`。

## 原理

- **密钥不在数据段明文**：程序把密钥生成逻辑放进一段可执行机器码（`.rodata` 中的 `shellcode` 数组），由 `call_embedded_shellcode` 调用；静态字符串搜索找不到完整 key，只有分析机器码或仿真执行才能得到 32 字节缓冲区内容。
- **shellcode 直接构造缓冲区**：常见形态是 `mov byte ptr [reg+offset], imm8`、`mov al, imm8; stosb` 或成对的 `mov` 写 32 字节；把各条写指令的立即数按目标偏移排序，即可拼出 key。示例的立即数依次对应 `t h 1 _ 1 s _ t h 3 _ v a l u 3 _ 0 f _ k 3 y`，剩余 9 字节为 0。
- **IV 与模式**：`strncpy(dest, "1337", 0x10)` 把 `"1337"` 写入 16 字节缓冲区，未覆盖部分由 `memset`/零初始化，因此 IV = `"1337" + 12 个 \0`；`encrypt_file` 使用 AES-256-CBC（32 字节 key、16 字节 IV），PKCS#7 填充。
- **验证**：用还原的 key/IV 解 `flag.enc`，明文应为可读 flag；若出现乱码，检查 key 顺序（立即数偏移是否按小端/大端）、IV 是否被后续 `memset` 清零、是否漏掉 `\0` 补位。
- **为什么成立**：嵌入 shellcode 只是把密钥构造从 C 代码搬到机器码，机器码中的立即数仍是静态可读的；即使有简单的异或/加法混淆，也可在仿真器（Unicorn/Speakeasy）中执行后读缓冲区，而不必真正运行恶意代码。

## 触发条件

- 逆向题/样本在 `.rodata`/`.data` 中有可执行 shellcode，并由函数指针/`call_embedded_shellcode` 调用。
- 该 shellcode 的输出缓冲区被用作对称加密密钥（AES-128/256、CBC/CTR 等），密钥长度固定（示例 32 字节）。
- 加密文件/密文与 IV/nonce 可获取；IV 由固定字符串或简单派生构造。
- 能静态反汇编 shellcode（IDA/x64dbg/Capstone）或在隔离环境用 Unicorn/Speakeasy 仿真。

## 利用步骤

1. 在 IDA 中定位 `main`：`call_embedded_shellcode(v6, 32)`、`strncpy(dest, "1337", 0x10)`、`encrypt_file("flag.txt", "flag.enc", v6, dest)`，确认 key 长度 32、IV 16 字节、AES-CBC。
2. 找到 `shellcode` 数组（例如 `.rodata` 偏移 0x2020 起），用 IDA 的“强制转换为代码”或 Capstone 反汇编，识别写缓冲区的指令与偏移。
3. 按偏移收集立即数：`mov byte ptr [rbx+0], 0x74` → `'t'`，`+1` → `'h'`……直到 32 字节；缺失的尾部按 `memset(v6, 0, 32)` 补 `\0`。
4. 构造 IV：`"1337"` + 12 个 `\0`；若程序先 `memset(dest,0,16)` 再 `strncpy`，确认未被覆盖的字节为 0。
5. 用 Python `Crypto.Cipher.AES` 以 `MODE_CBC` 解 `flag.enc`，去除 PKCS#7 填充，检查 flag 前缀。
6. 若静态分析困难，用 Unicorn 映射 shellcode 所在段、设置 `rbx`/`rdi` 指向 32 字节缓冲区并单步执行，执行后 dump 缓冲区。

## PoC

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 从 shellcode 的 mov 立即数按偏移还原
key = b"th1_1s_th3_valu3_0f_k3y" + b"\x00" * 9
iv  = b"1337" + b"\x00" * 12

ct = open("flag.enc", "rb").read()
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print(unpad(pt, 16).decode())
```

```text
# 静态提取思路（Capstone 伪代码）：
# for insn in md.disasm(shellcode, base):
#     if insn.mnemonic == "mov" and "byte ptr" in insn.op_str and ", 0x" in insn.op_str:
#         off = 解析 [reg+off]；imm = 解析第二个操作数
#         key[off] = imm & 0xFF
```

## 变体与关联

- 变体：shellcode 先用 XOR/ADD 混淆立即数再写入；需按同样运算还原（或在 Unicorn 中执行后 dump）。
- 变体：key 通过 `VirtualAlloc` + `memcpy` + 解密循环生成；可用 Speakeasy 仿真并 hook `memcpy`/加密 API 读取缓冲区。
- 变体：AES-CTR/ChaCha20 使用 nonce 而非 IV；按程序参数替换 `MODE_CTR(nonce=...)`。
- 关联：[[ctf-reverse-elf-rwx-selfdecrypt-staged-transform]]（运行时解密/自修改代码）、[[ctf-reverse-godot4-gdextension-rc4-hotpatch-shellcode]]（嵌入 shellcode 与密钥处理）、[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]（AES 密钥调度逆向）。
- 边界：若 shellcode 从外部输入/环境派生密钥（时间、机器名、反调试结果），静态立即数不完整，需要动态仿真或补环境；若加密使用 AEAD，还需校验 tag。

## 检测与防御

- 检测（CTF）：`.rodata` 中出现可执行字节序列、`call` 到数据段、`mov byte ptr [reg+off], imm` 密集写入、AES-CBC 常量（S-box）与 `flag.enc` 文件引用。
- 修复（软件保护）：不要把密钥以立即数形式放入可执行段；使用白盒密码/KDF + 设备绑定，或把密钥放在服务端。
- 加固：对 shellcode 做加密/多态变形并校验完整性；敏感密钥使用 OS 密钥库/TPM 保护，避免静态提取。
