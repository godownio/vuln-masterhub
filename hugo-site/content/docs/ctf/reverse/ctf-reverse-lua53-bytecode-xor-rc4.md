---
id: ctf-reverse-lua53-bytecode-xor-rc4
title: Lua 5.3 字节码逆向：循环异或解密 + unluac + RC4/XOR 逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: lua53-bytecode-xor-rc4
tags:
- ctf
- reverse
- lua
- bytecode
- rc4
- xor
- unluac
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:13:44+08:00'
  notes: 已对照原文核对：文件偏移 0x31A00、长度 0x3DC、"hulua" 循环异或、Lua 5.3 字节码、key xmctf2026、目标密文、RC4 后逐字节 XOR 0x66、flag xmctf{lu4t1c_r3v3rs3_ch4ll3ng3!} 均一致。未验证点：PoC 未本机复跑（无附件）；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-lua53-bytecode-xor-rc4/
draft: false
kb_aliases:
- Lua 字节码
- luac
- unluac
- hulua
- Lua VM 逆向
- RC4 + XOR
---

## 一句话结论

程序把一段 Lua 5.3 字节码加密后嵌在二进制里，启动时用 `"hulua"[i%5]` 循环异或解密，再交给 Lua VM 执行；dump 出解密后的 `.luac`、用 `unluac`/`luac -l` 反汇编，可看到 key `xmctf2026`、目标密文与 RC4 + 单字节 XOR `0x66` 的校验逻辑，逆推即得 flag。

## 原理

- 主程序创建 `lua_State`，把用户输入设为全局 `user_input`，再用 `luaL_loadbuffer` 加载内存中的字节码；字节码在加载前由 `sub_1400014A4` 逐字节异或 `"hulua"[i % 5]` 解密。
- 加密块位于文件偏移 `0x31A00`、长度 `0x3DC`；解密后是标准 Lua 5.3 字节码（`\x1bLua` 头）。
- 用 `unluac` 或 `luac -l -l` 反汇编，可看到常量：`"78 6D 63 74 66 32 30 32 36"`（hex→ASCII `xmctf2026`）、目标密文、常量 `102`（`0x66`），以及两个子函数（hex→bytes、RC4 风格流加密）。
- 校验流程：`user_input` 先异或 `0x66`，再用 key `xmctf2026` 做 RC4，结果与目标密文比较；因此解密为 `RC4(key, target)` 后再逐字节异或 `0x66`。
- 关键点：Lua 字节码本身是可反汇编的；加密只是外层包装，算法一旦从加载器恢复，内部逻辑完全可见。

## 触发条件

- 目标嵌入 Lua 字节码（`luaL_loadbuffer`/`luaL_loadstring`），或附件是 `.luac`/加密字节码。
- 加载前存在循环异或/简单流加密，密钥可能硬编码在二进制中。
- 字节码版本为 Lua 5.1/5.3/5.4，需匹配对应 `unluac`/`luac`。
- 校验逻辑使用可逆运算（RC4、XOR、加减）与硬编码密文。

## 利用步骤

1. 在二进制中定位 `luaL_loadbuffer` 调用与字节码缓冲区/长度。
2. 恢复加载前的解密循环（示例 `byte ^= "hulua"[i%5]`），dump 出 `.luac`。
3. 用匹配版本的 `unluac` 反编译，或 `luac -l -l` 查看常量/指令。
4. 提取 key、目标密文、XOR 常量与校验顺序。
5. 按逆序实现解密：先 RC4 解密，再逐字节 XOR；或按实际顺序调整。
6. 得到明文 flag，用格式校验。

## PoC

```python
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

key = bytes.fromhex("78 6D 63 74 66 32 30 32 36")  # xmctf2026
ct = bytes.fromhex(
    "8B 8B 77 BE 68 61 86 68 E5 63 EE 84 35 6F 58 C8 "
    "51 0F 6E 94 70 E7 26 90 B6 75 EC 28 AF 14 E2 E3"
)
mid = rc4(key, ct)
flag = bytes(b ^ 0x66 for b in mid)
print(flag.decode())
```

## 变体与关联

- 变体：Lua 5.1/5.4 字节码格式不同；`unluac` 需匹配版本，否则反编译失败。
- 变体：外层加密可能是 XOR、AES、自定义流密码；先恢复加载器再反汇编。
- 变体：字节码被裁剪/自定义 opcode，需要修改 Lua VM 或写自定义反汇编器。
- 关联：[[ctf-reverse-custom-python-vm-bytecode-disassembler]]（Python VM 字节码）、[[ctf-reverse-multistage-pe-vm-modified-sm4]]（自定义 VM）、[[ctf-crypto-single-byte-seed-recurrence-stream-cipher-bruteforce]]（流密码逆推）。

## 检测与防御

- 检测：二进制中出现 `luaL_loadbuffer`、Lua 字节码魔数 `\x1bLua`、循环异或解密循环。
- 防御：不要把敏感逻辑放在客户端 Lua 字节码中；使用服务端校验、代码签名/加密与完整性保护。
- 响应：确认字节码可提取后，视为逻辑泄露，轮换相关密钥并审计客户端。
