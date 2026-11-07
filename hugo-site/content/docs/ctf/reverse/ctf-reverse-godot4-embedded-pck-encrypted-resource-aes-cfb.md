---
id: ctf-reverse-godot4-embedded-pck-encrypted-resource-aes-cfb
title: Godot 4 单文件导出逆向：EXE 尾部 GDPC 内嵌 PCK + 40 字节头 AES-256-CFB 资源解密
type: scenario
domain: ctf
path: ctf/reverse
technique: godot4-embedded-pck-encrypted-resource-decrypt
tags:
- reverse
- godot
- pck
- gdscript
- aes-cfb
- game
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:12:55+08:00'
  notes: 已对照原文核对：NoMyBank.exe 单文件导出、GDPC@0x5194000、88 个文件、32 字节 key、40 字节头(MD5+长度+IV)+AES-256-CFB 均一致；原文无图片；PoC key 用占位符，未实际运行。
url: /docs/ctf/reverse/ctf-reverse-godot4-embedded-pck-encrypted-resource-aes-cfb/
draft: false
kb_aliases:
- Godot 4 单文件导出
- 内嵌 PCK
- GDPC 头
- Godot 资源加密
- AES-256-CFB 资源
- 40 字节头
- NoMyBank
---

## 一句话结论

Godot 4 的 Windows 单文件导出可以把 `.pck` 直接拼在 EXE 末尾（文件偏移处出现 `GDPC` 魔数），并用自定义模板加密资源；定位 PCK 头、解析文件表，再按“16 字节 MD5 + 8 字节明文长度 + 16 字节 IV + AES-256-CFB 密文”的 40 字节头格式解密，就能恢复 `Scripts/*.gdc`、`Scenes/*.scn`、`project.binary` 等工程资源。

## 原理

- Godot 4 的 PCK 文件以 `GDPC` 魔数开头，后面是版本、文件数、文件表（路径、偏移、大小、MD5）等；正常导出是 `game.exe` + `game.pck` 两个文件，但“单文件导出”会把 PCK 直接追加到 EXE 末尾，所以从 EXE 中搜索 `GDPC` 就能定位资源包。
- 本题 `NoMyBank.exe` 是 PE32+ x64，`GDPC` 位于文件偏移 `0x5194000`；PCK 文件表有 88 个条目，包含 `Scripts/*.gdc`、`Scenes/*.scn`、`project.binary`、`.godot/exported/...`、`bin/libextension.gdextension`。
- 资源不是明文，而是用自定义 Godot 模板加密。模板中读取 pack key 的逻辑可以通过报错字符串 `Can't open encrypted pack directory.` 定位；程序从一个全局地址取 32 字节 AES key。
- 每个资源的加密格式（本题）为 40 字节头：
  ```text
  [0:16]   MD5(plaintext)
  [16:24]  plaintext length, little-endian uint64
  [24:40]  IV
  [40:40+size] AES-256-CFB ciphertext
  ```
  解密时用 32 字节 key、IV 和 `segment_size=128` 的 CFB 模式解出明文，再用头部 MD5 校验，防止 key/偏移错误。
- `.gdc` 是 Godot 4 编译后的 tokenizer buffer，不是 Godot 3 的旧字节码；可以用 gdre_tools 等工具恢复 token 表、标识符表和常量表，得到接近源码的 GDScript。
- 根因是“客户端必须持有解密 key 才能运行游戏”，key 无论藏在模板、全局变量还是混淆代码里，最终都能被定位；加密只提高逆向成本。

## 触发条件

- 目标为 Godot 4 导出的游戏，且为单文件导出或 PCK 被追加/嵌入 EXE。
- 资源使用自定义模板加密，EXE 中存在解密 key 与解密逻辑。
- PCK 文件表可解析（版本匹配），资源头格式可从模板或已知明文推断。
- 允许静态分析 EXE 与本地解密（CTF/授权逆向场景）。

## 利用步骤

1. 用 `file`/Exeinfo 确认 PE32+ x64 与 Godot 特征；在 EXE 中搜索 `GDPC`，记录文件偏移。
2. 解析 PCK 头与文件表：确认文件数、每个资源的路径/偏移/大小；本题为 88 个文件。
3. 在模板中定位 `Can't open encrypted pack directory.` 等报错字符串的 xref，逆出读取 32 字节 key 的全局地址。
4. 按 40 字节头格式读取每个资源：MD5、长度、IV、密文；用 AES-256-CFB 解密并校验 MD5。
5. 将解密后的 `.gdc` 用 gdre_tools 恢复为 GDScript，阅读 `WinPopupTreasury.gdc`、`OnEnterTreasury.gdc`、`GameManager.gdc` 等关键脚本。
6. 继续分析外部 GDExtension 与最终校验逻辑（见关联卡片）。

## PoC

```python
import hashlib
from Crypto.Cipher import AES

KEY = bytes.fromhex("<32 字节 key>")
PACK = open("NoMyBank.exe", "rb").read()

# 定位 GDPC（示例偏移）
pck_off = PACK.find(b"GDPC")
print("GDPC at", hex(pck_off))

def decrypt_resource(blob: bytes) -> bytes:
    md5_expected = blob[:16]
    size = int.from_bytes(blob[16:24], "little")
    iv = blob[24:40]
    ct = blob[40:40 + size]
    pt = AES.new(KEY, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
    assert hashlib.md5(pt).digest() == md5_expected
    return pt

# 按 PCK 文件表取出某个资源 blob 后：
# plain = decrypt_resource(blob)
```

PCK 文件表解析（伪代码）：

```text
magic = "GDPC"
version = u32
ver_major, ver_minor, ver_patch = u32,u32,u32
flags = u32
file_base = u64
file_count = u32
for i in range(file_count):
    path_len = u32
    path = bytes[path_len]
    offset = u64
    size = u64
    md5 = bytes[16]
    flags = u32
```

## 变体与关联

- **导出变体**：`exe + 独立 pck`、单文件内嵌 pck、pck 被压缩/分片；先在 EXE/目录中搜索 `GDPC`。
- **加密变体**：Godot 资源加密可能是 AES-CFB、AES-CTR、XOR 流或自定义头；头格式（MD5/长度/IV）需按模板或已知明文推断。
- **脚本变体**：`.gdc` 可能是 Godot 3 字节码、Godot 4 tokenizer buffer 或明文 `.gd`；用对应版本工具反编译。
- **关联**：[[ctf-reverse-godot-pck-gdc-decompile-patch-repack]]（pck/gdc 解包反编译与补丁重打包）；[[ctf-reverse-godot4-gdextension-rc4-hotpatch-shellcode]]（本题第二层：GDExtension 伪 DLL 与热补丁 shellcode）。
- **边界**：若 key 由服务端动态下发、资源使用非对称加密或 PCK 文件表被完全自定义，需先逆出模板的加载逻辑。

## 检测与防御

- **检测**：EXE 尾部出现 `GDPC`、PCK 文件表、`Can't open encrypted pack directory.` 字符串；进程加载 `.pck`/`res://` 资源；资源头呈 MD5+长度+IV 结构。
- **防御**：游戏发行方不要把 flag/密钥编码进客户端；关键校验放服务端；资源加密 key 使用每用户/每会话派生并配合完整性校验。
- **加固**：自定义模板、字符串加密、反调试只能提高成本；资源最终必须被客户端解密，无法做到绝对保密。
