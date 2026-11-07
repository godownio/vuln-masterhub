---
id: ctf-reverse-brotli-embedded-js-rc4-xtea-xor
title: Brotli 内嵌前端 + RC4 + XTEA + XOR 掩码多层解密
type: scenario
domain: ctf
path: ctf/reverse
technique: brotli-embedded-js-rc4-xtea-xor
aliases:
- Brotli 内嵌 index.html
- 前端 RC4 Encrypt 函数
- 自定义 XTEA 变种
- XOR 固定掩码
- 多层解密链
tags:
- ctf
- reverse
- brotli
- rc4
- xtea
- xor
- embedded-html
- multilayer
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:23+08:00'
  notes: 已对照原文与全部 89 张图片核对；Brotli/RC4/XTEA/XOR 顺序与密钥一致；未在本机复现
---

## 一句话结论

exe 中搜索到 `index.html` 字符串，其附近是一段 `1B` 开头的 Brotli 压缩数据；解压得到前端 JS，`Encrypt_0x5031b3` 是密钥为 `SAdt0ngY1AIrC4hH` 的 RC4；后端有自定义 XTEA（`delta=0x7E3997B7`，key 字为 `'Welc','Om3t','rus0','UaTt'`）与固定 XOR 掩码；按“Base64 → XTEA 解密 → Base64 → XOR 掩码”的顺序即可还原 flag。

## 原理

- **Brotli 内嵌资源**：程序把前端 HTML/JS 以 Brotli 压缩后嵌入二进制 `.rdata`，运行时解压加载；`1B` 是 Brotli 流的常见首字节，可在字符串引用附近定位并 dump。
- **RC4**：前端 `Encrypt_0x5031b3` 用固定密钥初始化 S 盒并生成密钥流，对明文逐字节 XOR；密钥 `SAdt0ngY1AIrC4hH` 直接在 JS 中。
- **自定义 XTEA**：后端使用 `delta=0x7E3997B7`、32 轮，key words 由 ASCII `'Welc'`、`'Om3t'`、`'rus0'`、`'UaTt'` 组成；解密按相反顺序减轮函数并递减 sum。
- **XOR 掩码**：最后一步用固定 60 字节 `XOR_MASK` 循环异或，掩码可从二进制/代码中提取。
- **整体顺序**：密文先 Base64 解码，再做 XTEA ECB 解密（按大端解析、小端重组），再 Base64 解码，最后与 XOR 掩码异或得到 flag。

## 触发条件

- 目标为包含内嵌 Web 前端的 exe/ELF，字符串中有 `index.html`、`Encrypt_` 等特征。
- 前后端使用自定义/变种密码，常量与密钥可在二进制或 JS 中找到。
- 有密文与目标输出用于验证解密顺序。

## 利用步骤

1. 在 IDA 中搜索 `index.html` 字符串，跟踪引用，定位附近的 Brotli 数据（`1B` 开头），dump 为 `data.bin`。
2. 用 Brotli 解压 `data.bin`，得到前端 HTML/JS；搜索 `Encrypt` 函数，提取 RC4 密钥与调用方式。
3. 在后端定位 XTEA 轮函数，提取 delta、key words 与轮数；确认密文解析/输出字节序。
4. 提取固定 XOR 掩码（或从代码中重建）。
5. 按 Base64 → XTEA 解密 → Base64 → XOR 的顺序写脚本，验证输出为可读 flag。

## PoC

```python
import base64

XOR_MASK = [232,0,230,97,0,0,88,88,0,118,233,0,91,8,29,213,
            0,224,188,251,252,20,20,0,0,0,0,0,0,0,222,119,
            0,0,177,0,0,0,0,0,0,0,149,8,120,233,187,175,
            0,3,3,0,238,96,0,0,241,87,73,96]
TEA_DELTA = 0x7E3997B7
KEY_WORDS = (0x636C6557, 0x74336D4F, 0x73757230, 0x55615474)  # 'Welc','Om3t','rus0','UaTt'

def tea_decrypt(data: bytes, rounds=32):
    out = bytearray()
    sched = (TEA_DELTA * rounds) & 0xFFFFFFFF
    for i in range(0, len(data), 8):
        v0 = int.from_bytes(data[i:i+4], 'big')
        v1 = int.from_bytes(data[i+4:i+8], 'big')
        s = sched
        for _ in range(rounds):
            v1 = (v1 - (((v0 << 4) + KEY_WORDS[2]) ^ (v0 + s) ^ ((v0 >> 5) + KEY_WORDS[3]))) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) + KEY_WORDS[0]) ^ (v1 + s) ^ ((v1 >> 5) + KEY_WORDS[1]))) & 0xFFFFFFFF
            s = (s - TEA_DELTA) & 0xFFFFFFFF
        out += v0.to_bytes(4, 'little') + v1.to_bytes(4, 'little')
    return bytes(out)

encoded = "daF/DkQxixGmzn0aPFW2E2PhM8NabRtLjp6pI+c8TtY3WMuPxfnvlAsp9aluf8noZy/T6Sz9DJg="
layer1 = base64.b64decode(encoded)
layer2 = tea_decrypt(layer1)
layer3 = base64.b64decode(layer2)
flag = bytes(b ^ XOR_MASK[i % len(XOR_MASK)] for i, b in enumerate(layer3))
print(flag.decode())
```

## 变体与关联

- 内嵌前端可换成 gzip/zlib/Brotli、资源段/附加数据；先按魔数与字符串引用定位。
- 密码层可换成 RC4 变种、XXTEA、AES；关键是确认层顺序（编码/加密/掩码）。
- 关联：Go 程序多层 XOR/RC4/XXTEA、PyInstaller 内嵌前端、Godot GDExtension 多层解密。

## 检测与防御

- 恶意样本分析：识别内嵌 HTML/JS 与 Brotli 流，优先还原前端逻辑找密钥。
- 对多层加密，逐层验证字节序与编码（Base64 的填充、big/little endian）。
- 防御方不要把密钥硬编码在前端/二进制中；使用服务端密钥与标准密码库。
