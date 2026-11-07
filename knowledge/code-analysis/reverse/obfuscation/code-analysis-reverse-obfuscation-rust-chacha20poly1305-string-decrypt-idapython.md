---
id: code-analysis-reverse-obfuscation-rust-chacha20poly1305-string-decrypt-idapython
title: Rust 恶意样本 ChaCha20-Poly1305 字符串解密：硬编码 32 字节 key + IDAPython 批量还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: rust-chacha20poly1305-string-decrypt-idapython
aliases:
- Rust 字符串解密
- ChaCha20Poly1305 字符串
- muddy_internal decrypt
- IDAPython 批量解密字符串
- 硬编码 ChaCha20 key
- Rust 恶意样本去混淆
tags:
- code-analysis
- reverse
- obfuscation
- rust
- chacha20poly1305
- string-decrypt
- idapython
- malware
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:43:51+08:00'
  notes: 已对照原文与图06/07/08核对：secondstage::muddy_internal::decrypt 调用参数为密文指针/长度、nonce 指针/长短，图07 调用为 decrypt(v21,&encdata,21,&nonce,12)，key=9F80A116...（32字节），图08 为批量解密输出；卡中 IDAPython 四参数 store 解析与 ChaCha20Poly1305 调用一致。未在本机 IDA 复跑脚本。
---

## 一句话结论

Rust 恶意样本把字符串用 ChaCha20-Poly1305 加密后存放在 `.rdata`，解密函数接收密文指针/长度与 nonce 指针/长度并使用硬编码的 32 字节 key；找到该函数与 key 后，用 IDAPython 遍历所有 xref、解析调用前的四个参数 store、从 `.rdata` 读取密文与 nonce 并批量解密，即可一次性还原样本里的全部字符串。

## 原理

- **加密方案**：样本使用 ChaCha20-Poly1305（Rust `chacha20poly1305` crate 或等价实现），key 固定 32 字节，nonce 12 字节，密文尾部带 16 字节 Poly1305 tag。解密函数签名类似 `secondstage::muddy_internal::decrypt(ciphertext_ptr, ciphertext_len, nonce_ptr, nonce_len)`，返回 `CString`/`String`。
- **字符串存放方式**：加密后的字节和 nonce 放在 `.rdata`（或只读数据段），调用点把密文指针、长度、nonce 指针、长度写入栈上结构体（如 `[eax+4]=data_ptr`、`[eax+8]=data_len`、`[eax+0xC]=nonce_ptr`、`[eax+0x10]=nonce_len`），再 `call decrypt`。
- **硬编码 key 是单点失败**：key 不参与每次调用，而是函数内部常量/全局；一旦从反汇编或内存中找到 32 字节 key，所有字符串都能离线解密。样例 key 为 32 字节 hex，nonce 通常 12 字节、每条字符串不同或固定。
- **IDAPython 自动化思路**：
  1. 定位解密函数地址（通过 crypto 常量、字符串引用、函数签名或调试断点）。
  2. `idautils.XrefsTo(decrypt_addr)` 找所有调用点。
  3. 对每个 `call` 向前取 4 条 `mov` 指令，解析立即数/内存操作数，得到 nonce_len、nonce_ptr、data_len、data_ptr。
  4. `idc.get_wide_byte` 从 `.rdata` 读取密文与 nonce。
  5. 用 `ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)` 解密，打印/注释到 IDA。
- **为什么这样能批量还原**：Rust 编译器生成的参数布局相对固定，调用点模式一致；脚本按“call 前四条 store”的模板解析，能覆盖大量字符串而不用逐个人工跟踪。
- **边界**：如果 key 不是硬编码而是运行时派生、nonce 随机、密文被压缩/二次编码，脚本需要先还原 key/nonce；如果字符串通过 trait/间接调用，xref 可能不直接指向 decrypt，需要先解析 vtable/函数指针。

## 触发条件

- 目标为 Rust 编写的恶意样本/程序，字符串以 ChaCha20-Poly1305 密文形式存放在只读数据段。
- 能定位解密函数（符号、crypto API、常量、调试断点）并提取 32 字节 key。
- 有 IDA Pro/IDAPython 与 `cryptography` 库；样本可静态读取 `.rdata`。
- 调用点参数布局符合“call 前把四个值写入结构体”的模板；否则需要调整脚本。

## 利用步骤

1. 在 IDA 中定位解密函数：搜索 ChaCha20 常量（sigma `expand 32-byte k`）、`chacha20poly1305` 相关字符串、或对密文/`CString` 的引用。
2. 确认 key：在函数内部找 32 字节常量，或在调试时于 key 加载处 dump；确认 nonce 长度 12。
3. 找到所有 `call decrypt` 的 xref；对每个调用点向前解析四条参数 store。
4. 从 `.rdata` 读取密文与 nonce，调用 ChaCha20-Poly1305 解密；`cryptography` 的 `decrypt` 会自动校验/去除 tag。
5. 将解密结果写回 IDA 注释/重命名，或导出为 JSON 供后续分析。
6. 对解密失败/长度异常的调用点，检查参数顺序、nonce 长度、密文是否被二次编码。

## PoC

```python
import idautils, idaapi, idc
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY = bytes.fromhex("9F80A116F20535761EC9BB91CC406987B981A2AC7E3A709BAE83C8A512F8FAE4")

def read_bytes(addr, size):
    return bytes(idc.get_wide_byte(addr + i) for i in range(size))

def prev_insts(ea, count=4):
    out = []
    cur = ea
    for _ in range(count):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR:
            break
        out.append(cur)
    return list(reversed(out))

def operand_value(ea):
    insn = idaapi.insn_t()
    if not idaapi.decode_insn(insn, ea) or insn.itype != idaapi.NN_mov:
        return None
    op = insn.ops[1]
    if op.type == idaapi.o_imm:
        return op.value
    if op.type in (idaapi.o_mem, idaapi.o_near, idaapi.o_far):
        return op.addr
    return None

def decrypt_at(call_ea, decrypt_addr):
    insts = prev_insts(call_ea, 4)
    if len(insts) != 4:
        return
    nonce_len, nonce_ptr, data_len, data_ptr = [operand_value(i) for i in insts]
    if None in (nonce_len, nonce_ptr, data_len, data_ptr):
        return
    ct = read_bytes(data_ptr, data_len)
    nonce = read_bytes(nonce_ptr, nonce_len)
    try:
        pt = ChaCha20Poly1305(KEY).decrypt(nonce, ct, None)
        print(f"{call_ea:#x}: {pt.decode('utf-8', 'ignore')}")
    except Exception as e:
        print(f"{call_ea:#x}: decrypt failed: {e}")

for xref in idautils.XrefsTo(DECRYPT_ADDR):
    if idc.is_code(idc.get_full_flags(xref.frm)):
        decrypt_at(xref.frm, DECRYPT_ADDR)
```

> `DECRYPT_ADDR` 需替换为样本中解密函数地址；参数顺序（nonce/data）按实际调用点调整。

## 变体与关联

- 变体：key 由 `SHA-256(passphrase)` 或机器信息派生；nonce 随机/每条不同；密文先 Base64/hex 编码。
- 变体：ChaCha20（无 Poly1305）时密文无 tag，解密不校验完整性；nonce 可能 8/12 字节。
- 变体：字符串解密函数被 trait/vtable 间接调用，xref 不直接；需先还原函数指针表。
- 关联卡片：[[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]、[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]、[[code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt]]、[[pentest-c2-signed-installer-systemcertificates-dll-regsvr32-loader]]。

## 检测与防御

- 检测：Rust 样本 `.rdata` 中存在高熵数据块与 ChaCha20 常量（`expand 32-byte k`）；大量 `call` 指向同一解密函数。
- 检测：运行时在内存中出现明文字符串，而静态 `.rdata` 中对应位置为密文；可用内存 dump/断点对比。
- 防御：恶意样本分析侧可批量解密；防御侧应检测高熵字符串表、加密常量与解密函数调用模式。
- 防御：对 Rust 样本启用字符串加密时避免硬编码 key，使用运行时派生/白盒；分析侧关注 key 加载点与 nonce 生成逻辑。
