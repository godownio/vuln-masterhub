---
id: code-analysis-reverse-unpacking-pe-loader-lcg-chacha20
title: PE 加载器：LCG 派生 ChaCha20 key/nonce 解密二阶段 PE
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pe-loader-lcg-chacha20-stage2
aliases:
- 二阶段 PE
- PE loader
- ChaCha20 解密
- LCG 派生 key
- BankGuardian
- dotnet 加载器
tags:
- reverse
- unpacking
- pe-loader
- chacha20
- lcg
- dotnet
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:14:01+08:00'
  notes: 已对照原文核对：动态解析 kernel32、0xE400 密文、ChaCha20 常量 expand 32-byte k、LCG x=1103515245*x+12345 种子 2356100023 生成 11 个 u32 共 44 字节（前 32 key/后 12 nonce）、解密后 MZ、临时 PE + .runtimeconfig.json 以 dotnet 6.0.0 启动、二阶段 ssnKey=24 与片段均一致。未验证点：PoC 未本机复跑（无样本）；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

样本是一个 PE 加载器：它动态解析 `kernel32` 导出、把内置的 `0xE400` 字节密文用 ChaCha20 解密，检查结果是否为 `MZ`，再写成临时 PE 并配合 `.runtimeconfig.json` 用 `dotnet` 启动二阶段；ChaCha20 的 key/nonce 由固定种子 `2356100023` 经 LCG 生成 44 字节（前 32 字节 key、后 12 字节 nonce），因此可离线复现解密。

## 原理

- 加载器通过 `GetModuleHandleA("kernel32.dll")` + 自定义解析（哈希/序号）动态获取 `CreateFile`、`WriteFile`、`CreateProcess` 等函数，降低导入表可读性。
- 它从自身数据段复制 `0xE400` 字节密文到新内存，调用 `sub_140003DE0` 解密；该函数内部使用 ChaCha20 标准常量 `"expand 32-byte k"` 与 20 轮 block function。
- key/nonce 生成函数 `sub_140001260` 接收固定种子 `2356100023`，用 LCG `x = (1103515245*x + 12345) & 0xffffffff` 连续生成 11 个 uint32，按小端拼成 44 字节；前 32 字节为 ChaCha20 key，后 12 字节为 nonce。
- 解密结果以 `MZ` 开头，说明是 PE；加载器把它写到临时文件，再写 `.runtimeconfig.json`（`Microsoft.NETCore.App 6.0.0`），用 `dotnet "path"` 启动。
- 二阶段 .NET 程序再用 `ssnKey=24` 对内嵌资源 `Config.bin` 逐字节 XOR，恢复 `D0tN3t_`、`1nj3ct10n_`、`Pwn3r}` 等片段。
- 关键点：LCG 是确定性的，种子硬编码；ChaCha20 是标准算法；只要恢复 key/nonce 就能离线解密，不需要运行样本。

## 触发条件

- 样本是 PE 加载器，包含大块高熵数据与 `VirtualAlloc`/`WriteFile`/`CreateProcess` 等行为。
- 解密函数中出现 ChaCha20 常量或标准轮函数。
- key/nonce 由固定种子 + 线性同余/PRNG 生成。
- 解密结果以 `MZ`/`ELF` 等魔数开头，或加载器写临时文件后启动。

## 利用步骤

1. 定位加载器中的密文块（大小、偏移）与解密函数。
2. 识别 ChaCha20（常量 `expand 32-byte k`、20 轮、quarter round）。
3. 找到 key/nonce 生成函数与种子；复现 LCG，生成 44 字节材料。
4. 拆分 key（前 32）与 nonce（后 12），ChaCha20 解密整个密文块。
5. 检查输出是否以 `MZ` 开头；若是，写文件并用 PE 工具/.NET 反编译继续分析。
6. 分析二阶段资源 XOR/配置，恢复最终 flag/密钥。

## PoC

```python
import struct

SEED = 2356100023
CIPH_LEN = 0xE400

def lcg_material(seed: int) -> bytes:
    x = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(11):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        out += struct.pack("<I", x)
    return bytes(out)

material = lcg_material(SEED)
key, nonce = material[:32], material[32:44]
print("key =", key.hex())
print("nonce =", nonce.hex())

# 用标准 ChaCha20 实现（cryptography / pycryptodome）解密从样本提取的 0xE400 字节
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
# dec = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
# plain = dec.update(ciphertext)
# assert plain[:2] == b"MZ"
```

## 变体与关联

- 变体：PRNG 换成 MT19937、rand()、时间种子；key/nonce 可能分段生成。
- 变体：加密算法换成 AES-CBC/RC4/Salsa20；按常量与轮函数识别。
- 变体：二阶段可能是 .NET/Java/ELF，加载方式不同但“解密→落盘→启动”链相同。
- 关联：[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（UPX 变种 stub）、[[ctf-reverse-multistage-pe-vm-modified-sm4]]（多阶段 PE）、[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（LCG 恢复）。

## 检测与防御

- 检测：PE 中出现大块高熵数据、ChaCha20 常量、`CreateProcess`/`WriteFile` 临时 PE、`.runtimeconfig.json` 写入。
- 防御：EDR 监控临时目录 PE 落盘与 `dotnet` 启动链；对内存中的 MZ 镜像做扫描；限制脚本/加载器执行。
- 响应：提取并解密二阶段，分析其网络/持久化行为，隔离主机并轮换相关凭据。
