---
id: code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt
title: PyInstaller --key 加密 PYZ：pyimod00_crypto_key 取密钥 + 按版本分流 PyCrypto-CFB/tinyaes-CTR 解密 pyc.encrypted
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pyinstaller-encrypted-pyz-pyc-decrypt
tags:
- reverse
- unpacking
- pyinstaller
- python
- pyc
- tinyaes
- pycrypto
- aes-cfb
- aes-ctr
- zlib
cve: []
severity: medium
confidence: high
affected_versions: PyInstaller < 4.0（PyCrypto AES-CFB）；>= 4.0（tinyaes AES-CTR）（原文版本分支）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:52:25+08:00'
  notes: V263 复核：已完整重读 content.md 并逐张核对36张图。卡面“PyInstaller --key 加密 PYZ”部分与原文一致：图09/10 解包出现 pyimod00_crypto_key.pyc、pyimod02_archive.pyc、something.pyc 与 Failed to decompress ... probably encrypted；图11/12 反编译得 key="yibaibayibei1801"；图13 Cipher.decrypt 使用 CTR_xcrypt_buffer；图14 明确 PyInstaller <4.0=>PyCrypto+CFB、>=4.0=>tinyaes+CTR；原文两段解密脚本均为“前16字节IV→AES解密→zlib.decompress→补pyc头”，卡内 PoC 与之等价，pyc magic 表 3.7/3.8/3.9/3.10 亦与原文一致。affected_versions 按原文版本分支保留（<4.0 PyCrypto CFB；>=4.0 tinyaes CTR）。文章其余部分（pyc 基础/magic 表、TEA/XTEA/XXTEA、花指令与 IDA 去花）经确认已由 code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract、code-analysis-reverse-crypto-encoding-identification-decrypt、code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair 等既有 verified 卡覆盖，跳过成立。dedup 最高分为卡自身 exact，其余 PyInstaller 卡为不同环节/不同算法，非同一链。未运行原文工具与 PoC；frontmatter 无 sources/source（符合禁用要求），亦无 source_url。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt/
draft: false
kb_aliases:
- pyc.encrypted 解密
- pyimod00_crypto_key
- pyimod02_archive
- CTR_xcrypt_buffer
- PyInstaller --key
- 加密 pyc 恢复
---

## 一句话结论

用 `--key` 加密打包的 PyInstaller EXE，`PYZ-00.pyz_extracted` 下的依赖 pyc 会变成 AES 加密的 `*.pyc.encrypted`；从解包出的 `pyimod00_crypto_key.pyc` 反编译得到 key，再按 PyInstaller 版本选择算法（<4.0 为 PyCrypto AES-CFB，>=4.0 为 tinyaes AES-CTR），把文件前 16 字节当 IV、解密剩余内容后 `zlib.decompress`，补上与打包 Python 版本匹配的 16 字节 pyc 头，即可得到可反编译的 pyc。

## 原理

- PyInstaller 的加密打包（`pyinstaller -F --key <key> target.py`）只加密 PYZ 归档中的依赖模块，入口脚本与引导代码仍以明文 pyc 形式存在；加密后的模块在提取目录里表现为 `*.pyc.encrypted`，直接交给 pycdc/uncompyle6 会失败。
- 打包器在 CArchive 中同时放入 `pyimod00_crypto_key.pyc`，其反编译结果就是开发者指定的 key（字符串）；`pyimod02_archive.pyc` 中的 `Cipher` 类封装了实际加解密：`__create_cipher(iv)` 用 `self.key.encode()` 和 IV 构造 AES 对象，`decrypt(data)` 取 `data[:CRYPT_BLOCK_SIZE]` 作 IV，对 `data[CRYPT_BLOCK_SIZE:]` 调用底层加密库。
- 加密方案随 PyInstaller 版本变化：<4.0 使用 PyCrypto 的 `AES.MODE_CFB`，>=4.0 改用 tinyaes 的 `CTR_xcrypt_buffer`（CTR 模式）。若用错版本脚本，解密结果是乱码，`zlib.decompress` 会直接报错。
- 每个 `pyc.encrypted` 的文件布局是“16 字节 IV + 密文”，且密文解密后仍是 zlib 压缩数据；所以解密顺序必须是先 AES 解密、再 zlib 解压，不能反过来。
- PyInstaller 只加密依赖库、不写 pyc 头：解密出的只是 marshal 序列化的 code object。要交给反编译器，必须自己补 16 字节 pyc 头（4 字节 magic + 12 字节标志/时间戳/大小字段，Python 3.7+ 为 16 字节头）；magic 必须对应打包时的 Python 版本，否则反编译器会拒绝或误解析。
- 反编译得到的 `pyimod02_archive` 同时暴露了判断依据：类名 `Cipher`、`AES(self.key.encode(), iv)`、`CTR_xcrypt_buffer`（>=4.0）或 CFB 调用（<4.0），据此选择解密脚本，而不是盲试。

## 触发条件

- 目标 EXE 由 PyInstaller 打包且使用了 `--key`（加密打包）；`pyinstxtractor` 输出中可见 `Failed to decompress ... probably encrypted`，提取目录出现 `*.pyc.encrypted` 或 `PYZ-00.pyz_extracted` 内文件无法反编译。
- 能从解包结果中取到 `pyimod00_crypto_key.pyc`（key 硬编码在打包产物里），且 `pyimod02_archive.pyc` 可反编译或可读字节码。
- 已知打包使用的 PyInstaller 大版本（<4.0 / >=4.0）或可根据 `Cipher` 类实现判断；已知打包 Python 版本以选择 pyc magic。
- 允许在本地安装 `pycryptodome`/`tinyaes` 执行离线解密。

## 利用步骤

1. 先按常规解包：`python pyinstxtractor.py target.exe`，记录输出中的 PyInstaller 版本、Python 版本与入口 pyc；若出现大量 `probably encrypted`，说明命中了 `--key` 加密。
2. 在输出目录找到 `pyimod00_crypto_key.pyc`，用对应 Python 版本的反编译器（或在线 pyc 反编译）还原，读取 `key = "..."`。
3. 反编译 `pyimod02_archive.pyc`，查看 `Cipher.decrypt`：出现 `CTR_xcrypt_buffer` 即 PyInstaller >=4.0（tinyaes）；出现 `AES.MODE_CFB`/PyCrypto 即 <4.0。
4. 遍历 `PYZ-00.pyz_extracted/**/*.pyc.encrypted`：读前 16 字节作 IV，AES 解密其余字节，`zlib.decompress` 得到 code object 数据。
5. 按打包 Python 版本写入 16 字节 pyc 头（如 Python 3.8 为 `55 0d 0d 0a` + 12 个 0），再拼上解密数据，输出同名 `.pyc`。
6. 用 pycdc/uncompyle6/对应在线服务反编译还原源码；反编译失败时改用 `marshal.loads(data)` + `dis` 或 pycdas 看字节码。
7. 对入口脚本与剩余依赖重复同一流程；注意入口 pyc 通常未加密，优先反编译入口以确认业务逻辑。

## PoC

```python
# PyInstaller < 4.0：PyCrypto AES-CFB；key 来自 pyimod00_crypto_key.pyc
import glob, zlib
from Crypto.Cipher import AES
from pathlib import Path

CRYPT_BLOCK_SIZE = 16
key = bytes('MySup3rS3cr3tK3y', 'utf-8')   # pyimod00_crypto_key 中的 key

for p in Path("PYZ-00.pyz_extracted").glob("**/*.pyc.encrypted"):
    inf = open(p, 'rb')
    outf = open(p.with_name(p.stem), 'wb')
    iv = inf.read(CRYPT_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = zlib.decompress(cipher.decrypt(inf.read()))
    outf.write(b'\x55\x0d\x0d\x0a' + b'\x00' * 12)  # Python 3.8 pyc 头
    outf.write(plaintext)
    inf.close(); outf.close()
```

```python
# PyInstaller >= 4.0：tinyaes AES-CTR
import zlib, tinyaes
from pathlib import Path

CRYPT_BLOCK_SIZE = 16
key = bytes('MySup3rS3cr3tK3y', 'utf-8')

for p in Path("PYZ-00.pyz_extracted").glob("**/*.pyc.encrypted"):
    inf = open(p, 'rb')
    outf = open(p.with_name(p.stem), 'wb')
    iv = inf.read(CRYPT_BLOCK_SIZE)
    cipher = tinyaes.AES(key, iv)
    plaintext = zlib.decompress(cipher.CTR_xcrypt_buffer(inf.read()))
    outf.write(b'\x55\x0d\x0d\x0a' + b'\x00' * 12)  # 按实际 Python 版本替换 magic
    outf.write(plaintext)
    inf.close(); outf.close()
```

## 变体与关联

- 变体：PyInstaller 版本判断错误是首要失败原因；`pyimod02_archive.pyc` 的 `Cipher.decrypt` 是权威依据，必要时直接看 `tinyaes`/`PyCrypto` 导入。
- 变体：Python 3.7/3.8/3.9/3.10 的 pyc magic 不同（如 3.7 `42 0d 0d 0a`、3.8 `55 0d 0d 0a`、3.9 `61 0d 0d 0a`、3.10 `6f 0d 0d 0a`）；magic 不对时反编译器直接报错。
- 变体：key 可能不是明文常量，而是运行时拼接/派生；此时需动态调试 `pyimod00_crypto_key` 或 `Cipher` 构造处 dump。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（常规 PyInstaller 解包与 pyc 反编译）、[[code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object]]（pyd 内 marshal code object 的 XOR 还原）、[[ctf-reverse-pyinstaller-marshal-btea-xxtea-decrypt]]（解密后业务层再套 TEA 系列加密）。
- 边界：`--key` 加密保护的是依赖库源码，入口与引导层仍可分析；若打包后又加壳/混淆，仍需先脱壳再解 CArchive。

## 检测与防御

- 检测（逆向侧）：PYZ 提取目录出现 `*.pyc.encrypted`、`Failed to decompress ... probably encrypted`；`pyimod00_crypto_key.pyc` 与 `pyimod02_archive.pyc` 同时存在即可判定 `--key` 打包。
- 防御（打包者）：`--key` 只是把密钥放在同一个 EXE 里，无法阻止离线解密；不要把授权判断、敏感算法或密钥只放在客户端，关键校验必须放服务端。
- 加固：代码签名/完整性校验、反调试只能提高成本；若必须保护 Python 逻辑，应使用白盒化/服务端执行等方案，而不是依赖 PyInstaller 加密。
