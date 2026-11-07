---
id: code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object
title: PyInstaller pyd 内嵌 XOR 加密 marshal code object：IDA dump + 循环异或还原 pyc
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: pyinstaller-pyd-xor-marshal-code-object
tags:
- python
- reverse
- pyinstaller
- pyd
- marshal
- xor
- unpacking
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:49:44+08:00'
  notes: 已对照原文与图01-11核对：PyByteArray 长度0x327B2/地址0x2B2F9171580、PyBytes key bangdreamitsmygo、PyNumber_InPlaceXor、解密后CB0D0D0A pyc头均一致；原文PoC未复跑。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object/
draft: false
kb_aliases:
- pyd 逆向
- PyInstaller pyd
- 内嵌 marshal code object
- XOR 加密 bytearray
- chal.pyc
- pyinstxtractor
- PyLingual
---

## 一句话结论

PyInstaller 程序解包得到 `chal.pyc` 后，如果它只调用 `checkinput.pyd` 里的函数，就继续逆向 pyd：在 IDA 中定位 `PyByteArray`/`PyBytes` 对象和 `PyNumber_InPlaceXor` 循环，dump 出大 bytearray 与硬编码 key（如 `bangdreamitsmygo`），按字节循环异或即可还原出带 pyc 头/marshal code object 的下一层文件，再用 PyLingual 反编译。

## 原理

- PyInstaller 解包：`pyinstxtractor.py` 从 exe 的 CArchive 提取 `chal.pyc`；`chal.pyc` 可能只是引导代码，真正逻辑在打包进来的 `checkinput.pyd`（Python 扩展模块）。
- pyd 是原生 PE，但通过 CPython C API 操作 Python 对象：IDA 中可见 `PyByteArray_Type`、`PyBytes_Type`、`PyLong_Type`、`PyNumber_InPlaceXor` 等符号/类型指针。
- 样本在 pyd 中构造一个 `bytearray`（文章长度 `0x327B2`），内容为加密的下一层代码；另有一个 `bytes` 对象存 XOR key（文章为 `bangdreamitsmygo`，`PyBytes` 长度 0x10）。
- 循环里先取 `bytearray[i]`（`sub_...` 返回 PyLong，值为字节），再取 key[i % len]（`PyLong`/`PyBytes`），调用 `PyNumber_InPlaceXor` 异或，写回 bytearray。
- 异或后的 bytearray 开头出现 `CB 0D 0D 0A`（Python 3.12 pyc magic）和 marshal `0xE3` 等特征，说明它是完整的 pyc（或带 pyc 头的 marshal code object）；把它写成文件后用 PyLingual/pycdc 反编译，得到 layer2 逻辑。
- 关键点：加密是简单的循环 XOR，密钥以 `PyBytes` 明文存在于 pyd 内存；IDA 动态调试可以直接 dump bytearray 指针和内容，或静态从 `.data`/初始化代码提取。

## 触发条件

- 目标是 PyInstaller 打包的 Python 程序，解包后得到 pyc 和 pyd。
- pyd 中有大块加密数据（bytearray/bytes），运行时用 XOR/简单变换解密；密钥硬编码在 pyd 中。
- 能使用 IDA/x64dbg 附加到 Python 进程，或在静态分析中定位 PyByteArray/PyBytes 对象和 `PyNumber_InPlaceXor` 调用。
- 解密结果符合 pyc magic（`CB 0D 0D 0A` 等）或 marshal code object 特征。

## 利用步骤

1. 用 `pyinstxtractor.py` 解包 exe，提取 `chal.pyc`；用 PyLingual 反编译，确认它 `import pyramid`/调用 pyd 函数。
2. 在 IDA 中打开 pyd，搜索 `PyByteArray_Type`/`PyBytes_Type`/`PyNumber_InPlaceXor`，定位解密循环和 bytearray/key 对象。
3. 通过调试器查看 `PyByteArray` 对象的 `ob_size` 和数据指针（文章 `0x2B2F9171580`、长度 `0x327B2`），dump 加密数据；同时 dump `PyBytes` key（`bangdreamitsmygo`）。
4. 用脚本按 `data[i] ^= ord(key[i % len(key)])` 循环异或，写出 `decrypt_dump.bin`。
5. 用十六进制查看确认 pyc magic（`CB 0D 0D 0A`）与 marshal `0xE3`；必要时补上 16 字节 pyc 头（magic + bit field + timestamp + size）。
6. 用 PyLingual/pycdc/uncompyle6 反编译，继续分析 layer2（可能还有 RC4/白盒 AES 等下一层）。

## PoC

IDA dump：

```python
start = 0x2B2F9171580
size  = 0x327B2
data = ida_bytes.get_bytes(start, size)
open(r"D:\dump.bin", "wb").write(data)
```

循环异或：

```python
xor_key = "bangdreamitsmygo"
data = open("dump.bin", "rb").read()
out = bytes(b ^ ord(xor_key[i % len(xor_key)]) for i, b in enumerate(data))
open("decrypt_dump.bin", "wb").write(out)
# 期望开头：CB 0D 0D 0A（Python 3.12 pyc magic）
```

## 变体与关联

- 变体：密钥不是固定字符串而是运行时由 FNV-1a/哈希/时间派生；需要先在 pyd 中定位 key 生成逻辑。
- 变体：加密不是 XOR 而是 RC4/AES/XXTEA；先识别算法再按密钥解密；见 [[ctf-reverse-pyinstaller-marshal-btea-xxtea-decrypt]]、[[ctf-reverse-pyarmor-pyinstaller-custom-xtea-carlotta]]。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller CArchive/PYZ 提取）。
- 关联：[[code-analysis-reverse-unpacking-python-nested-marshal-consts-chain]]（marshal code object 嵌套还原）。
- 边界：pyd 被 VMProtect/加壳、密钥运行时从网络获取、数据被分片/压缩/多层加密时，需先脱壳或动态跟踪。

## 检测与防御

- 检测：PyInstaller exe 中出现 pyd，pyd 里有大块高熵 bytearray/bytes、`PyNumber_InPlaceXor` 循环、硬编码字符串 key；解密结果出现 pyc magic。
- 防御：不要把密钥硬编码在客户端；对 Python 扩展做签名/完整性校验；使用白盒/多层加密提高逆向成本（但无法阻止动态 dump）。
- 加固：敏感逻辑放服务端；对 pyd 做反调试/反 dump；对内存中的明文/密钥做及时清零。
