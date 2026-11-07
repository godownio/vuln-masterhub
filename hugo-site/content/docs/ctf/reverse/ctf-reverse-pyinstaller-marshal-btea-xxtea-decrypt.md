---
id: ctf-reverse-pyinstaller-marshal-btea-xxtea-decrypt
title: PyInstaller 提取 marshal code object 后逆 XXTEA/btea 分组加密
type: scenario
domain: ctf
path: ctf/reverse
technique: pyinstaller-marshal-btea-xxtea-decrypt
tags:
- ctf
- reverse
- pyinstaller
- marshal
- btea
- xxtea
- tea
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:47:40+08:00'
  notes: 已对照原文 ezPython 节核对：MEI cookie/PYZ-00.pyz/python39.dll、smain 无 pyc 头 marshal code object、btea/MX/rounds=6+52//n、n=4、key 1111222233334444、res 常量、flag 总长 26 取中间 16 字符并 struct.pack 回拼，均与原文 exp 一致。未验证点：PoC 未本机复跑、未实际解包附件；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-pyinstaller-marshal-btea-xxtea-decrypt/
draft: false
kb_aliases:
- PyInstaller + btea
- marshal code object 反编译
- XXTEA 解密
- btea n=-4
- ezPython
---

## 一句话结论

PyInstaller 打包的 Python 程序解包后会得到无 `.pyc` 头的 `marshal` code object；用 `marshal.loads()` + `dis`/反编译还原主逻辑，若发现 `btea(v, n, key)` 与 `MX` 混合函数、`rounds=6+52//n`，就是 XXTEA/btea，把密文按 `n=-4` 反向解密、`struct.pack("<IIII")` 拼回即可还原 flag。

## 原理

- **PyInstaller 结构**：EXE 尾部有 `MEI\x0c\x0b\x0a\x0b\x0e` cookie，指向 CArchive 的 pkg start/TOC；TOC 条目包含 `entry_len`、`data_offset`、`compressed_size`、`uncompressed_size`、`cflag`、`type`、`name`。逐个解析可得到 `smain`、`myalgo`、`crypto`、`PYZ-00.pyz` 等。
- **marshal code object**：`smain` 没有 pyc 的 16 字节头，但内容是 Python 3.9 的 code object（`marshal` 序列化）；`marshal.loads()` 后可用 `dis.dis` 看字节码，或用 `uncompyle6`/`decompyle3`（按 Python 版本）反编译。
- **题目逻辑**：flag 必须以 `LilacCTF{` 开头、`}` 结尾、总长 26，取中间 16 字符；`struct.unpack("<IIII", mid)` 得到 4 个 uint32；调用 `myalgo.btea(inp, 4, key)`；结果要等于常量 `res=[761104570,1033127419,3729026053,795718415]`。
- **XXTEA/btea 识别**：`myalgo` 里有 `MX()` 混合函数、`btea(v,n,key)` 结构、`rounds = 6 + 52 // n`；这是 Block TEA/XXTEA 家族的典型实现。主程序 `n=4`，对 4 个 uint32 加密。
- **解密**：XXTEA 对称；把 `res` 当密文，用同一 key 执行 `n=-4` 的解密（或按加密轮逆序、把加法改成减法）；得到 4 个 uint32 后 `struct.pack("<IIII")` 变回 16 字节，拼回 flag。
- **key**：题目固定 `key = struct.unpack("<IIII", b"1111222233334444")`，即 4 个小端 uint32。

## 触发条件

- 拿到的是 PyInstaller 打包的 PE/ELF（`strings` 可见 `PYZ-00.pyz`、`python39.dll`、`pyimod01_archive`、`MEI` 魔数）。
- 解包后关键模块是无 pyc 头的 marshal code object（`smain`），需要 `marshal.loads`。
- 反编译逻辑中出现 `btea`/`MX`/`rounds = 6 + 52 // n`，且密文/ key 为固定常量。
- 输入长度固定、按 `<IIII` 拆成 32 位字。

## 利用步骤

1. `strings main.exe | grep -i pyinstaller` 确认 PyInstaller；用 `pyinstxtractor` 或按 cookie/TOC 手工解包。
2. 找到 `smain`（marshal code object）、`myalgo`、`crypto`；`marshal.loads(smain)` 后用 `dis`/反编译还原主逻辑。
3. 从 `myalgo` 确认 btea 的 `n`、`rounds`、`MX` 公式、key 字节序和密文常量。
4. 实现解密：`sum = rounds*DELTA`，从最后一轮到第一轮，`v[p] -= MX(y,z,sum,p,e)`，`sum -= DELTA`；或用标准 XXTEA 的 `n=-4` 解密。
5. `struct.pack("<IIII", *plain)` 得到中间 16 字符，拼回 `LilacCTF{...}`。
6. 用给定 `res` 重新加密验证结果（`btea(plain, 4, key) == res`）。

## PoC

```python
import struct

def btea_decrypt(v, k):
    DELTA = 0x9E3779B9
    n = 4
    rounds = 6 + 52 // n
    mask = 0xFFFFFFFF
    def MX(y, z, s, p, e):
        return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4))
                ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z)))
    s = (rounds * DELTA) & mask
    y = v[0]
    while rounds > 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - MX(y, z, s, p, e)) & mask
        z = v[n - 1]
        y = v[0] = (v[0] - MX(y, z, s, 0, e)) & mask
        s = (s - DELTA) & mask
        rounds -= 1
    return v

cipher = [761104570, 1033127419, 3729026053, 795718415]
key = list(struct.unpack("<IIII", b"1111222233334444"))
plain = btea_decrypt(cipher.copy(), key)
print("LilacCTF{" + struct.pack("<IIII", *plain).decode() + "}")
```

说明：PoC 按原文的 `btea_decrypt` 重写；实际需先完成 PyInstaller 解包与 marshal 反编译，未在本机对附件复跑。

## 变体与关联

- **标准 XXTEA**：`btea(v, -4, key)` 的参考实现；注意 key 的字节序（小端 unpack）。
- **TEA/XTEA**：2 个 32 位字的 Feistel，`delta=0x9E3779B9`，轮数 32/64；识别 `MX` 与轮数。
- **PyInstaller 变体**：PyInstaller 5+/6+ 的 CArchive 结构、PYZ 加密、`pyimod` 版本差异；可参考 [[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]。
- **marshal 版本**：Python 3.9/3.10/3.11 的 code object 格式不同，反编译工具需匹配；无法反编译时用 `dis` 读字节码。
- **关联**：[[ctf-crypto-self-referential-key-tea-variant]]（TEA 变体）、[[ctf-reverse-modified-rc4-rounds-sbox]]（另一种自定义流密码）。

## 检测与防御

- PyInstaller 不是保护：`pyinstxtractor` 等工具可稳定解包；敏感逻辑应放 native 扩展/服务端，不要只靠打包。
- 检测：PE/ELF 中出现 `MEI` cookie、`PYZ-00.pyz`、`pyimod` 字符串；对 PyInstaller 木马可进一步提取 marshal 模块做静态分析。
- CTF 防守方：可对 marshal 做自定义加密/混淆，但最终仍需在本地解密，无法从根本上阻止逆向。
