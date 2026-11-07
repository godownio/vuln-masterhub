---
id: code-analysis-reverse-obfuscation-pyarmor-static-unpack-aes-ctr
title: Pyarmor 静态脱壳：Pyarmor-Static-Unpack-1shot 解析 runtime AES-CTR 密钥批量还原源码
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: pyarmor-static-unpack-aes-ctr
aliases:
- Pyarmor-Static-Unpack-1shot
- pyarmor 1shot 静态脱壳
- pyarmor_runtime AES key
- BCC 段解密
- Python 混淆还原
- shot.py 去混淆
tags:
- python
- pyarmor
- obfuscation
- deobfuscation
- unpacking
- aes-ctr
- runtime-key
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:50:03+08:00'
  notes: 已对照原文shot.py源码与图02核对：RuntimeInfo/runtime_aes_key、data[20:24]==9判BCC、data[28:32]/[32:36]密文偏移长度、nonce=data[36:40]+data[44:52]、AES-CTR initial_value=2、BCC段0x2001/0x2003拆分、.1shot.seq标记(\xa1/\xa2/\xf0\xff)、pycdc反编译后搜索flag均与源码一致；图02确认输出flag{po2iso3ning_su4cess5fully_triggered}；dedup候选为PyInstaller/XTEA等不同案例
---

## 一句话结论

Pyarmor 混淆的 Python 脚本把 code object 用运行时密钥加密，`pyarmor_runtime` 中保存 serial number 与 AES 密钥；用 `Pyarmor-Static-Unpack-1shot` 对目标目录执行 `python shot.py <dir>`，工具会自动识别 runtime、按文件头定位密文偏移/长度与 nonce、用 AES-CTR（`initial_value=2`）解密 BCC 段和主密文，生成 `.1shot.seq` 并调用 pycdc 反汇编/反编译，即可批量还原出可读源码并搜索 flag。

## 原理

- **Pyarmor 的静态保护**：脚本被改写为“引导 + 加密 code object”，运行时由 `pyarmor_runtime` 动态解密；加密数据与 runtime 一起分发，因此离线也能拿到解密所需的密钥材料。
- **runtime 解析**：`RuntimeInfo` 从 `pyarmor_runtime[.pyd|.so|.dylib]` 中读取 serial number 与 `runtime_aes_key`，并生成与 nonce 混合的 `mix_str_aes_nonce()`；同一目录下可能有多个 runtime，工具按 serial number 建索引。
- **文件头与 BCC 段**：工具用固定偏移解析每个被保护文件：`data[20:24]`（小端）等于 9 表示存在 BCC 段；密文偏移在 `data[28:32]`、长度在 `data[32:36]`；nonce = `data[36:40] + data[44:52]`。BCC 解密后按 `segment_offset/segment_length/architecture_id/next_segment_offset` 逐段切出 native 部分（0x2001=dll、0x2003=so）。
- **AES-CTR 解密**：`general_aes_ctr_decrypt(data, key, nonce)` 使用 `AES.MODE_CTR(nonce=nonce, initial_value=2)`；主密文按上述偏移/长度解密后，与原始头部/尾部拼成 `.1shot.seq`（写入 `\xa1 + runtime_aes_key`、`\xa2 + mix_str_aes_nonce()`、`\xf0\xff` 等标记）。
- **反编译**：工具调用平台对应的 `pyarmor-1shot`/pycdc 可执行文件读取 `.1shot.seq`，反汇编/反编译为 Python 源码；遇到不支持的 opcode 时输出错误但通常仍能导出部分源码与常量。
- **为什么能拿到 flag**：题目把 flag 作为常量或字符串放在被保护的 Python 代码中；解密后反编译文本中直接出现 `flag{...}`，`ctrl-f flag` 即可定位。

## 触发条件

- 目标为 Pyarmor 保护的 Python 程序/目录，且能取得 `pyarmor_runtime` 文件（与加密脚本一起分发）。
- 能运行 `Pyarmor-Static-Unpack-1shot`（或其 `pyarmor-1shot`/pycdc 可执行文件）并读取目标目录。
- 加密文件不是被额外二次加密/加壳（如再套 PyInstaller），或已先用 pyinstxtractor 等工具解包。
- 反编译结果可能不完整，但常量/字符串（如 flag）通常能被导出。

## 利用步骤

1. 收集目标目录，确认存在 `pyarmor_runtime` 与被保护的 `.py`/`.pyc`/`.pyz` 文件。
2. 获取 `Pyarmor-Static-Unpack-1shot`，按平台准备 `pyarmor-1shot` 可执行文件（或 `-e` 指定）。
3. 运行 `python shot.py <目标目录> -o <输出目录> --show-all`；工具会遍历目录、识别 runtime、解析每个文件的加密头。
4. 对存在 BCC 段的文件，工具先解出 `.1shot.bcc.dll/so`，再解密主密文并生成 `.1shot.seq`。
5. 等待 pycdc 反编译完成，在输出目录中搜索 `flag`、`secret`、`password` 等关键字；必要时对不完整文件用 `--export-raw-data` 导出原始数据再用其他反编译器处理。
6. 结合反编译源码还原业务逻辑/密钥，完成题目或分析。

## PoC

```bash
# 目录模式：工具自动发现 pyarmor_runtime 与受保护文件
python shot.py ./challenge -o ./out --show-all

# 单文件模式需显式指定 runtime
python shot.py ./challenge/main.py -r ./challenge/pyarmor_runtime.so -o ./out
```

关键解密参数（来自工具源码，供自实现参考）：

```python
from Crypto.Cipher import AES

def general_aes_ctr_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=2)
    return cipher.decrypt(data)

# 头部解析
cipher_text_offset = int.from_bytes(data[28:32], 'little')
cipher_text_length = int.from_bytes(data[32:36], 'little')
nonce = data[36:40] + data[44:52]
plain = general_aes_ctr_decrypt(
    data[cipher_text_offset:cipher_text_offset + cipher_text_length],
    runtime.runtime_aes_key,
    nonce,
)
```

说明：原文在 CTF 题中对 pyarmor 加密目录运行 `python shot.py`，得到三个文件，在第二个文件的 pycdc 输出中搜索到 `flag{...}`。工具源码较长，这里只保留与解密格式相关的关键逻辑；未在本机复跑。

## 变体与关联

- **PyInstaller + pyarmor 组合**：[[ctf-reverse-pyarmor-pyinstaller-custom-xtea-carlotta]] 覆盖 PyInstaller 解包后 pyarmor-1shot 还原源码、再逆自定义 XTEA/RC4-like 的案例；本卡聚焦 Pyarmor 静态脱壳本身的 runtime/AES-CTR 格式。
- **PyInstaller 提取 pyc**：[[code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object]] 处理 PyInstaller 打包与 pyd 内嵌 marshal 的还原，可作为前置步骤。
- **动态 dump 替代**：若静态工具失败，可在运行时 dump 解密后的 code object/内存；或在有 `pyarmor_runtime` 调试符号时直接 hook 解密函数。
- **边界**：目标若使用更高版本 Pyarmor 的新保护模式、runtime 被剥离、或加密文件被二次加壳，`shot.py` 可能无法识别；需要动态分析或升级工具。

## 检测与防御

- 防御：Pyarmor 等混淆只是提高逆向成本，不是安全边界；敏感逻辑/密钥不应放在客户端 Python 代码中，应放到服务端或使用硬件/服务端授权。
- 防御：对分发的 runtime 做完整性校验与 license 绑定；定期升级 Pyarmor 并使用其最新保护选项，但不要依赖其保密性。
- 检测：监控对 `pyarmor_runtime` 的静态解析、`.1shot.seq`/`.1shot.bcc.*` 等工具产物；若为软件保护场景，可检测批量反编译/调试行为。
- 响应：若密钥/算法因脱壳泄露，轮换密钥、更新客户端保护方案，并评估被还原的业务逻辑带来的风险。
