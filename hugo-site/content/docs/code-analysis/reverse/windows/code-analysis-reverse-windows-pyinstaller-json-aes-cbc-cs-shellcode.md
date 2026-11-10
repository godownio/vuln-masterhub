---
id: code-analysis-reverse-windows-pyinstaller-json-aes-cbc-cs-shellcode
title: PyInstaller 3.10 Cobalt Strike 样本：1.json 双字段 code/load 经 AES-CBC(key=IV) 解密，ctypes RWX 内存加载 CS shellcode 并静态提取 C2/URI/UA
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pyinstaller-json-aes-cbc-loader-cs-shellcode-ioc
tags:
- reverse
- windows
- pyinstaller
- python
- aes-cbc
- shellcode
- cobalt-strike
- malware-analysis
- ioc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T14:37:57+08:00'
  notes: 已对照原文及19张图核验：1.json code/load 双字段、key=IV 的 AES-128-CBC+PKCS7+base64、dfhkAsDFAjDShdfu、VirtualAlloc(0x3000,0x40)/RtlMoveMemory/CreateThread/WaitForSingleObject、shellcode 头 fc 48 83 e4 f0、C2 119.29.82.40、/QlXH、MSIE 8.0 UA、情报平台 CobaltStrike 关联（标签已过期）均与原文/图一致。与同篇 pycdas 卡互补不重复，与滚动XOR/XXTEA等既有样本卡不同链路。小问题：标题写『PyInstaller 3.10』易被读成打包器版本，原文实际为 PyInstaller 2.1+ 打包、Python 3.10（正文已写清）；样本专属 IOC 卡保留价值有限但成立。原文未标受影响版本，不设 affected_versions。dup-scan(11-08)早于建卡。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pyinstaller-json-aes-cbc-cs-shellcode/
draft: false
kb_aliases:
- PyInstaller CS 样本分析
- JSON code load 双载荷
- AES-CBC key 与 IV 相同
- ctypes VirtualAlloc shellcode
- CS reverse https x64
- 面试题样本分析
---

## 一句话结论

该样本是 PyInstaller（Python 3.10）打包的 EXE 加同目录 `1.json`：入口 pyc 读取 JSON 中 `code`/`load` 两个 base64 字段，用硬编码字符串 key（同时充当 IV）的 AES-CBC 解密——`code` 解出十六进制 shellcode，`load` 解出 Python loader 源码并 `exec`；loader 用 ctypes 调 `VirtualAlloc(RWX)`/`RtlMoveMemory`/`CreateThread` 在内存中执行 shellcode，shellcode 为 Cobalt Strike reverse https x64，C2 `119.29.82.40`、URI `/QlXH`、UA 为 `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)`。

## 原理

- **样本布局**：一个 PyInstaller 打包的 Windows EXE（约 7 MB）与一个 3 KB 的 `1.json`；JSON 只有两个字段 `code` 与 `load`，值都是长 base64 串，分别承载 shellcode 与 loader。
- **入口 pyc 逻辑**：`import aesdecypto, json, ctypes`；`open('1.json')` 读取后 `json.loads`，取 `load`、`code`；硬编码 `aes_key = 'dfhkAsDFAjDShdfu'`（16 字符）；`code = aesdecypto.decrypt(aes_key, code)` 得到十六进制字符串，再 `bytes.fromhex(code)` 还原 shellcode 字节；`load = aesdecypto.decrypt(aes_key, load)` 得到 Python 源码，`exec(load)` 执行。
- **加密实现**：`aesdecypto.decrypt(key, content)` 中 `key_bytes = bytes(key,'utf-8')`、`iv = key_bytes`，`AES.new(key_bytes, AES.MODE_CBC, iv)` 后 `base64.b64decode(content)` 解密，再 PKCS7 去填充；即 AES-128-CBC、key 与 IV 相同、密文 base64 封装。加密函数对称，key 直接写死在 pyc 常量里。
- **loader 行为**：解密出的 loader 是一段 ctypes 脚本：`VirtualAlloc(0, len(code), 0x3000, 0x40)`（MEM_COMMIT|MEM_RESERVE，PAGE_EXECUTE_READWRITE），`RtlMoveMemory` 把 `code` 复制到该 RWX 页，`CreateThread(0, 0, rwxpage, 0, 0, 0)` 创建线程执行，`WaitForSingleObject(handle, -1)` 等待结束；`code` 由主脚本 `exec` 后的全局变量提供。
- **shellcode 分析**：反汇编可见 PEB 遍历、API 解析等典型位置无关代码；x64dbg 在 `WinINet` 相关调用处可看到 C2 IP `119.29.82.40`、请求路径 `/QlXH`、伪造的 `User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)`，并循环发起 HTTP 请求等待返回；自动化脚本按字符串特征将其识别为 `CS reverse https x64 shellcode`。
- **威胁情报关联**：该 IP 在威胁情报平台被标记为 IDC/CDN 服务器，历史上与 `MalGeneric.CobaltStrike` 恶意样本家族关联，并被打过 `CobaltStrike木马` 标签（记录已过期但可作旁证）。
- **为什么可行**：密钥硬编码在客户端 pyc 中、key 与 IV 相同、算法是标准库/公开实现，攻击者只能提高逆向成本；分析者拿到 EXE+JSON 后按 pyc 字节码还原算法即可离线解密全部载荷。

## 触发条件

- 拿到成对的 PyInstaller EXE 与同目录 JSON 配置（JSON 内为两段以上长 base64 值）。
- 能解包 EXE（Python 版本可识别；反编译器失败时可用 pycdas/dis 读字节码）。
- 分析在隔离环境进行，不直接运行样本；需要离线解密而非动态执行。

## 利用步骤

1. 目录识别：EXE 与 `1.json` 成对出现，JSON 字段名如 `code`/`load`，值为长 base64；用 DIE 确认 EXE 为 PyInstaller 打包、查看 Python 版本。
2. `pyinstxtractor` 解包，定位入口 pyc（如 `ma.pyc`）；pycdc 失败时用 `pycdas` 反汇编，从 `[Constants]` 取硬编码 key，按 `LOAD_NAME/LOAD_METHOD/CALL_METHOD` 还原 `decrypt`/`bytes.fromhex`/`exec` 流程。
3. 按还原出的 AES-CBC（key=IV、PKCS7、base64）离线解密 `code` 与 `load`；`code` 先去 base64 解密再 `fromhex` 得到 shellcode 字节。
4. 阅读解密出的 `load` 源码，确认 loader 的 API 调用（VirtualAlloc/RtlMoveMemory/CreateThread 等）与执行方式。
5. 对 shellcode 做静态分析：提取可打印字符串/API 调用，定位 C2 IP、URI、User-Agent、请求循环；必要时在调试器中在 `WinINet`/`HttpOpenRequestA` 等调用处断下确认。
6. 用威胁情报平台关联 IP/URI 与样本哈希，确认家族（如 Cobalt Strike）；记录 IOC 供检测规则使用。

## PoC

```python
# 按反编译/字节码还原的 aesdecypto 逻辑离线解密（未在本机执行样本）
import base64, json
from Crypto.Cipher import AES

key = b"dfhkAsDFAjDShdfu"          # 来自入口 pyc 常量表

def dec(content: str) -> bytes:
    raw = AES.new(key, AES.MODE_CBC, key).decrypt(base64.b64decode(content))
    return raw[:-raw[-1]]          # PKCS7 去填充

data = json.load(open("1.json", "r"))
shellcode = bytes.fromhex(dec(data["code"]).decode())
loader_src = dec(data["load"]).decode()
print(shellcode[:16].hex())        # fc 48 83 e4 f0 ...（CS shellcode 头）
print(loader_src)                  # ctypes VirtualAlloc/RtlMoveMemory/CreateThread loader
```

```text
# shellcode 静态特征（strings/自动化脚本）
119.29.82.40
/QlXH
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)
```

## 变体与关联

- **同思路变体**：外层可能是 AES-CBC、RC4、XOR 或组合；密钥可能来自 pyc 常量、环境变量或与 C2 协商；JSON 字段名与载荷段数会变化，应以字节码还原为准。
- **loader 变体**：除 `VirtualAlloc/RtlMoveMemory/CreateThread` 外，还可能用 `NtCreateThreadEx`、回调函数、APC、线程池等执行方式。
- **CS 配置提取**：确认是 CS shellcode 后，可用 1768.py 等工具解析 stager/beacon 配置，参考 [[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]；本卡的 IP/URI/UA 是直接静态提取。
- **PyInstaller 相关**：解包细节见 [[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]；反编译失败兜底见 [[code-analysis-reverse-unpacking-pycdas-constants-key-disassembly]]；同类 PyInstaller 木马流量解密见 [[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（该卡为 ELF + AES-GCM 流量，机制不同）。
- **其他 CS shellcode 分析**：[[code-analysis-reverse-windows-shellcode-rolling-xor-embedded-cs-pe]]、[[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]。

## 检测与防御

- 检测：PyInstaller EXE 与同名/同目录 JSON 成对出现，JSON 含两段以上长 base64 字段；pyc 中出现 `aesdecypto`/`decrypt`/`fromhex`/`exec` 与小写 16 字节 key 常量。
- 检测：Python 进程通过 ctypes 调 `VirtualAlloc` 申请 RWX 页并 `RtlMoveMemory`+`CreateThread`；这是进程内执行 shellcode 的强特征。
- 检测：内存/流量中出现 `119.29.82.40`、URI `/QlXH`、`User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)` 等 IOC；结合威胁情报与 YARA 规则批量排查。
- 防御：终端限制脚本解释器/未知 EXE 执行与出站连接；对 PyInstaller 样本做沙箱与解包审计；封锁 C2；轮换可能泄露的凭据。
