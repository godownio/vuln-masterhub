---
id: code-analysis-reverse-windows-wineloader-double-rc4-config-extract
title: WINELOADER 变种双层 RC4 配置恢复：0x8028 shellcode 首层解密 + 0x20 处 key 与 3 字节轮询间隔的二次字符串表
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: wineloader-double-rc4-config-extract
tags:
- reverse-engineering
- malware-analysis
- wineloader
- apt29
- rc4
- config-extraction
- shellcode
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V443
  verified_at: '2026-11-09T23:11:44+08:00'
  notes: 对照原文图10-15与正文：导出函数入口 mov rdx,8028h + call 解密例程（图10/11）、首层 RC4 密文跟随导出函数后（图12/14）、CyberChef 首层解密（图13）、首层 blob 结构=头部3字节C2轮询间隔+偏移0x20处32字节key（与首次 key 一致）+密文长度+密文（图15）、二次 RC4 得到 明文:密文 字符串表（模块/API/C2/UA/POST/管道/主机指纹）均与卡一致；原文 hex 块标注为 KEY 实为 key+首层密文的内存 dump（图15 标注 key 32 字节后即密文，长度字段 0xE0），卡按 32 字节 key 描述正确。PoC 注明字节序/偏移按样本对齐，合理。dedup 候选为 Dridex/Godot/假 v2ray 等单层或嵌密钥 RC4 卡，非同一条链（本卡为双层结构与偏移 key）。未验证点：C2 已失效，未复跑解密；key/偏移随样本变化。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-wineloader-double-rc4-config-extract/
draft: false
kb_aliases:
- WINELOADER 配置解密
- APT29 WINELOADER
- 双层 RC4 shellcode
- 0x8028 RC4
- 明文密文字符串表
- C2 轮询间隔提取
---

## 一句话结论

WINELOADER 变种的加载器在恶意 DLL 的导出函数里用硬编码 32 字节 RC4 key 解密长度 `0x8028` 的 shellcode；解出的第一层数据不是明文，而是"3 字节 C2 轮询间隔 + 偏移 0x20 处 32 字节 RC4 key + 密文长度 + 密文"的结构，用同一 key 再做一次 RC4 才得到字符串/配置表（API 名、`user32.dll`/`wininet.dll` 等模块、C2 域名与 `/auth.php` 路径、Chrome UA、POST、命名管道等），据此可完整还原加载器的通信与能力。

## 原理

- **第一层：导出函数里的 shellcode 解密**：恶意 `vcruntime140.dll` 的导出函数（如 `memset`，另一变种为 `_set_se_translator`）入口即调用 RC4 解密例程，密文长度硬编码为 `0x8028`，密钥为 64 个十六进制字符（32 字节），存放在恶意导出函数之后的数据区；解密后把结果写入全局并跳转执行。
- **第二层：配置/字符串表再加密**：首次解密得到的 blob 不是最终明文。其结构为：
  - 头部 3 字节：C2 轮询间隔；
  - 偏移 `0x20`：32 字节 RC4 key（与首次解密 key 一致）；
  - 其后：密文长度 + 密文段。
  用该 key 对这层密文再做 RC4，得到明文表。
- **明文表的内容**：文章以"明文: 密文"形式列出各项，覆盖加载器所需的一切：模块名（`user32.dll`、`rpcrt4.dll`、`bcryptprimitives.dll`、`kernelbase.dll`、`ole32.dll`、`mscoree.dll`、`shlwapi.dll`、`wininet.dll`、`iphlpapi.dll`、`advapi32.dll`、`ntdll.dll`、`kernel32.dll`）、API（`VirtualProtect`、`CreateThread`、`LoadLibraryW`、`Sleep`、`FindFirstFileW`、`InternetOpenW`/`InternetConnectW`/`HttpOpenRequestW`/`HttpSendRequestW`/`InternetReadFile`、`CreateNamedPipeW`、`OpenProcessToken`/`GetTokenInformation`、`GetUserNameW`/`GetComputerNameW`、`NtMapViewOfSection` 等）、字符串（C2 域名、`/auth.php`、Chrome/115 UA、`POST`、`\\.\pipe\`、`Updated agent`）。
- **能力画像**：由表可推断加载器通过 WinINet 以 POST+浏览器 UA 回连 C2 拉取下一阶段；用命名管道做进程间通信；读取用户名/计算机名/令牌信息用于主机指纹；具备文件枚举与 Section 映射能力。
- **为什么这样设计**：单层 RC4 解出的 shellcode 仍会被内存扫描按明文 API/URL 命中；把关键字符串再加密一层，且 key 藏在首层结构的固定偏移，静态分析必须先完整复现两层解密才能看到配置。

## 触发条件

- 已获得样本（恶意 DLL/加载器）或内存中的解密前 blob。
- 已定位恶意导出函数与硬编码 key（可在导出函数尾部数据区、IDA 交叉引用或调试器内存中找）。
- 能复现 RC4（标准算法，key 32 字节）并按结构解析第二层。

## 利用步骤

1. 在 IDA/x64dbg 中定位恶意导出函数（如 `memset`）入口，观察 `mov rdx, 8028h` 与调用解密例程的模式。
2. 从导出函数后的数据区提取 32 字节 RC4 key（64 hex）。
3. 对 `0x8028` 字节密文做第一次 RC4，得到 blob。
4. 解析 blob：读前 3 字节为轮询间隔；取偏移 `0x20` 起 32 字节为第二层 key；按样本格式读密文长度与密文段。
5. 用第二层 key 再做 RC4，得到明文表；把"明文: 密文"条目映射为模块/API/字符串/配置。
6. 从表中提取 C2 域名、路径、UA、管道名与主机指纹相关 API，形成 IOC 与能力清单；结合网络流量与内存验证。

## PoC

```python
from Crypto.Cipher import ARC4

key = bytes.fromhex("替换为导出函数后提取的 64 位 hex key")
ct = open("shellcode.bin", "rb").read()          # 长度 0x8028
blob = ARC4.new(key).decrypt(ct)

interval = int.from_bytes(blob[:3], "little")    # C2 轮询间隔（按样本对齐字节序）
key2 = blob[0x20:0x40]                           # 第二层 32 字节 key
# 其后为密文长度 + 密文段；按样本解析后：
# table = ARC4.new(key2).decrypt(inner_ct)
print(interval, key2.hex())
```

说明：偏移与长度字段的字节序/宽度以样本为准；文章给出的是 `0x8028` 长度、偏移 `0x20` key、头部 3 字节间隔的结构。

## 变体与关联

- 变体：首层可用 CyberChef 的 RC4 recipe 快速验证（key 为 hex），再把输出按结构切分做第二次 RC4。
- 变体：不同 WINELOADER 样本的 key/长度/偏移会变，但"导出函数→RC4→结构体→二次 RC4 字符串表"的模式一致。
- 关联：[[pentest-c2-sqldumper-vcruntime140-export-memset-sideload]]（本卡的加载器与导出函数入口）；[[pentest-initial-access-hta-certutil-tar-signed-exe-chain]]（样本投递链）；[[code-analysis-reverse-obfuscation-warmcookie-rc4-string-record]]（RC4 字符串记录结构）；[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（RAT 配置提取对照）；[[code-analysis-reverse-windows-dridex-c2-table-signature-extraction]]（C2 表提取对照）。

## 检测与防御

- 检测：内存/文件中出现 `0x8028` 长度常量 + RC4 初始化（256 字节 S 盒）+ 32 字节高熵 key 的组合；导出函数内部出现解密循环后跳转私有内存。
- 检测：进程通过 WinINet 以 Chrome UA POST 到新注册/失陷域名（如 `*/auth.php`）；命名管道名异常；读取用户/计算机名后立即外联。
- 防御：对内存中的高熵 blob 与 RC4 特征做扫描；封锁已知 C2 域名/路径与 UA 组合；监控白程序加载异常运行库后的网络行为；样本侧可用 YARA 匹配 `0x8028` 与 key 结构。
- 局限：C2 已失效时只能做静态配置还原，无法验证后续载荷；key/偏移随样本变化，需要按样本重新定位。
