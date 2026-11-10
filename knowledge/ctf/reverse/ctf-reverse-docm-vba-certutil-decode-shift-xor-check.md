---
id: ctf-reverse-docm-vba-certutil-decode-shift-xor-check
title: DOCM 宏用 certutil -decode 释放 PE：olevba 提取宏 + 位移 6/异或 7 校验逆运算
type: scenario
domain: ctf
path: ctf/reverse
technique: docm-vba-certutil-decode-shift-xor-check
aliases:
- docCrack
- certutil -decode 释放 exe
- DOCM 宏释放 PE
- 位移 6 异或 7
- olevba 宏分析
- VBA LOLBin
tags:
- ctf
- reverse
- docm
- vba
- certutil
- lolbin
- pe
- shift
- xor
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:40+08:00'
  notes: 已对照原文 docCrack 段与图 42 核对：DOCM 宏 olevba 提取、temp.temp/temp.exe、certutil -decode temp.temp temp.exe、WScript.Shell 执行、exe 中 v7[j+64]=argv[1][j]<<6 与常量比较均一致；用卡内 enc 数组实跑 (v>>6)^7 得 DASCTF{Vba_1s_dangerous!!!_B1ware_0f_Macr0_V1ru5es!!!}，与原文一致。
---

## 一句话结论

DOCM 宏把内嵌数据写成 `temp.temp` 和批处理，用系统自带签名工具 `certutil -decode temp.temp temp.exe` 释放并运行 PE；用 `olevba` 提取宏后，逆向释放出的 exe 可看到校验循环 `enc[j] = (input[j] ^ 7) << 6`，对常量数组执行 `chr((enc[j] >> 6) ^ 7)` 即可还原 flag。

## 原理

- **DOCM 与 VBA 提取**：`.docm` 本质是 OOXML ZIP，宏源码保存在 `word/vbaProject.bin`（OLE 复合文档）。`olevba`/`oletools` 可静态提取 VBA 源码、字符串和自动执行入口（`AutoOpen`/`Document_Open`），无需打开文档或启用宏。
- **certutil 作为 LOLBin**：`certutil` 是 Windows 自带的签名工具，`-decode` 子命令把 Base64 文件解码为二进制。宏用 `WScript.Shell` 执行批处理：`cd /d <文档目录>`、`certutil -decode temp.temp temp.exe`、`temp.exe ...`、`del`。因为调用的是系统可信工具，可绕过“禁止 PowerShell/下载器”的简单策略，也不需要网络下载。
- **释放与校验**：宏把编码后的数据/字符串写入 `temp.temp`，certutil 解码得到 `temp.exe`；exe 检查 `argc==2` 和输入长度（54），然后执行 `v7[j+64] = argv[1][j] << 6` 并与常量数组逐项比较。编码侧的变换等价于 `enc = (char ^ 7) << 6`，所以逆运算为 `char = (enc >> 6) ^ 7`。
- **为什么成立**：certutil 的 `-decode` 是确定性的 Base64 解码；校验只是可逆的位移+异或，没有哈希/密钥；常量数组可从 exe 的 `.data` 直接提取，因此完全静态可解。

## 触发条件

- 拿到 `.docm`/`.doc`/`.xlsm` 等含宏的 Office 文档，宏中出现 `certutil`、`-decode`、`temp.temp`、`WScript.Shell`、`Shell` 等字符串。
- 文档目录/临时目录释放出 PE 或批处理文件；exe 接受一个命令行参数并做长度/常量比较。
- 分析环境允许解压与静态反汇编，不需要执行宏或 exe。
- 校验变换是位移、异或、加减等可逆运算（常数可从二进制提取）。

## 利用步骤

1. 用 `olevba` 提取宏：`olevba suspicious.docm`，重点看 `AutoOpen`、`Shell`、`CreateTextFile`、`certutil`、`temp.temp`、`temp.exe`。
2. 解包 DOCM（改后缀为 `.zip`）检查 `word/vbaProject.bin` 与嵌入对象；从宏字符串/文件中提取 `temp.temp` 的编码数据（Base64/十六进制）。
3. 静态解码 `temp.temp`（`certutil -decode` 等价于 Base64 解码）得到 PE；不要直接运行。
4. 用 IDA/Ghidra 分析 PE：定位 `main`、`argc/argv` 使用、`strlen` 长度检查、常量数组与比较循环。
5. 提取常量数组，按逆变换 `chr((enc[j] >> 6) ^ 7)` 还原输入；若还有其他变换（rot13、加减、异或常量），按代码逆序处理。
6. 用原 exe 的校验逻辑正向复算，确认结果匹配；若 exe 有反调试/花指令，先静态 patch 或模拟校验函数。

## PoC

```python
enc = [
    4288, 4480, 5376, 4352, 5312, 4160, 7936, 5184, 6464, 6528,
    5632, 3456, 7424, 5632, 6336, 6528, 6720, 6144, 6272, 7488,
    6656, 7296, 7424, 2432, 2432, 2432, 5632, 4416, 3456, 7168,
    6528, 7488, 6272, 5632, 3520, 6208, 5632, 4736, 6528, 6400,
    7488, 3520, 5632, 5184, 3456, 7488, 7296, 3200, 6272, 7424,
    2432, 2432, 2432, 7808,
]
print("".join(chr((v >> 6) ^ 7) for v in enc))
```

```text
# 输出：
# DASCTF{Vba_1s_dangerous!!!_B1ware_0f_Macr0_V1ru5es!!!}
```

## 变体与关联

- **certutil 变体**：`-decode`（Base64）、`-decodehex`（十六进制）、`-urlcache -split -f`（下载）；也可能用 `mshta`、`regsvr32`、`rundll32` 等 LOLBin 替代。
- **载荷释放变体**：宏直接写 exe 字节、写入 `%TEMP%`/文档目录、用 `WScript.Shell.Run` 隐藏执行；也可释放 DLL 由 `rundll32` 加载。
- **校验变体**：位移方向/位数、异或常量、加减、rot13、字符交换、数组下标变换；按二进制逐指令复刻，不要假设是标准算法。
- **宏隐藏变体**：VBA stomping（源码与 p-code 不一致）、宏密码保护、仅 p-code；需要 `olevba`/`pcode` 或动态调试。
- **关联卡片**：[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（DOCM 宏 Base64+XOR 下载器）、[[ctf-forensics-docm-vba-xor-powershell-encodedcommand-deflate]]（宏三段载荷）、[[ctf-forensics-docm-vba-project-password-dpb-bypass]]（宏工程密码绕过）、[[pentest-initial-access-lolbins-signed-tool-download-exec]]（certutil 等 LOLBin 下载执行）。
- **边界**：exe 使用哈希/非对称签名校验、宏释放的载荷被加密且密钥不在文档内、或宏被完全剔除仅剩 p-code 时，静态逆运算可能不成立，需要动态分析/沙箱。

## 检测与防御

- **终端**：默认禁用宏/仅启用签名宏；对来自 Internet 的文档启用 Mark-of-the-Web/受保护视图；监控 Office 进程拉起 `certutil.exe`、`cmd.exe`、`wscript.exe` 以及临时目录新 PE 的执行。
- **邮件/网关**：拦截/沙箱分析含宏文档；扫描 `vbaProject.bin` 中的 `certutil`、`-decode`、`temp.exe`、`WScript.Shell` 等特征；限制 `%TEMP%` 可执行文件的运行。
- **检测信号**：`certutil -decode` 后紧跟同目录 exe 执行并自删除；DOCM 文档目录出现 `temp.temp`/`temp.exe`/`.bat`；宏中包含 `CreateTextFile` + `Shell` 组合。
- **分析规范**：优先静态解包与反汇编，不在分析机启用宏或运行释放的 PE；需要动态时使用隔离沙箱与网络模拟。
