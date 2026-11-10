---
id: code-analysis-reverse-windows-crackme-keyfile-xor-checksum-keygen
title: KeyFile 注册校验：ReadFile 读 18 字节，前 14 字节 XOR 'A'+i 还原用户名，字符和 XOR 0x12345678 比对末 4 字节
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: keyfile-xor-checksum-keygen
tags:
- reverse
- windows
- crackme
- ollydbg
- keyfile
- keygen
- xor
- checksum
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372-fix
  verified_at: '2026-11-09T06:29:31+08:00'
  notes: V372 核对指出调试地址与参数有误：bytesRead 实际在 0x004021A0（原卡 0x402140）、ReadFile Buffer 在 0x00402008（原卡 0x0040600C）；CreateFileA 实际 Access=GENERIC_READ|GENERIC_WRITE、ShareMode=FILE_SHARE_READ|FILE_SHARE_WRITE（原卡简写）。已按图33/34 修正原理与步骤3。核心 XOR/累加/0x12345678 校验与 PoC 不变。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-crackme-keyfile-xor-checksum-keygen/
draft: false
kb_aliases:
- Key 文件注册
- CRACKME3.KEY
- Cruehead-CrackMe-3
- 密钥文件注册机
- CreateFileA ReadFile 注册
- 异或校验 KeyFile
---

## 一句话结论

该 CrackMe 没有注册输入框，而是用 `CreateFileA("CRACKME3.KEY")` + `ReadFile` 读取 18 字节密钥文件：前 14 字节与 `'A'+i` 逐位异或还原用户名并累加字符值，累加和再与 `0x12345678` 异或，结果必须等于文件末 4 字节（小端 DWORD）；按此格式生成 `CRACKME3.KEY` 即可显示 `Good work cracker! Cracked by: <用户名>`。

## 原理

- **KeyFile 注册**：软件启动时打开同目录的许可文件（原文 `CRACKME3.KEY`），读取固定长度内容作为注册凭证；文件不存在/读不满/校验失败则不注册。
- **文件读取链**：`CreateFileA("CRACKME3.KEY", GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, ...)` 打开文件；`ReadFile(hFile, buffer, 0x12, &bytesRead, NULL)` 读 18 字节；随后检查 `bytesRead == 0x12`（原文 `CMP DWORD PTR DS:[4021A0], 0x12` / `JNZ`）。
- **前 14 字节解码**：算法函数对 `buffer[0..13]` 逐字节与 `'A'+i` 异或（i 从 0 开始），还原出用户名各字符；把这些字符的 ASCII 值累加得到 32 位和。
- **末 4 字节校验**：累加和与 `0x12345678` 异或，结果与 `buffer[14..17]` 按小端 DWORD 比较（辅助函数 `MOV ESI,[ESP+4]; ADD ESI,0xE; MOV EAX,[ESI]; RET` 正是读取偏移 14 处的 DWORD）；相等即注册成功。
- **为什么可写注册机**：校验只依赖文件内容与固定常量，无机器绑定/签名；知道用户名即可构造前 14 字节与末 4 字节。
- **文件名/长度固定**：读取长度 0x12 与文件名是硬编码，keyfile 必须正好 18 字节可读。

## 触发条件

- 目标为本地 Windows 32 位 GUI 程序（原文 `Cruehead-CrackMe-3.exe`，12KB，CrackMe v3.0），无注册对话框，启动/点击时读取同目录 KeyFile。
- 客户端完成校验，无壳/无反调试，可用 OllyDbg 对 `CreateFileA`/`ReadFile` 下断。
- 能向程序目录写入自定义 `CRACKME3.KEY`。

## 利用步骤

1. 运行程序确认无注册框（File/Help/About 菜单），推测 KeyFile 注册；在程序目录创建任意 `CRACKME3.KEY` 便于断点命中。
2. 导入 OllyDbg，`Ctrl+N` 找到 `CreateFileA`/`ReadFile` 下断；F9 运行，命中 `CreateFileA` 时查看 `FileName` 参数为 `CRACKME3.KEY`。
3. 继续到 `ReadFile`，记录缓冲区地址（原文 `0x00402008`）与读取长度 `0x12`，并注意 `bytesRead` 位于 `0x004021A0`；执行后确认 `bytesRead == 0x12`。
4. F7 跟进自定义算法函数（原文 `0x00401311`）：确认循环 i=0..13 的 `XOR 'A'+i` 与字符累加；返回主程序后确认 `XOR 0x12345678`。
5. 跟进取末 4 字节的函数（原文 `0x0040133C`，`[buffer+0xE]` 的 DWORD）与最终比较分支。
6. 写注册机：用户名补齐/截断到 14 字符 → 逐字节 `username[i] ^ ('A'+i)` 写入前 14 字节 → `sum(username chars) ^ 0x12345678` 按小端写入末 4 字节 → 保存 18 字节 `CRACKME3.KEY`，运行程序验证。

## PoC

最小 Python 注册机（原文 C++ 等价复写）：

```python
name = "123456789ABCDE"[:14].ljust(14, " ")  # 原文最长 14 位，不足补空格
data = bytes((ord(name[i]) ^ (ord('A') + i)) & 0xFF for i in range(14))
key = (sum(ord(c) for c in name) & 0xFFFFFFFF) ^ 0x12345678
open("CRACKME3.KEY", "wb").write(data + key.to_bytes(4, "little"))
```

原文验证：用户名 `123456789ABCDE` 生成 keyfile 后，程序弹出 `Good work cracker! Cracked by: 123456789ABCDE! Now try the next crackme!`。

## 变体与关联

- 变体：文件名/长度/常量替换；异或键改为固定字节或索引变换；校验和改为 CRC32/MD5；末 4 字节可改为明文比较或签名。
- 关联：[[code-analysis-dynamic-debugging-ini-config-xor-add-decrypt-api-breakpoint]]（CreateFileA/ReadFile 断点锁定加密配置）、[[code-analysis-reverse-windows-winhex-license-crc32-keygen]]（许可证/CRC32 校验）、[[code-analysis-reverse-windows-keygenme-name-char-delta-serial]]（另一种 Name→Serial 校验）。
- 边界：若 KeyFile 还包含机器绑定/签名，单纯字符和校验不足以伪造；若文件读取长度或路径受保护，需要相应调整。

## 检测与防御

- **逆向检测（防守方视角）**：固定格式 KeyFile + 可逆异或/校验和属于“可伪造许可证”，任何人可写 keygen。
- **加固**：许可证使用非对称签名（私钥服务端保存），客户端只验签；绑定用户/机器信息并加入有效期/功能位；避免把全部校验逻辑放在客户端。
- **审计线索**：无注册框、`CreateFileA` 打开固定文件名、`ReadFile` 固定长度、随后出现 XOR/累加与 DWORD 比较，是 KeyFile 注册的典型特征。
