---
id: code-analysis-dynamic-debugging-serial-data-constraint-memory-proximity
title: 序列号数据约束性搜索：在假注册码 ±0x90 内存范围用 WinHex/OllyDbg 找真序列号（TraceMe 12121212→2470）
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: serial-data-constraint-password-proximity-memory-search
tags:
- reverse
- crackme
- serial
- license
- memory-search
- ollydbg
- winhex
- data-constraint
- password-proximity
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T07:51:35+08:00'
  notes: 已对照原文与3张图核对：±0x90（原文±90h）数据约束性/密码相邻性、TraceMe 用户名pediy+假序列号12121212、错误框不关闭、WinHex RAM Editor/OllyDbg Alt+M+Ctrl+B 搜索、图01/03可见12121212与2470相邻均一致；无CVE/版本，未设versions。PoC为工具操作步骤，未在本机复跑。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-serial-data-constraint-memory-proximity/
draft: false
kb_aliases:
- 数据约束性
- 密码相邻性
- Data constraint
- Password proximity
- TraceMe
- WinHex RAM Editor
- OllyDbg Ctrl+B
- 真序列号附近
---

## 一句话结论

很多序列号校验程序会把用户输入的假注册码和运行时算出的真注册码/中间结果放在同一个栈帧的局部变量里；在程序完成校验但错误提示框尚未关闭时，用 WinHex RAM Editor 或 OllyDbg 的内存搜索在整个进程空间查找假注册码，真注册码往往就在其 ±0x90 字节范围内——原文 TraceMe 输入 `pediy` / `12121212`，在附近直接找到真序列号 `2470`。

## 原理

- **数据约束性 / 密码相邻性（Data constraint / Password proximity）**：序列号校验代码需要同时持有“用户输入”和“程序算出的正确值/中间值”才能比较。编译器通常把这些局部变量连续放在同一栈帧里，软件作者调试时也要同时观察两者，因此正确序列号经常落在输入序列号附近的小范围内（原文给出 ±0x90 字节的经验值）。
- **为什么真序列号会以明文出现**：对 `序列号 = F(用户名)` 型保护，程序必须在本地算出正确序列号再与输入比较，计算结果在比较前以明文存在内存/栈上；对 `用户名 = F^-1(序列号)` 型保护，虽然正确序列号本身不出现，但逆变换的中间结果和输入仍在附近，可辅助定位校验代码。
- **为什么要在错误框未关闭时搜索**：校验函数弹出 `MessageBox` 报错时是模态阻塞，函数尚未返回，保存输入和正确值的栈帧仍然有效；一旦关闭对话框、函数返回，局部变量所在栈空间可能被后续调用覆盖。所以搜索要趁错误提示还开着。
- **搜索的可操作形态**：调试器/内存编辑器按字节搜索输入串（ASCII `31 32 31 32 31 32 31 32`；Unicode 则穿插 `00`），命中后查看前后若干行；也可搜索中间值、用户名或错误提示字符串附近的引用。
- **局限**：若程序只保存输入与正确值的哈希/加密结果、比较后立即清零，或正确值根本不在本地（服务端校验），邻近搜索就找不到明文；此时需改用比较点断点、API 断点或算法逆推。

## 触发条件

- 本地可运行的序列号/注册码校验程序（crackme、共享软件），能输入用户名与假序列号并触发一次校验。
- 校验失败后有错误提示框/断点让进程停在比较附近，栈帧未被回收。
- 程序把正确序列号或可识别中间值以明文保存在输入附近；未做严格的内存清零/加密比较。
- 有进程内存读取能力：WinHex RAM Editor、OllyDbg/x64dbg 内存搜索，或自写 `ReadProcessMemory` 工具；目标无强反调试/反内存扫描，或已绕过。

## 利用步骤

1. 运行目标（原文 TraceMe.exe），输入用户名 `pediy`、假序列号 `12121212`，点击 Check；弹出“序列号错误”提示框后不要关闭。
2. **WinHex 路径**：`Tools → RAM Editor`（或 `Alt+F9`）→ 选择 TraceMe 进程的 Primary Memory → `Ctrl+F` → 输入 ASCII `12121212`（可勾选 Entire block/Case sensitive，也可按 HEX 搜索 `31 32 31 32 31 32 31 32`）→ 查看命中地址前后的内存。
3. **OllyDbg 路径**：加载/附加 TraceMe，`Alt+M` 打开内存映射，在目标块上 `Ctrl+B` 搜索 `12121212`，或使用二进制搜索覆盖整个进程内存。
4. 在命中位置附近（经验范围 ±0x90）寻找可读字符串/数值；原文在 `12121212` 附近找到 `2470`。
5. 把找到的值作为序列号重新输入验证；若通过，即得到正确注册码；若不通过，扩大搜索范围、改用 Unicode 编码，或转去定位比较指令/API 断点。

## PoC

原文 TraceMe 实例的操作序列（工具操作，无代码）：

```text
1) TraceMe.exe: username=pediy, serial=12121212 -> Check -> 保持错误提示框
2) WinHex: Alt+F9 (RAM Editor) -> 选 TraceMe -> Ctrl+F -> ASCII "12121212"
   或 OllyDbg: Alt+M -> 目标内存块 -> Ctrl+B -> "12121212"
3) 命中地址附近查看：
   ... 31 32 31 32 31 32 31 32 ...   <- 输入的假序列号 12121212
   ... 32 34 37 30             ...   <- 附近发现的真序列号 "2470"
4) 用 2470 重新注册，校验通过
```

ASCII/Unicode 搜索字节：

```text
ASCII:  31 32 31 32 31 32 31 32
UTF-16LE: 31 00 32 00 31 00 32 00 31 00 32 00 31 00 32 00
```

## 变体与关联

- **变体**：搜索范围/编码可调整（ASCII、UTF-16LE/BE、HEX）；也可搜索用户名、错误提示字符串、中间计算结果；Windows 9x/Me 上还可用 `hmemcpy`“万能断点”在字符串复制时中断，NT/2000+ 无此内部函数。
- **与断点法配合**：若邻近搜索找不到，可在 `GetWindowTextA/W`、`GetDlgItemTextA/W`、`MessageBoxA/W`、`RegQueryValueExA/W`、`GetPrivateProfileStringA`、`CreateFileA` 等 API 下断，先定位校验代码，再在比较点观察寄存器/栈中的正确值。
- **关联卡片**：[[code-analysis-dynamic-debugging-crackme-password-check-patch]]（比较点断点后改寄存器/ZF/补丁的通用破解）；[[code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate]]（Delphi 注册对话框的输入 API 定位）；[[code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint]]（Qt 注册码程序断 QLineEdit::text）；[[ctf-forensics-memory-image-flag-keyword-search]]（内存镜像关键词搜索，偏取证，不依赖进程邻近性）。

## 检测与防御

- **代码层**：不要在本地长期保存正确序列号的明文；比较使用哈希/带密钥的 MAC，比较后立即清零缓冲区；避免在错误提示未关闭时让包含秘密的栈帧长期存活；增加完整性校验与反调试。
- **检测特征**：进程被 WinHex/OllyDbg/x64dbg 等工具附加或读取内存；短时间内出现对整个进程空间的关键词/字节搜索；注册校验失败后进程长时间停在错误对话框；调试器断点/硬件断点被设置。
- **加固**：服务端校验或在线激活；序列号与硬件指纹/账号绑定；对本地校验逻辑做混淆与完整性保护，降低“内存里直接看到正确值”的概率。
