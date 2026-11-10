---
id: code-analysis-reverse-windows-autoit-a3x-xor-not-keyfold-decrypt
title: AutoIt 编译脚本 .a3x 提取与 XOR+BitNOT 折叠密钥解密分析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: autoit-a3x-xor-not-keyfold-decrypt
aliases:
- a3x 提取
- autoit-extractor
- AutoIt 脚本解密
- BitNOT BitXOR 密钥折叠
- AutoIt compiled script 分析
- SFZFQODn
tags:
- windows
- autoit
- a3x
- malware-analysis
- decryption
- xor
- reverse-engineering
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T03:20:59+08:00'
  notes: 已对照原文与16张图片核对，并独立复现算法：key=SFZFQODn 折叠得 keyAlt=0x35(len 8 XOR 各字节)，对文中四段 hex 应用 BitNOT(BitXOR(c,keyAlt)) 分别解出 DllStructCreate(byte[46768])、VirtualProtect(...0x40...)、DllStructSetData、EnumWindows 片段，与图13-15一致；大段  解出乱码、原文未还原主载荷且 DarkGate 结论来自同类报告，卡内已如实标注；autoit-extractor 提取流程、DIE 识别 AutoIt compiled script(2.XX-3.XX) 与图12/16一致。无 affected_versions/CVE 正确。未验证点：未对  继续寻找第二套密钥，未动态调试复现。
---

## 一句话结论

对编译后的 AutoIt 载荷 `script.a3x`，可用 autoit-extractor 提取其中的脚本/资源；案例脚本的解密函数先把密钥做“密钥长度 XOR 所有密钥字节”的折叠，再对每个密文字节执行 `BitNOT(BitXOR(c, keyAlt))`——该变换是对合运算，用同一函数即可解密——解出的片段包含 `DllCall("kernel32.dll","VirtualProtect",...)` 与 `DllCall("user32.dll","EnumWindows",...)` 的 shellcode 执行逻辑；但大段 `$data` 密文用该函数解出乱码，说明主载荷另有加密/密钥，不能仅凭此函数还原。

## 原理

- **文件识别**：`.a3x` 是 AutoIt 编译脚本，Detect It Easy 等工具识别为 `AutoIt compiled script(2.XX-3.XX)`；它由 AutoIt3 解释器执行（`AutoIt3.exe -a script.a3x`），不是标准 PE，常规 PE 分析流程不适用。
- **资源提取**：autoit-extractor 可解析 AutoIt 编译文件，导出其中的脚本源码/资源；案例借此拿到混淆后的 AutoIt 脚本（`#NoTrayIcon`、`GUICreate("amnpybqgf", 0x9e, 0x287)`、`_ENCRYPT` 函数与多段 hex 字符串）。
- **密钥折叠**：`_ENCRYPT($vvalue, $skey)` 先令 `$ikeyalt = BinaryLen($skey)`，再对密钥每个字节执行 `$ikeyalt = BitXOR(BinaryMid($skey,$i,1), $ikeyalt)`；即 `keyAlt = len(key) XOR key[0] XOR key[1] ...`，把任意长度密钥折叠成单字节值（案例密钥 `SFZFQODn`）。
- **逐字节变换与对合性**：对密文每个字节 `c` 计算 `p = BitNOT(BitXOR(c, keyAlt))`。两次应用：`BitNOT(BitXOR(BitNOT(BitXOR(p,K)),K)) = p`（XOR 两次抵消、按位取反两次还原），所以同一 `_ENCRYPT` 函数既是加密也是解密。
- **可还原内容**：把案例中的多段 `0x8EA6...` hex 字符串传入该函数，可得到 AutoIt 代码片段（执行时用 `Execute` 运行），其中调用 `DllStructCreate`、`DllCall("kernel32.dll","BOOL","VirtualProtect",...)`、`DllCall("user32.dll","int","EnumWindows",...)`，属于“分配/改权限后用回调执行 shellcode”的典型 LocalAlloc+VirtualProtect+EnumWindows 组合。
- **未还原部分**：脚本还包含大量 `$data &= "..."` 十六进制片段（数万字符），用同一 `_ENCRYPT` 解出的是乱码（原文实测 console 输出乱码），说明主载荷使用不同算法/密钥或仅部分加密；原文最终 DarkGate 结论来自同类样本报告，而非本样本完整解密。

## 触发条件

- 拿到 AutoIt 编译脚本（`.a3x`）或编译后的 AutoIt EXE；文件未被额外加壳/反提取处理。
- 能运行 AutoIt3/SciTE 或纯脚本复现解密函数；样本的密钥可从脚本常量中直接读取（案例 `SFZFQODn`）。
- 解密函数为纯字节运算、不依赖运行环境生成的一次性密钥（本案前半部分满足，主 `$data` 不满足）。

## 利用步骤

1. 用 Detect It Easy 确认文件类型为 AutoIt compiled script；用 autoit-extractor 提取脚本与资源，得到 AutoIt 源码/伪源码。
2. 阅读提取结果，定位字符串解密函数（案例为 `_ENCRYPT`）及密钥常量；识别 `BinaryLen`/`BinaryMid`/`BitXOR`/`BitNOT`/`DllStructSetData` 等 AutoIt 内建函数。
3. 复现密钥折叠：`keyAlt = len(key)`，再依次与每个密钥字节 XOR。
4. 对脚本中的 hex 字符串调用同一函数（对合），观察输出是否为可读 AutoIt 代码；可把输出写入文件交给 SciTE/AutoIt 语法高亮检查。
5. 若输出包含 `DllCall`/`Execute`，继续跟踪其参数：`VirtualProtect` 目标缓冲区、`EnumWindows` 回调地址等。
6. 若大段数据解密失败，检查是否存在第二套密钥/算法（如按块选择密钥、`BinaryToString` 前先做其它变换），或转向动态调试：用 AutoIt3 运行到 `Execute`/`DllCall` 前后 dump 内存。

## PoC

解密函数（案例，AutoIt）：

```autoit
Func _ENCRYPT($vvalue, $skey)
    $tbyte = DllStructCreate("BYTE")
    Local $s_encrypted
    Local $ikeyalt = BinaryLen($skey)
    For $i = 0x1 To $ikeyalt
        $ikeyalt = BitXOR(BinaryMid($skey, $i, 0x1), $ikeyalt)
    Next
    For $i = 0x1 To BinaryLen($vvalue)
        $s_encrypted &= Chr(DllStructSetData($tbyte, 0x1, BitNOT(BitXOR(BinaryMid($vvalue, $i, 0x1), $ikeyalt))))
    Next
    Return $s_encrypted
EndFunc

ConsoleWrite(_ENCRYPT(BinaryToString("0x8EA6A699BEB8BFA9BE89B8AFABBEAFE2E8A8B3BEAF91FEFCFDFCF297E8E3"), "SFZFQODn") & @CRLF)
```

解出的代码片段（示意）：

```autoit
DllCall("kernel32.dll", "BOOL", "VirtualProtect", "ptr", ..., "dword", ..., "dword", 0x40, "ptr*", ...)
DllCall("user32.dll", "int", "EnumWindows", ...)
```

## 变体与关联

- 变体：AutoIt 脚本常用 `Execute` 执行解密后的代码；密钥可能是常量、由环境/参数拼出，或每段不同；`$data` 可能是另一种加密（如仅低字节 XOR、分块密钥、字符串反转）。
- 关联：执行侧“AutoIt3.exe -a script.a3x”解释器宿主见 [[pentest-c2-autoit3-a3x-interpreter-payload-host]]；`VirtualProtect` + `EnumWindows` 执行 shellcode 的原语见 [[pentest-c2-local-shellcode-exec-callback-fiber-hook]]。
- 关联：同类字符串 XOR/BitNOT 混淆的分析思路可参考 [[code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell]]（多层编码逐层还原）。
- 边界：本案主 `$data` 未还原、DarkGate 归属依赖同类报告，卡内只描述已验证的提取/解密流程与未完成点；不同样本的 AutoIt 版本、编译选项与加密函数可能不同。

## 检测与防御

- 文件侧：检测 AutoIt compiled script 文件头/结构、便携 AutoIt3 解释器与 `.a3x` 同时落地；对 AutoIt 脚本中的 `DllCall` + `VirtualProtect`/`EnumWindows`/`Execute` 组合做规则或 YARA。
- 行为侧：监控 AutoIt3 进程调用 `VirtualAlloc`/`VirtualProtect` 后创建线程或回调执行、从 `Execute` 动态运行字符串；结合父进程（PowerShell/HTA）与目录（隐藏目录）关联。
- 分析侧：先用 autoit-extractor 提取，再按密钥折叠 + XOR/BitNOT 对合复现；对无法还原的密文转向动态调试与内存 dump，不要仅凭静态片段判断最终载荷家族。
- 防御：非必要环境禁止 AutoIt3/AutoHotkey 等解释器从用户目录运行；限制未知 ZIP 下载解压；EDR 覆盖脚本解释器加载数据脚本的行为链。
