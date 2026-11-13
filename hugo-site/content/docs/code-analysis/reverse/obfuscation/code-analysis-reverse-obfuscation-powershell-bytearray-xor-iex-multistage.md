---
id: code-analysis-reverse-obfuscation-powershell-bytearray-xor-iex-multistage
title: PowerShell 加密字节数组 + 重复密钥 XOR + iex 的多阶段脚本加载器与静态还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: powershell-bytearray-xor-iex-multistage-loader
tags:
- powershell
- obfuscation
- xor
- byte-array
- loader
- multistage
- malware-analysis
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T02:27:07+08:00'
  notes: 已对照原文图1（[byte[]] 数组 + x 函数 -bxor 重复密钥 + iex）与图2/3（第二层经 iex 替换落盘 LayerTwo.ps1 后美化）核对；密钥在原文打码，PoC 用占位符并已注明未执行；frontmatter 无 sources/source_url；加载器非组件/框架类，无受影响版本。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-powershell-bytearray-xor-iex-multistage/
draft: false
kb_aliases:
- PowerShell 字节数组加载器
- 加密字节数组 XOR iex
- 重复密钥 XOR 解密
- 把 iex 改为落盘导出
- LayerTwo 脚本还原
---

## 一句话结论

把下一阶段 PowerShell 脚本以十进制 `[byte[]]` 数组形式内嵌，运行时用脚本自带的一段重复密钥逐字符 XOR 解密成字符串，再交给 `iex` 执行；由于密钥就写在脚本里、算法是可逆的字符异或，只要把最后的 `iex` 换成落盘或打印，就能静态还原下一层，不需要执行原始载荷。

## 原理

- **编码层**：脚本开头是 `[byte[]] $payload = 88,83,97,...` 形式的大数组，每个元素是一个 0-255 的字节值；随后 `[System.Text.Encoding]::UTF8.GetString($payload)` 把字节数组按 UTF-8 解释成字符串，即得到密文字符串。
- **解密函数**：自定义函数（样本中命名为 `x`）接收 `$pt`（密文字符串）与 `$key`（密钥字符串），把 `$key` 转成字符数组，遍历密文的每个字符，执行 `[char]([byte][char]$_ -bxor $ka[$kp])`，即取密文字符的字节值与密钥字符的码点做异或，结果转回字符；`$kp` 每处理一个字符加一，到密钥长度后回绕，因此是**重复密钥 XOR**（Vigenère 式异或）。
- **执行层**：解密结果 `$cmd` 直接管道给 `iex`（`Invoke-Expression`）。整个加载器不落地文件、不联网获取密钥，所以分析时可以完全离线还原：XOR 是对称运算，同一密钥再异或一次即得明文。
- **为什么成立**：密钥是硬编码在脚本里的常量，算法只依赖字符码，不含随机数、时间戳或服务端下发材料；密文字节数组与明文一一对应，属于纯静态可逆变换。限制是 `[byte][char]$_` 会截断到 8 位，明文字符必须在 ASCII 范围内（否则还原出错），因此这类加载器通常只承载纯 ASCII 的下一阶段脚本。
- **多阶段结构**：第一层只负责解出第二层 PowerShell 脚本（样本中解出后另存为独立脚本继续分析）。第二层通常再用大量无意义变量名、字符串替换和拼接做混淆，需要美化和逐步重命名；本卡聚焦第一层的字节数组 XOR 还原，第二层的具体混淆依样本而定。

## 触发条件

- 拿到可疑 PowerShell 脚本（文件、计划任务参数、BITSAdmin 下载物、`-EncodedCommand` 解码结果等）。
- 脚本中出现 `[byte[]]` 大数组、`foreach-object` 内 `-bxor`、`[char]` 转换与 `iex` 组合。
- 分析环境隔离；只需静态还原，不需要也不应该让原始样本连接其 C2。

## 利用步骤

1. 在脚本中定位 `[byte[]] $payload = ...`、解密函数（常含 `-bxor`、`ToCharArray`、密钥回绕计数）与 `$key = "..."` 赋值，记录两边。
2. 确认执行点：`$cmd | iex` 或 `Invoke-Expression $cmd`。
3. 静态还原：用等价脚本（Python/PowerShell）取同一字节数组与密钥做重复密钥 XOR；或最小改动原脚本，把 `iex` 替换为 `Out-File .\LayerTwo.ps1`（或 `Write-Output`），在隔离环境运行后得到下一层。
4. 检查还原出的下一层：若仍是编码/拼接混淆，重复"识别层类型 → 静态解码"，并把所有执行点改为打印或落盘，绝不执行原始逻辑。
5. 记录每层哈希、内嵌 C2/下载地址、落地路径等 IOC，交付检测规则。

## PoC

```python
# 按样本中的 [byte[]] 数组与 $key 原样填入；ASCII 范围内等价于原脚本的字符码 XOR
payload = [88, 83, 97, 68, 74, 8, 40, 40, 85, 8, 0, 22, 25, 10, 25, 45]
key = b"REPLACE_WITH_SAMPLE_KEY"

ct = bytes(payload)
pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))
print(pt.decode("utf-8", "replace"))
```

```powershell
# 最小改动法（示意）：其余代码保持原样，仅替换最后一行
# 原： $cmd | iex
$cmd | Out-File -Encoding utf8 .\LayerTwo.ps1
```

说明：PoC 为等价最小实现，未执行原始样本；实际数组很长时从样本完整复制，密钥取 `$key` 赋值处。

## 变体与关联

- 变体：整数数组加固定偏移后 `[char]` 拼接、Base64/十六进制字符串、`[CHar]` 码点拼接、`ScriptBlock.Create` 内存执行，思路相同但变换不同；参见 [[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]] 与 [[code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell]]。
- 变体：密钥可以是单字节、固定串、按位置递增/递减，或与另一段常量拼接派生；若密钥来自运行环境或服务端下发，则静态还原会失败，需要沙箱动态导出。
- 关联：还原出的下一层常是 C2 后门或下载器，例如 [[pentest-c2-powershell-runspacepool-sslstream-async-backdoor]] 一类 PowerShell 后门。
- 边界：非 ASCII 明文、密钥拼接逻辑复杂或密钥动态生成时，不能直接用字节 XOR 还原；需按脚本语义逐步化简。

## 检测与防御

- 检测：PowerShell 4104 脚本块日志中出现大段十进制数组、`-bxor`、`ToCharArray`、密钥轮转计数与 `iex` 同现；命令行出现 `powershell -nop -w hidden -c` 读取/执行脚本。
- 检测：对可疑脚本离线跑等价解码，提取下一层与 C2 地址，而不是只做明文关键字匹配。
- 防御：启用 Script Block Logging、Module Logging、AMSI 与约束语言模式；限制 PowerShell 由服务进程/下载器拉起；出站白名单。
- 响应：隔离主机、保留原始脚本与哈希、清除持久化项（计划任务/服务/BITS 作业），封锁还原出的 C2。
