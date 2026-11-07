---
id: ctf-reverse-dotnet-dnspy-de4dot-arithmetic-inverse
title: C#/.NET CTF 逆向：dnSpy 反编译、de4dot 去混淆与逐字节算术校验逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: dotnet-dnspy-de4dot-arithmetic-inverse
tags:
- ctf
- reverse
- dotnet
- csharp
- dnspy
- de4dot
- il
- obfuscation
- arithmetic
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:50+08:00'
  notes: 已对照 content.md 与 8 张图核对：IDA 加载 pe64.dll 并显示 IL、Exeinfo 显示 MS Visual C# / Basic.NET、dnSpy 中 Unicode 随机名、de4dot 重新生成解决方案、三个案例（Base64 常量、de4dot 去混淆、逐字节算术逆推）及 MD5 大写 X2+Substring(0,20) 细节均一致。本机验算 MD5('1001') 前 20 位为 B8C37E33DEFDE51CF91E，两段 Base64 flag 解码正确；未在本机运行 dnSpy/de4dot/案例 PoC。frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-dotnet-dnspy-de4dot-arithmetic-inverse/
draft: false
kb_aliases:
- C# 逆向
- .NET 逆向
- dnSpy 反编译
- de4dot 去混淆
- IL/MSIL
- Unicode 随机名混淆
- C# 逐字节校验
---

## 一句话结论

C#/.NET 程序编译为 IL（MSIL）而非机器码，dnSpy 可把 IL 反编译成接近原始源码的 C#；遇到 Unicode 随机类名/方法名的混淆先用 de4dot 去混淆；校验逻辑常是“Base64 常量比较”或“逐字节可逆算术”，按逆运算并注意 C# `byte`/`int` 的截断（Python 侧 `& 0xff`）即可还原 flag。

## 原理

- **.NET 程序结构**：C# 编译产物是 PE 格式的 exe/dll，但代码不是 CPU 机器码，而是 CLR 元数据 + IL 字节码。IDA 打开时会加载 `pe64.dll` 处理器模块，反汇编窗口显示的是 IL 指令（`ldstr`、`call`、`stloc` 等），类似 Python 的 pyc 字节码。
- **快速识别**：用 Exeinfo PE 查看，若显示 `.NET`/`MSIL`/`MS Visual C# / Basic.NET`，即为 C# 程序；也可用 `strings` 搜 `mscoree.dll`、`_CorExeMain`、`.NET Framework` 等特征。IDA 中出现 `pe64.dll` 且只有 IL 代码也是强特征。
- **dnSpy 反编译**：dnSpy 直接读取 .NET 元数据，把 IL 还原成 C# 源码，保留命名空间、类名、方法名、字符串常量与调用关系；支持“分析”查看交叉引用/调用图，支持调试（目标需 debug 编译）与源码级编辑后保存为新的 exe/dll（补丁）。
- **de4dot 去混淆**：常见 .NET 混淆器会把类名/方法名/变量名替换成 `​‍...` 之类的 Unicode 随机串，或插入控制流/字符串加密。de4dot 支持 Agile.NET、Babel.NET、Dotfuscator、.NET Reactor、SmartAssembly、ConfuserEx 等，自动识别或 `-P <id>` 指定混淆器；输出去混淆后的 `*-cleaned.*` 文件，再用 dnSpy 打开。
- **校验模式一：Base64 常量比较**：
  ```csharp
  bool ok = Convert.ToBase64String(Encoding.UTF8.GetBytes(input)) == "Q0ZJey...";
  ```
  直接把常量 Base64 解码即可；注意 `Encoding.UTF8`/`Encoding.Default` 的差异。
- **校验模式二：逐字节可逆算术**：
  ```csharp
  if ((byte)((int)((byte)text[i] + 114 ^ 114) ^ i * i) != array[i]) { ... }
  ```
  正向：取输入字节 → `+114` → `^114` → `^ (i*i)` → 截断为 byte。逆向：`((array[i] ^ (i*i)) ^ 114) - 114`，最后 `& 0xff`。
- **C# 与 Python 的精度差异**：C# 的 `(byte)` 转换按 8 位截断，`int` 为 32 位；Python 整数无限精度且 `^` 是按位异或，不会自动截断。逆推时必须显式 `& 0xff`，否则负数/高位会污染结果。另注意 C# 中 `^` 是异或，不是幂运算；`+` 优先于 `^`，必要时按括号还原。
- **为什么客户端校验可逆**：IL 保留了完整的运算与常量，没有不可逆哈希/签名时，校验只是“输入经过可逆变换后与常量比较”；攻击者可以反推变换或直接 dnSpy 打补丁跳过比较。

## 触发条件

- 目标为 C#/.NET 编译的 exe/dll（Exeinfo PE 显示 .NET/MSIL，或 IDA 只显示 IL）。
- 有权限在本地用 dnSpy/de4dot 分析样本；目标未使用强 native 保护（如 .NET Reactor 的 native stub 可能需要额外脱壳）。
- 校验逻辑位于托管代码中，使用 Base64/hex 常量或逐字节可逆算术，而非服务端校验/非对称签名。
- 混淆可能存在，但 de4dot 能识别或可手动定位关键方法。

## 利用步骤

1. 用 Exeinfo PE / `strings` / IDA 判断是否为 .NET；记录位数与 .NET 版本，选择 dnSpy32/64。
2. 用 dnSpy 打开样本，展开命名空间，定位 `Main`、按钮点击事件（`button1_Click`）或 `Validate*` 类；查看字符串常量、比较分支与输入读取。
3. 若类名/方法名是 `​...` 随机串或控制流混乱，运行 `de4dot.exe target.exe`（或 `-P sa` 指定 SmartAssembly 等），用生成的 `target-cleaned.exe` 重新分析。
4. 识别校验模式：
   - Base64/hex 常量：直接解码；
   - 逐字节变换：抄下数组与表达式，按逆序写 Python 脚本；
   - 哈希/加密：确认是否可逆，必要时用 dnSpy 调试或打补丁。
5. 逆推时注意 C# 的 `byte` 截断与运算符优先级，Python 侧对每步 `& 0xff`；用正向 C# 逻辑回验结果。
6. 可选：在 dnSpy 中直接编辑校验方法（如把 `return false` 改为 `return true`，或让程序打印中间值），保存模块生成补丁版；或写一个 C# 小程序复现正向逻辑验证。
7. 运行原程序/补丁程序，确认 flag 或“注册成功”。

## PoC

```csharp
// 案例：逐字节算术校验（原文 Moectf 2024 dotNet）
byte[] array = new byte[] {
    173,146,161,174,132,179,187,234,231,244,177,161,65,13,18,12,
    166,247,229,207,125,109,67,180,230,156,125,127,182,236,105,21,
    215,148,92,18,199,137,124,38,228,55,62,164
};
string text = Console.ReadLine();
if (text.Length != array.Length) { /* wrong */ }
for (int i = 0; i < array.Length; i++) {
    if ((byte)((int)((byte)text[i] + 114 ^ 114) ^ i * i) != array[i]) { /* wrong */ }
}
```

```python
# 逆推：先逆 i*i 异或，再逆 114 异或，最后减 114；C# byte 截断 -> & 0xff
enc = [
    173,146,161,174,132,179,187,234,231,244,177,161,65,13,18,12,
    166,247,229,207,125,109,67,180,230,156,125,127,182,236,105,21,
    215,148,92,18,199,137,124,38,228,55,62,164
]
flag = "".join(chr((((enc[i] ^ (i * i)) ^ 114) - 114) & 0xff) for i in range(len(enc)))
print(flag)
```

```python
# Base64 常量型校验：直接解码
import base64
print(base64.b64decode("Q0ZJey5OZXRDI18xc19AdzNzMG0zfQ==").decode())
```

说明：以上为按原文案例整理的结构化 PoC，未在本机执行；Base64 常量与数组来自原文，实际样本需重新提取。dnSpy 调试要求目标为 debug 编译，补丁保存前建议备份原文件。

## 变体与关联

- **校验变体**：Base64/hex/UTF-16 常量、逐字节 XOR/加/减/循环移位、`i*i`/`i` 参与、字符串 `Replace`/`Substring` 拼接、哈希（MD5/SHA）不可逆时需爆破或打补丁。
- **混淆变体**：Unicode 随机名、控制流平坦化、字符串加密、资源加密、ConfuserEx/.NET Reactor 的 native stub；de4dot 不一定覆盖所有新版混淆，需动态调试/脱壳。
- **工具变体**：dnSpy、ILSpy、dotPeek、dnSpyEx、de4dot、UnconfuserEx；调试可用 dnSpy 或 x64dbg + SOS。
- **关联卡片**：[[ctf-reverse-base64-table-index-mutation]]（Base64 换表变体）、[[ctf-reverse-byte-multiply-reverse-26-byte-check-inverse]]（逐字节可逆校验）、[[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]（.NET 字符串加密与自动解密）、[[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]（.NET 分层样本）。
- **边界**：强 native 保护/虚拟化、服务端校验、非对称签名会让纯静态反编译失效；de4dot 对未被支持的混淆器可能无效。

## 检测与防御

- **CTF/验证**：逆推结果应为可打印 flag；用 dnSpy 正向执行或补丁程序验证“注册成功”；Base64 常量解码应匹配格式。
- **检测信号**：PE 中出现 CLR 头、`mscoree.dll`、`_CorExeMain`、`.NET`/`MSIL` 字符串；dnSpy 可完整还原类/方法；de4dot 处理前后类名从 `​...` 变为可读名。
- **防御视角**：.NET 混淆（de4dot 可去除）、字符串加密、控制流平坦化只能提高逆向成本，不能作为安全边界；不要把 flag、许可证判断或密钥只放在客户端托管代码中。
- **加固**：关键校验放服务端；客户端使用代码签名/完整性校验、native 保护与反调试作为纵深防御；对敏感常量做服务端下发或加密，并定期轮换。
