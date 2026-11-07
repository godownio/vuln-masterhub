---
id: code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt
title: Obfuscar 字符串隐藏自动还原：dnlib 定位 InitializeArray 字节数组 + offset/size 切片 + byte^i^key 解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: obfuscar-dnlib-string-auto-decrypt
tags:
- dotnet
- reverse
- obfuscation
- string-encryption
- xor
- dnlib
- pythonnet
- malware-analysis
- agenttesla
- dnspy
cve: []
severity: medium
confidence: high
affected_versions: Obfuscar 1.0（原文样本 DIE 检测到的保护器版本；其他版本生成的访问器与密钥可能变化）
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:43+08:00'
  notes: 已对照原文与图01-27核对；Obfuscar 1.0、10969字节数组、key=170、FieldRVA/InitialValue与ldc短格式均一致；PoC未在样本上复跑。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt/
draft: false
kb_aliases:
- Obfuscar 字符串提取
- Obfuscar HideStrings
- Obfuscar ProcessStrings
- dnlib 字符串自动解密
- InitializeArray FieldRVA
- byte ^ index ^ 170
- AgentTesla 字符串解密
- .NET 字符串表切片
---

## 一句话结论

Obfuscar 的字符串隐藏会把所有字符串拼进一个大的 `byte[]`，在 `.cctor` 里用 `array[i] = (byte)(array[i] ^ i ^ key)` 整体解密，并为每个字符串生成一个 `cache[index] ?? GetString(index, offset, count)` 访问器；用 dnlib（pythonnet 加载）遍历 .NET 元数据/IL，找到 `RuntimeHelpers.InitializeArray` 前一条 `ldtoken` 指向的 `FieldDef.InitialValue` 即可直接取出密文数组，再从 `.cctor` 的 `xor`/`ldc.i4`/`xor` 模式提取 key，最后按访问器中的 `index/offset/count` 切片并整体解密，就能批量还原全部字符串。

## 原理

- **Obfuscar 的字符串隐藏方式**：Obfuscar 开源实现里的 `HideStrings()` 遍历程序集的所有类型（跳过 `<Module>`），对每个方法调用 `ProcessStrings()`，最后 `Squeeze()`。`ProcessStrings()` 把方法中所有 `ldstr` 指令替换为对“单个字符串访问器”的调用；访问器的 IL 形如：取字符串缓存数组的第 `index` 项，非空则直接返回，为空则压入 `index`、`start`、`count` 三个整数并调用统一的 `StringGetter`，由后者从字节数组中按 `start/count` 解码 UTF-8 并写回缓存。
- **数据布局**：所有明文字符串首尾相接写入一个连续的 `byte[]`（示例为 10969 字节），字符串之间没有 `\x00` 分隔符；每个访问器只知道自己字符串的起始偏移和长度。因为没有分隔符，直接解出整个数组会得到一串连在一起的文本（如 `<b>[ </b>`、`{ALT+TAB}`、TorBrowser 下载 URL 等），必须按访问器参数切片才能得到独立字符串。
- **整体 XOR 解密**：编译器生成的 `.cctor`（标记 `beforefieldinit`）在类初始化时执行：
  ```csharp
  for (int i = 0; i < ARRAY.Length; i++)
      ARRAY[i] = (byte)((int)ARRAY[i] ^ i ^ 170);
  ```
  即 `plain[i] = cipher[i] ^ (i & 0xFF) ^ key`，示例 key 为 170（0xAA）。索引参与异或意味着**不能**把某一段密文单独拿出来从 0 开始解密；必须按它在原始数组中的全局偏移计算索引，或者先把整个数组整体解密再切片。
- **为什么反编译看起来“没有字符串”**：Obfuscar 同时做了控制流混淆（方法体变成 `num` 状态机与 `goto`），字符串又被折叠进一个大数组和一堆单字母访问器（`A()`、`a()`、`B()`、`hE()`…），dnSpy 的字符串搜索/交叉引用很难直接命中；但保留的元数据（`FieldDef`、`FieldRVA`、IL 指令）足以让脚本静态还原，不需要运行样本。
- **dnlib 的作用**：dnlib 是 dnSpy 内部使用的 .NET 元数据/IL 库，可通过 pythonnet 在 Python 中加载。与纯元数据解析库相比，它能直接访问 `MethodDef.Body.Instructions`、`FieldDef.InitialValue` 和 `HasFieldRVA`，相当于“IDA 的 idapython”之于 x86；定位 `InitializeArray` 后，前一条 `ldtoken` 的 `FieldDef` 就是编译器存放数组数据的字段，`InitialValue` 直接给出原始字节，省去手工按 RVA 去 PE 里读文件偏移。
- **key 与切片参数的静态识别**：key 在 `.cctor` 的指令序列中表现为 `xor`（数组元素与索引）→ `ldc.i4`（常量 key）→ `xor`；切片参数在访问器中表现为连续三条 `ldc.i4*` 后跟一次返回 `System.String` 的 `call`，分别对应 `index`、`start`、`count`。难点是 `ldc.i4` 有长格式 `ldc.i4 170`、短格式 `ldc.i4.s 17` 和极短格式 `ldc.i4.0`～`ldc.i4.8`/`ldc.i4.m1`，脚本必须都能解析，否则会漏掉大量访问器。
- **工程化筛选**：样本中可能存在多个 `InitializeArray` 数组和多个候选 key。文章的做法是收集所有候选数组、取最长者作为字符串表；收集 `.cctor` 中所有 `ldc.i4 + 前后 xor` 的常量作为候选 key；用前 100 字节解密后的可打印 ASCII 比例（>0.8）选出正确 key，再按访问器参数输出字符串。

## 触发条件

- 目标为 .NET PE（示例为 PE32、.NET Framework 4.0、VB.NET 编译），DIE/pestudio 可识别 `Obfuscar(1.0)` 保护器。
- 样本使用 Obfuscar 的字符串隐藏功能（默认选项或等价实现），元数据中存在 `FieldRVA` 的静态字段和 `RuntimeHelpers.InitializeArray` 调用。
- 分析环境为 Windows（示例为 Python 3.8 + PyCharm），已安装 `pythonnet` 并准备好与样本 .NET 版本匹配的 `dnlib.dll`（通常取自 dnSpy 安装目录）；`import clr` 失败时应安装 `pythonnet` 而不是名为 `clr` 的包。
- 样本可以无法运行（反虚拟机/反调试/缺依赖），本方法全程静态，不依赖样本执行。

## 利用步骤

（以下为样本分析流程，不执行恶意代码。）

1. **识别保护器**：DIE 查看 PE 头与 .NET 信息，确认 `Obfuscar(1.0)`、`.NET(v4.0.30319)`、`VB.NET`；dnSpy 打开确认方法体被控制流混淆、字符串在普通视图中不可读。
2. **定位大数组**：在 `{GUID}` 命名空间中找到 `internal static byte[]` 字段及其上方 `static` 构造函数；`.cctor` 中的循环就是整体解密逻辑，key 为 170。
3. **看访问器**：同一命名空间内大量 `public static string X()` 返回 `cache[index] ?? GetString(index, start, count)`；`GetString` 用 `Encoding.UTF8.GetString(array, start, count)` 解码并缓存。记录 `index/start/count` 三元组。
4. **加载 dnlib**：`clr.AddReference(<dnlib.dll>)` 后 `import dnlib`，用 `ModuleDefMD.Load(sample)` 打开样本；注意 dnlib.dll 版本要与 pythonnet/运行时匹配。
5. **遍历类型/方法/指令**：`for type in mod.GetTypes()` → `for method in type.Methods` → `method.Body.Instructions`，先 `HasBody`/`HasInstructions` 判空。
6. **取数组**：找到 `RuntimeHelpers::InitializeArray` 指令，取前一条 `ldtoken` 的 `Operand`；若为 `FieldDef` 且 `HasFieldRVA`，直接读 `InitialValue` 得到密文数组（同时可读 `RVA` 做交叉验证）。
7. **取 key**：在 `.cctor` 中匹配 `xor`、`ldc.i4`、`xor` 三连，取中间常量为候选 key；若存在多个候选，用可打印 ASCII 比例筛选。
8. **取切片参数**：遍历返回 `System.String` 的方法，找到 `call`（字符串 getter）前连续三条 `ldc.i4*`，解析出 `index/start/count`；注意短格式与极短格式。
9. **解密输出**：先对整张数组做 `b ^ i ^ key`，再按 `start:start+count` 切片并 UTF-8 解码；对结果做可打印性校验，输出访问器名到字符串的映射，继续分析 C2、文件路径、Tor/浏览器下载地址等。

## PoC

最小化 Python（pythonnet + dnlib）脚本，仅做静态元数据解析：

```python
import clr
clr.AddReference(r"C:\tools\dnSpy-net-win64\bin\dnlib.dll")
import dnlib
from dnlib.DotNet import ModuleDefMD, FieldDef
from dnlib.DotNet.Emit import OpCodes

SAMPLE = r"sample.exe"
mod = ModuleDefMD.Load(SAMPLE)

def ldc_value(instr):
    name = instr.OpCode.Name
    if name in ("ldc.i4", "ldc.i4.s"):
        return int(instr.Operand)
    if name.startswith("ldc.i4."):
        tail = name.split(".")[-1]
        return -1 if tail == "m1" else int(tail)
    return None

def field_array(instr):
    op = instr.Operand
    if isinstance(op, FieldDef) and op.HasFieldRVA:
        return bytes(op.InitialValue)
    return None

def decrypt_all(data: bytes, key: int) -> bytes:
    return bytes(b ^ (i & 0xFF) ^ key for i, b in enumerate(data))

arrays, keys = [], []
for t in mod.GetTypes():
    for m in t.Methods:
        if not (m.HasBody and m.Body.HasInstructions):
            continue
        ins = m.Body.Instructions
        for i, x in enumerate(ins):
            if "InitializeArray" in x.ToString() and i > 0:
                arr = field_array(ins[i - 1])
                if arr:
                    arrays.append(arr)
            if (x.OpCode == OpCodes.Xor and i + 2 < len(ins)
                    and ins[i + 1].OpCode == OpCodes.Ldc_I4
                    and ins[i + 2].OpCode == OpCodes.Xor):
                k = ldc_value(ins[i + 1])
                if k is not None and k not in keys:
                    keys.append(k)

table = max(arrays, key=len)              # 最长数组通常是字符串表
key = next(k for k in keys
           if sum(32 <= c < 127 for c in decrypt_all(table[:100], k)) / 100 > 0.8)
plain = decrypt_all(table, key)

for t in mod.GetTypes():
    for m in t.Methods:
        if str(m.ReturnType) != "System.String" or not (m.HasBody and m.Body.HasInstructions):
            continue
        ins = m.Body.Instructions
        for i in range(3, len(ins)):
            if ins[i].OpCode != OpCodes.Call or "System.String" not in ins[i].ToString():
                continue
            idx, start, count = (ldc_value(ins[i - 3]), ldc_value(ins[i - 2]), ldc_value(ins[i - 1]))
            if None in (idx, start, count):
                continue
            if 0 <= start and start + count <= len(plain):
                print(m.Name, idx, start, count, plain[start:start + count].decode("utf-8", "replace"))
```

手工验证时可在 dnSpy 中直接对 `.cctor` 的数组做 `b ^ i ^ 0xAA`，再按访问器参数切片；示例样本解出的第一段是连在一起的键盘特殊键常量（`{BACK}`、`{ALT+TAB}`、`{F1}`…），进一步按切片可得到独立字符串，最终可还原 TorBrowser 下载地址、`%tordir%`、`%hash%` 等配置/外传字段。

## 变体与关联

- **key 与算法变体**：key 不一定为 170；也可能使用 `b ^ key`（不含索引）、`b ^ i`、多字节循环 key 或标准加密。应以 `.cctor`/解密函数的实际 IL 为准，不能硬编码 0xAA。
- **访问器变体**：Obfuscar 版本不同，`GetString` 的参数顺序、缓存数组类型（`string[]` 还是 `object[]`）和访问器命名可能变化；若三条 `ldc.i4` 的顺序不是 `index/start/count`，需结合 `GetString` 方法体确认。
- **多数组/多 key**：较大样本可能有多个 `InitializeArray` 数组（如资源、常量表）和多个 XOR 常量；文章用“最长数组 + ASCII 比例筛选”启发式，必要时可对每个数组/每个 key 组合做评分。
- **其它 .NET 字符串混淆**：XORStringsNet 使用 `[4B size][4B key][密文]` 记录表和逆序 XOR，与 Obfuscar 的“单一大数组 + offset/size 切片”完全不同；ConfuserEx、SmartAssembly、Eazfuscator 各有自己的定位特征。
- **同类工具链**：dnlib + pythonnet 的思路也可用于批量提取资源、方法签名、P/Invoke、字符串访问器；de4dot 的 `--strtyp delegate` 适合已知 token 的动态解密，但批量离线分析不如 dnlib。
- 关联：[[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]（另一种 .NET 字符串混淆的 dnfile 自动解密）、[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（轻量字符串拼接/API 包装还原）、[[code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis]]（dnSpy/VB.NET 样本分析方法）、[[mobile-android-apk-xor-string-batch-deobfuscation]]（移动端批量 XOR 字符串还原）。

## 检测与防御

- **静态检测**：YARA/PE 规则匹配 `Obfuscar` 保护器特征、大的 `FieldRVA` 静态字节数组、`.cctor` 中的 `xor`+常量+`xor` 循环、大量返回 `System.String` 的单字母访问器；dnfile/dnlib 扫描流水线可对“超大 InitializeArray 数组 + 统一 StringGetter”告警。
- **分析流水线**：把 dnlib 脚本接入样本预处理，自动输出字符串表、key、访问器映射；对解出的 URL/IP/文件路径/注册表键做 IOC 提取与同源样本聚类。
- **动态检测**：监控 `RuntimeHelpers.InitializeArray` 后的类构造、`Encoding.UTF8.GetString` 大批量调用、字符串缓存数组写入；内存扫描可在 `.cctor` 执行后 dump 明文数组。
- **防御侧认知**：Obfuscar 字符串隐藏只是弱混淆（单字节 XOR + 索引异或），静态元数据即可完整还原；提高分析成本需要标准加密/密钥派生，但不能替代行为检测。对 AgentTesla 类样本，应结合其键盘记录、浏览器凭据窃取、SMTP/FTP 外传等行为做主机与网络检测。
