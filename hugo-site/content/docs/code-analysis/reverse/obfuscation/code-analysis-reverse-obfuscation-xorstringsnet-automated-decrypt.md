---
id: code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt
title: XORStringsNet 字符串自动解密：ClassLayout 最大 Size + FieldRVA 相邻差定位加密表，逆序+单字节 XOR 还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: xorstringsnet-classlayout-fieldrva-automated-decrypt
tags:
- dotnet
- reverse
- obfuscation
- string-encryption
- xor
- malware-analysis
- dnfile
- de4dot
- yara
- agenttesla
- redline
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V153
  verified_at: '2026-11-06T07:44:45+08:00'
  notes: 已对照原文与20张图核对：YARA msil_susp_obf_xorstringsnet 特征 06 1E 58 07 8E 69 FE 17、Decrypt(id) 的 0x420+偏移/cpblk(data+8)、首尾三步 XOR 交换+奇数中间字节、老版本单字节 key 与新版本 key[i%4]/key_data[i%key_data.Length]、ClassLayout max Size=19516 + FieldRVA 相邻差定位 RVA 0x1BB7B/文件偏移 0x19D7B、de4dot token 0x06000101 与命令 0x6000000、自动脚本输出 28 个字符串（含 /log.tmp）均一致；路径/无 sources/source_url；原文未给混淆器版本区间，未设 affected_versions。未验证点：未执行样本；脚本结果按原文截图核对。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt/
draft: false
kb_aliases:
- XORStringsNet
- XorStringsNET
- AgentTesla 字符串解密
- Redline Stealer 字符串解密
- dr4k0nia
- dnfile 自动解密
- de4dot --strtyp delegate
- FieldRVA 定位
- tdExplicitLayout
- msil_susp_obf_xorstringsnet
---

## 一句话结论

XORStringsNet 把字符串以 `[4 字节长度][4 字节 key][密文]` 的记录表形式放进一个 `StructLayout(LayoutKind.Explicit, Size=N)` 的大结构体；运行时用 `cpblk` 拷出密文，再做“首尾 XOR 交换 + 注入 key”的解密。老版本只用了 key 的低 8 位，因此等价于“密文逆序后逐字节异或单字节 key”。自动化定位时，用 dnfile 取所有 `tdExplicitLayout` 的 `ClassLayout.ClassSize` 最大值作为表大小，再找相邻 `FieldRVA` 差值等于该大小的那一行，即得到加密表 RVA；按记录解析、逆序、单字节 XOR 即可批量还原字符串。

## 原理

- **XORStringsNet 的背景**：它是 dr4k0nia 开源的一键 .NET 字符串混淆器，被 AgentTesla、Redline Stealer 等恶意软件家族大量使用；作者后来发布了 YARA 规则 `msil_susp_obf_xorstringsnet`（特征字节 `06 1E 58 07 8E 69 FE 17`，`dotnet.is_dotnet`，文件 <25MB）来检测自己的混淆器及其衍生变体。
- **数据布局**：加密表开头有一个 4 字节“全局 XOR key”（用于解密传给解密方法的参数），随后是若干记录：`[4 字节长度][4 字节 key][长度字节的密文]`。每条记录有自己的 key；老版本代码只取 key 的低 8 位。
- **运行时解密**：`Decrypt(int id)` 用 `data = (byte*)0x420 + (id ^ *(int*)data)` 定位记录；`buffer = new byte[*(int*)data]`；`cpblk(data + 8, ptr, buffer.Length)` 把密文拷进 buffer（`+8` 跳过 length 和 key 两个 4 字节字段）；随后循环：
  ```csharp
  for (int i = 0, n = buffer.Length - 1; i < n; i++, n--) {
      buffer[i] ^= buffer[n];
      buffer[n] ^= (byte)(buffer[i] ^ key);
      buffer[i] ^= buffer[n];
  }
  if (buffer.Length % 2 != 0)
      buffer[buffer.Length >> 1] ^= key;
  ```
  这组三步异或交换等价于：先把密文整体逆序，再对每个字节异或 key；奇数长度时中间字节再异或一次 key。
- **老版本的 bug**：`key` 是 4 字节 int，但代码只做 `(byte)key` 强制转换，实际只用低 8 位；因此即使不知道完整 4 字节 key，也可以对 256 个单字节暴力尝试。文章分析的样本正是这个老版本，CyberChef 用 `Reverse by Byte` + `XOR DD` 就能得到 `/log.tmp`。新版本改为 `key_data[i % key_data.Length]`，需要按 4 字节 key 循环异或。
- **为什么反编译器看不到数据**：C# 编译器把大的连续字节数组放进一个带 `[StructLayout(LayoutKind.Explicit, Pack=1, Size=N)]` 的类/结构体；dnSpy 等默认只显示一个空结构体和一个静态字段，不显示原始字节，所以字符串表在常规视图里“消失”，只能通过 FieldRVA/内存地址定位。
- **手动定位**：在 dnSpy 里找到解密函数的 MethodDef Token（样本中为 `0x06000101`，文章命令写作 `0x6000000`），以及静态字段的 RVA（样本 0x1BB7B，文件偏移 0x19D7B）；用 `de4dot.exe <sample> --strtyp delegate --strtok 0x6000000` 让 de4dot 以委托方式调用解密函数，生成 `-cleaned` 文件后字符串已解密。也可以直接按 RVA 读出记录，用 CyberChef 逆序 + XOR 验证。
- **自动定位的核心思想**：
  1. **最大 ClassSize**：遍历 `ClassLayout` 表，只保留 `TypeDef.Flags.tdExplicitLayout` 为真的行，取 `ClassSize` 最大值；加密表通常是程序中最大的显式布局结构体（样本为 19516 字节）。
  2. **FieldRVA 相邻差**：`FieldRva` 表记录各静态字段数据的 RVA；如果相邻两行的 `next.Rva - curr.Rva` 正好等于最大 ClassSize，则 `curr.Rva` 就是加密表起点。若没找到，退回用最后一个 FieldRVA 行。
  3. **记录解析**：从 RVA 读 `ClassSize` 字节；跳过前 4 字节全局 key；循环读 `size`（4 字节小端）、`key`（4 字节，只取第一字节）、`size` 字节密文；`密文[::-1]` 后逐字节 XOR key；UTF-8/ASCII 解码。`size == 0`、`size > 0x100` 或解码出非 ASCII 时停止，防止读到垃圾。
- **为什么用 dnfile**：dnfile 是纯 Python 的 .NET 元数据解析库，不需要在 Windows/CLR 上运行样本，适合批量、离线、沙箱外分析；相比模拟执行解密函数，它不依赖样本能否运行，也不会触发反调试/环境检测。
- **YARA 回扫**：作者用上述 YARA 规则回扫发现大量样本命中，说明该混淆器在恶意软件生态中被广泛复用；分析时可先用 YARA 判断是否 XORStringsNet，再跑自动解密脚本。

## 触发条件

- 样本是 .NET PE（有 CLR 头、`dotnet.is_dotnet`），并使用 XORStringsNet 或其衍生混淆器。
- 元数据中存在 `tdExplicitLayout` 的 `ClassLayout` 行，且字符串表是其中 ClassSize 最大的结构体；`FieldRVA` 表中有对应的连续数据项。
- 老版本（单字节 key）可直接用单字节 XOR 解密；新版本需要按完整 4 字节 key 循环异或，或先通过动态调试确认 key 方案。
- 分析环境有 Python 3 + `dnfile`，或 Windows 上有 dnSpy/de4dot/CyberChef 做手动验证。
- 加密表未被额外压缩/加密（XORStringsNet 本身只做 XOR + 逆序；若样本再套壳/压缩，需要先脱壳）。

## 利用步骤

1. 用 YARA 规则 `msil_susp_obf_xorstringsnet`（`06 1E 58 07 8E 69 FE 17`）或 `dnfile` 判断样本是否为 .NET 且命中 XORStringsNet 特征。
2. 手动验证：dnSpy 打开样本，找到解密函数（特征：频繁被调用、传入较大整数、返回 string、内部有 `cpblk` 和首尾交换循环）；记下 MethodDef Token 和静态字段 RVA/文件偏移。
3. 用 `de4dot.exe <sample> --strtyp delegate --strtok <token>` 生成 `-cleaned` 文件，确认字符串已解密；或用 CyberChef 按 RVA 取一条记录，`Reverse by Byte` + `XOR <key>` 验证算法。
4. 自动化：用 `dnfile.dnPE` 解析元数据，收集所有 `tdExplicitLayout` 的 `ClassLayout.ClassSize`，取最大值；遍历 `FieldRva.rows`，找相邻 RVA 差等于该最大值的行，得到表 RVA。
5. 读取该 RVA 处的 `ClassSize` 字节；跳过开头 4 字节全局 key；循环读长度/key/密文，`密文[::-1]` 后逐字节 XOR 首字节 key，UTF-8 解码并收集。
6. 对结果做 ASCII/可打印性校验；若出现大量乱码，说明定位错误或样本使用新版完整 key，需要换 `xor_crypt` 为 4 字节循环 key，或回到动态调试确认。
7. 将解密结果写回 dnSpy/de4dot 或生成 IDA 注释，继续分析 C2、文件路径、注册表键等。

## PoC

手动解密核心（老版本单字节 key）：

```python
def xor_crypt(data: bytes, key: int) -> str:
    return bytes(b ^ key for b in data).decode("utf-8", errors="ignore")

# 记录格式: [4B size][4B key][size B data]
key_byte = data[ptr]                 # 只取 key 的第一个字节
cipher = data[ptr + 4: ptr + 4 + size]
plain = xor_crypt(cipher[::-1], key_byte)
```

自动化定位（dnfile，原文脚本核心）：

```python
import struct
import dnfile

def extract_and_decrypt_strings(file_path: str):
    pe = dnfile.dnPE(file_path)

    # 1) 找最大的 tdExplicitLayout 结构体
    sizes = []
    for row in pe.net.mdtables.ClassLayout.rows:
        type_row = pe.net.mdtables.TypeDef.rows[row.Parent.row_index - 1]
        if type_row.Flags.tdExplicitLayout:
            sizes.append(row.ClassSize)
    target_size = max(sizes)

    # 2) 相邻 FieldRVA 差值 == target_size，定位表 RVA
    target_rva = None
    rows = pe.net.mdtables.FieldRva.rows
    for i in range(len(rows) - 1):
        if rows[i + 1].Rva - rows[i].Rva == target_size:
            target_rva = rows[i].Rva
            break
    if target_rva is None and rows:
        target_rva = rows[-1].Rva

    # 3) 解析记录并解密
    data = pe.get_data(target_rva, target_size)
    out, ptr = [], 4                      # 跳过 4 字节全局 key
    while ptr + 4 <= len(data):
        size = struct.unpack("<I", data[ptr:ptr + 4])[0]
        if size == 0 or size > 0x100:
            break
        ptr += 4
        key_byte = data[ptr]              # 老版本只用第一个字节
        ptr += 4
        cipher = data[ptr:ptr + size]
        ptr += size
        text = bytes(b ^ key_byte for b in cipher[::-1]).decode("utf-8", errors="ignore")
        if not text.isascii() or not text.strip():
            break
        out.append(text)
    return out
```

de4dot 手动法：

```bat
de4dot.exe sample.exe --strtyp delegate --strtok 0x6000000
```

原文样本（sha256 `023e6c15...ebf3e70`）实测自动脚本输出 `SC`、`/log.tmp`、`KL`、`<br>[`、`yyyy-MM-dd HH:mm:ss` 等 28 个字符串；本卡不执行样本。

## 变体与关联

- **新版完整 key**：把 `xor_crypt` 改成 `b ^ key_data[i % len(key_data)]`，其中 `key_data` 是记录中的 4 字节 key；老版本的单字节假设不再成立。
- **RDXR 变体**：文章提到 `RDXR` 类实现使用 `BitConverter.GetBytes(key)` 取完整 4 字节 key，并按 `i % key_data.Length` 循环；遇到 `RDXR`/新版 XorStrings 时要按此处理。
- **其它定位方法**：统计“被调用次数最多的函数”找到解密函数；用 `cpblk` 指令特征；用独特嵌套私有结构体；或暴力枚举大结构体。文章最终选择“最大 ClassSize + FieldRVA 相邻差”，因为纯元数据、无需执行样本。
- **动态方法**：de4dot 的 `--strtyp delegate --strtok` 让目标解密函数在 CLR 中实际执行，适合脚本/Token 已知的单个样本；自动化批量分析不如 dnfile。
- **其它 .NET 字符串混淆**：ConfuserEx 的常量加密、SmartAssembly、Eazfuscator 等结构不同，需按各自特征定位；本卡只针对 XORStringsNet 及其衍生。
- 关联：[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（另一种 .NET 字符串混淆还原）、[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（脚本层参数解密）、[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]（PE 加载器/二阶段解密）。

## 检测与防御

- **YARA 检测**：使用 `msil_susp_obf_xorstringsnet`（`{ 06 1E 58 07 8E 69 FE17 }`）及作者后续规则；结合 `dotnet.is_dotnet`、文件大小、`cpblk` 特征和大 ExplicitLayout 结构体做启发式。
- **元数据扫描**：在沙箱/批量分析流水线中用 dnfile 解析 `ClassLayout`/`FieldRVA`，对“最大显式布局结构体 + 大量静态字段数据”的样本告警；对 XORStringsNet 特征直接跑自动解密提取 IOC。
- **动态检测**：监控 `cpblk` 解密循环、`string.Intern` 调用、运行时反射/委托调用解密函数；内存扫描可在字符串被 `Intern` 后 dump 明文。
- **对恶意软件作者的“缓解”**：仅 XOR + 逆序、单字节 key 是弱混淆，容易被静态/暴力还原；应使用完整 key、标准加密/KDF，但这只是提高分析成本，不能替代检测。
- **分析侧**：自动脚本要对新版 key 方案做兼容，并对解密结果做 ASCII/可打印性/语言模型校验，避免把错误定位的随机字节当字符串；保留手动 dnSpy/de4dot 验证路径。
- **IOC 产出**：解密后的 URL、IP、文件路径、注册表键、互斥体名可直接用于检测规则和威胁情报。
