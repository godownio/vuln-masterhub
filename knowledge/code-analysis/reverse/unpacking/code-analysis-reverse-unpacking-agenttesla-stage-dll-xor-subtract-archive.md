---
id: code-analysis-reverse-unpacking-agenttesla-stage-dll-xor-subtract-archive
title: AgentTesla 阶段 DLL 还原两法：SimpleLogin.dll 用 22 字节滚动 key 异或后减后一字节（原地反馈），Gamma.dll 实为压缩包用归档工具解出 [Content]
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: agenttesla-stage-dll-xor-subtract-and-archive
aliases:
- SimpleLogin.dll 解密
- Gamma.dll 解密
- AgentTesla 多阶段载荷
- 22 字节 key 异或
- 减后一字节
- 原地反馈解密
- 压缩包伪装 DLL
- '[Content] 提取'
tags:
- reverse
- unpacking
- windows
- dotnet
- malware-analysis
- agenttesla
- xor
- stage-decryption
- archive
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T12:08:45+08:00'
  notes: 已对照原文与 img11-14 核对：SimpleLogin 解密 key J9EZ6H5428445+C755C8RZH（22 字节）、异或后减 a[(i+1)%len]+256 的原地反馈循环、输出 68KB .NET Assembly InternalName SimpleLogin.dll；Gamma 阶段 Key0 用 2345好压打开含 [Content]、解出 62KB .NET Assembly Gamma.dll 均一致；卡将两法作为同一阶段 DLL 还原场景的两个变体，原子性可接受；未对原样本实跑
---

## 一句话结论

AgentTesla 变体的阶段 DLL 有两种常见“解密”方式：`SimpleLogin.dll` 用由两段固定字符串拼成的 22 字节 key 做重复异或，再减去（原地数组中的）后一字节并取低 8 位，按索引顺序原地解密即可还原出 .NET 程序集；`Gamma.dll` 则根本不是加密代码，而是一个压缩容器，用归档工具（如 7-Zip/2345好压）直接打开并解出 `[Content]` 就是一个 .NET PE。

## 原理

- **SimpleLogin.dll 的变换**：设密文数组为 `a`，key 为 `first + second`（样本为 `J9EZ6H5428445` + `C755C8RZH`，共 22 字节），对每个下标 `i`：
  - `b = key[i % 22]`；
  - `num4 = a[i] XOR b`；
  - `num5 = num4 - a[(i+1) % len] + 256`；
  - `a[i] = num5 & 0xFF`。
  由于 `a` 是原地修改，`a[(i+1) % len]` 在 `i < len-1` 时尚未被改（后面才处理），但 `i = len-1` 时 `(i+1)%len = 0`，读到的是**已经解密过的首字节**——这是一个带首尾反馈的自引用变换。因此不能用“先异或再整体减固定值”的并行方式实现，必须严格按 `i=0..len-1` 的顺序原地执行；复现脚本若先把密文整体 XOR 再减，会因反馈点不同而解不出正确 PE。
- **为什么能识别为简单算法**：该变换只含 XOR、减法和字节截断，没有 S 盒/轮函数/大常数表；在反编译或调试加载器时表现为一个短循环，key 是相邻的两个字符串常量。作者样本中 `off` 文件解密后为 68KB 的 .NET Assembly（InternalName `SimpleLogin.dll`），可直接用 dnSpy/ilspycmd 分析。
- **Gamma.dll 为什么“用压缩软件就能解密”**：该阶段的文件（样本中名为 `Key0`）是压缩归档而非 PE/加密载荷；用 2345好压/7-Zip 打开可见条目 `[Content]`，解出后是 62KB 左右的 .NET Assembly（程序集名 `Gamma`，InternalName `Gamma.dll`）。这说明“阶段 DLL 文件名/扩展名”不可信，先看文件头（`PK`、`7z`、`RAR`、`MZ`）再决定解密/解压路径，可以避免对压缩数据硬套解密算法。
- **为什么这两步在批量分析中有用**：AgentTesla 的加载链会分阶段释放/解密 DLL（SimpleLogin、Gamma、Tyrone 等），最终载荷再走进程替换；直接复现每一层算法并提取每层 key 工作量大。对能解开的部分（固定 key 变换、压缩包）先离线还原，可拿到更多阶段样本与配置线索；解不开的部分再回到 `WriteProcessMemory` 断点抓最终载荷。

## 触发条件

- 已获得 AgentTesla 变体的阶段文件（如 `off`、`Key0` 等），且文件不是最终 PE（无 `MZ` 头或 PE 解析失败）。
- SimpleLogin 变体：能在加载器/样本中定位到两段固定 key 字符串与解密循环，或从公开分析中拿到同版本 key；密文长度已知。
- Gamma 变体：文件头/归档工具识别为压缩格式（或归档工具能强制打开），且解出的条目是 PE。
- 仅用于授权的恶意样本分析；解密脚本不运行样本。

## 利用步骤

1. 对阶段文件先做文件类型判断：`MZ`→PE，`PK`→ZIP，`7z`→7z，`Rar!`→RAR；都无则再按加密载荷处理。
2. **方法一（SimpleLogin.dll）**：在加载器代码/反编译结果中定位 key 拼接（如 `first`、`second` 两个字符串）与按 `i % keylen`、`(i+1) % len` 的循环；按第 3 步的原地顺序实现解密；输出文件后用 PEview/DIE 确认 .NET Assembly 与 InternalName。
3. **方法二（Gamma.dll）**：把阶段文件交给 7-Zip/2345好压打开（扩展名不对可强制指定格式），列出条目；解出 `[Content]` 等条目；对解出文件再做 PE 识别与反编译。
4. 对还原出的 DLL，用 dnSpy/ilspycmd 查看配置类字段（SMTP/FTP/URL），或继续跟踪下一阶段加载逻辑。
5. 若两种方法都不适用（算法/key 不可得），回到动态路径：在 `WriteProcessMemory`/`NtWriteVirtualMemory` 等写入点断点抓最终载荷，或用内存雕刻从进程 dump 中还原 PE。

## PoC

无漏洞利用 PoC；以下为按文章解密循环重写的 Script（未对真实样本实跑；`key` 与文件名需按变体替换）。

```python
def decrypt_simplelogin(data: bytes,
                        first: str = "J9EZ6H5428445",
                        second: str = "C755C8RZH") -> bytes:
    key = (first + second).encode("ascii")
    a = bytearray(data)
    n = len(a)
    for i in range(n):
        num4 = a[i] ^ key[i % len(key)]
        num5 = num4 - a[(i + 1) % n] + 256   # 原地数组，末字节反馈到 a[0]
        a[i] = num5 & 0xFF
    return bytes(a)

# 用法：open("off","rb").read() -> decrypt_simplelogin(...) -> 写 off_dec_SimpleLogin.dll
# 结果应为 MZ 开头、PEview/DIE 识别为 .NET Assembly，InternalName=SimpleLogin.dll
```

```text
# 方法二：Gamma.dll（压缩包伪装）
7z l  Key0          # 或 2345好压打开，查看条目
7z x  Key0  -oout   # 解出 [Content]（PE，.NET Assembly, InternalName=Gamma.dll）
```

## 变体与关联

- 变体：key 两段字符串/长度随变体变化；有的变体把 key 拆成更多段或运行时拼接，需在加载器里定位最终 22 字节缓冲区，而不是硬编码样本中的字符串。
- 变体：Gamma 阶段的归档可能是 ZIP/7z/RAR 或带自定义头；先识别文件头，必要时用 `binwalk`/归档工具强制格式；若条目名不是 `[Content]`，按所有 PE 条目逐个尝试。
- 变体：若解密循环把 `a[(i+1)%len]` 写成“原始密文的后一字节”（先拷贝一份密文再解密），则没有首尾反馈，可并行实现；需以实际反编译代码为准。
- 关联：[[code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve]]（解不开阶段算法时的兜底：断点抓最终载荷 + 内存雕刻）、[[code-analysis-reverse-unpacking-pyinstaller-appended-zip-footer-dropper]]（压缩容器伪装/尾部归档的识别）、[[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]（内嵌 PE 的 XOR 解密与 MZ 定位）、[[code-analysis-reverse-windows-machineguid-md5-aes-cfb-payload-binding]]（载荷与配置的机器绑定/完整性校验）。

## 检测与防御

- 检测：样本侧可检测分析工具与调试器；防御方可监控进程加载非签名 .NET DLL、临时目录释放的 `SimpleLogin.dll`/`Gamma.dll` 类阶段性文件名，以及后续 SMTP/FTP 外连行为；对内存中出现的 PE 头做扫描。
- 防御：加载器可改成运行时从网络拉取 key、把多阶段载荷放在加密配置中、或使用系统 API 映射（`NtMapViewOfSection`）减少明文落盘；分析侧则需结合动态断点与内存雕刻。
- 说明：本文是恶意样本阶段载荷还原技术，severity 记为 low，confidence 记为 medium（SimpleLogin 解密循环已按文章代码复现逻辑，但 key/样本随变体变化，未对原样本实跑）。
