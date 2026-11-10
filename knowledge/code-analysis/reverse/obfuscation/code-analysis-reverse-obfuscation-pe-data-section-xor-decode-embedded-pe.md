---
id: code-analysis-reverse-obfuscation-pe-data-section-xor-decode-embedded-pe
title: PE .data 节整体 XOR 加密：高熵 RW 节区 + 运行时逐字节解码还原字符串表与内嵌 PE
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: pe-data-section-xor-decode
aliases:
- .data 节加密
- 节区熵值异常
- XOR 解码循环
- 内嵌 PE 运行时还原
- 高熵 .data 节
- 高熵 RW 节区
tags:
- reverse
- pe
- xor
- data-section
- entropy
- obfuscation
- embedded-pe
- malware-analysis
- windows
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343-fix
  verified_at: '2026-11-08T22:46:12+08:00'
  notes: V343 核对指出：原文图07 节表 .data characteristics=0xC0000040（READ|WRITE，不含 EXECUTE；仅 .text/.bss 可执行），卡内标题/一句话结论/原理/步骤1/检测多处误写 0xE0000040 与 RWX。已按原文统一修正为高熵 RW 节区（0xC0000040），并说明解码出的 PE 不在本节执行、而是写入挂起 RegAsm.exe；别名同步调整。主会话按 V343 结论修正后转 verified；XOR 循环/解码字符串/内嵌 MZ 等其余核对项不变。
---

## 一句话结论

样本把 C2 URL、User-Agent、窃取路径等字符串与一个完整的内嵌 PE 一起放进 `.data` 节，构建时整体 XOR 加密；静态看该节熵值约 7.98、字节分布均匀、节属性为可读可写（`0xC0000040`，不含执行），运行时由一段紧凑的 `xor byte ptr ds:[ecx+ebx], al` 循环解码，解码后内存中直接出现 `MZ` 头和明文 URL，按「熵值/节属性定位 → 找解码循环 → 解码后 dump」即可还原。

## 原理

- **为什么放在 `.data`**：编译器把已初始化的全局变量和字符串常量放进 `.data`/`.rdata`；把这一节整体加密，可以一次性藏住所有静态字符串（C2、UA、目标路径）和内嵌载荷，`strings`、YARA、导入表之外的静态特征全部失效。
- **可观测异常**：正常 `.data` 熵值通常在 4–6 之间；该样本 `.data` 熵值 7.98（`.text` 6.60、`.rdata` 4.71），字节直方图几乎均匀，说明内容接近随机/加密。该节属性为 `0xC0000040`（READ|WRITE，不含 EXECUTE；原文节表中仅 `.text`/`.bss` 可执行），解码时需要写入本节；解码出的 PE 并不在本节直接执行，而是随后写入挂起的 `RegAsm.exe` 执行。
- **解码方式**：反汇编可见按索引遍历节区的循环，密钥字节从栈上小表/变量取出（`mov al, byte ptr ss:[esp+eax+60]`），再对目标字节做 XOR（`xor byte ptr ds:[ecx+ebx], al`），循环边界与节大小/固定常量比较（截图中出现 `cmp ecx, 0x1000`）。属于「整节单字节/按索引循环 XOR」，强度低但足以对抗静态扫描。
- **解码结果**：解码后的 `.data` 同时包含多组明文——`steamcommunity.com/profiles/...`、`t.me/...`、Mozilla/Safari UA、`sqlite3.dll`、Chrome/Brave/Opera 路径、`WinSCP 2\Sessions`、`FileZilla\recentservers.xml` 等——以及一个完整 PE（起始为 `4D 5A`、DOS stub、`PE` 头）。该 PE 随后被写入挂起的 `RegAsm.exe` 执行。
- **为什么有效**：静态文件里没有可搜索的 URL/API 名/PE 头；只有运行到解码函数之后明文才出现在内存。解密代码本身很小、密钥可放在栈上，逆向时需要理解循环而非直接提字符串。
- **弱点**：解码循环必然存在且可定位（对 `.data` 的写引用、循环 XOR 指令）；高熵 + 异常节区本身就是强特征；运行时明文在内存中，可在解码后下断或 dump 进程内存一次性还原全部配置与载荷。

## 触发条件

- 分析者拿到 PE 样本（无需运行），具备 IDA/x64dbg 或可模拟执行的环境。
- 样本在启动早期（反调试检查之后、网络请求之前）执行解码，使断点/模拟可以赶在配置使用前命中。
- 若只做静态分析，需要能从反汇编恢复 XOR 密钥与节区范围。

## 利用步骤

1. 用 PE 工具/脚本读取节表，计算各节熵值与属性；标记高熵且属性异常的节区（本例 `.data` 熵 7.98、大小约 200KB、`0xC0000040` = READ|WRITE，不含执行）。
2. 在 IDA/x64dbg 中查找对该节区的写引用（`xor [reg+reg], reg` 形式），定位解码循环及其调用点；确认密钥来源（栈上表/常量/位置相关）与循环边界。
3. 在解码循环结束后下断点（或对解码区设置硬件写断点），运行到明文生成；dump 整个节区。
4. 在 dump 中搜索 `MZ`/`PE` 与 `http`、`\\` 路径、UA 等字符串；按 `MZ` + `e_lfanew` 校验并切出内嵌 PE。
5. 若无法动态运行，按反汇编重写 XOR（逐字节、密钥表/索引规则），在 Python 中离线解码节区，再执行第 4 步。
6. 将还原出的 URL、UA、路径、内嵌 PE 哈希纳入 IOC；继续分析内嵌 PE 的注入/通信逻辑。

## PoC

```python
import math, collections

def entropy(b):
    n = len(b)
    c = collections.Counter(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

# 从 PE 节表取 .data 的 raw 数据（示意）
raw = open('sample.bin', 'rb').read()
data = raw[0x2600:0x2600 + 209920]   # 以实际 PointerToRawData/SizeOfRawData 为准
print('entropy =', entropy(data))     # 接近 7.98 说明高熵/加密

# 按反汇编恢复的规则离线解码（示例：密钥表 0x60 字节 + 逐字节 XOR，具体以样本为准）
def decode(buf, keytab):
    out = bytearray(buf)
    for i in range(len(out)):
        out[i] ^= keytab[i % len(keytab)]
    return bytes(out)

# 解码后搜索 MZ / URL / 路径
plain = decode(data, b'\x00' * 0x60)
print(plain.find(b'MZ'), plain.find(b'https://'))
```

说明：密钥表与循环规则需以目标样本反汇编为准；上面仅为「熵值定位 + 离线 XOR 还原」的最小骨架。

## 变体与关联

- [[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]：shellcode 内嵌 PE + 改 PE 签名 + 逐字节 XOR，与本卡「整节加密 + 内嵌 PE」互补。
- [[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]：.NET 字符串级 XOR 自动解密；本卡是 PE 节区级整体加密。
- [[code-analysis-reverse-obfuscation-mystic-stealer-tea-variant-c2-auto-extract]]：TEA 变种加密 `.rdata` 配置；可对比「整节加密」的不同算法（TEA/AES/RC4）。
- [[pentest-c2-encrypted-payload-dialer-injection-watchdog-mutex]]：32 字节随机串循环 XOR 加密多个 PE 后注入合法进程；同属「加密载荷 + 合法宿主」组合。
- 变体：整节加密可换成按字符串逐条加密、把载荷放入资源节（`.rsrc`）、或只在内存中解密（无文件落盘）；算法可换 RC4、TEA、AES-CBC、滚动密钥。
- 关联：本样本解码出的 PE 被写入挂起 `RegAsm.exe`，见 [[pentest-c2-vidar-suspended-regasm-embedded-pe-injection]]。

## 检测与防御

- 检测（静态）：PE 节表中出现高熵（>7）且 READ|WRITE 的 `.data`（本例 `0xC0000040`，不含执行）；节区原始数据中 `MZ`/URL/API 名均不可见；代码段存在对同一节区的循环 XOR 写操作；节大小与虚拟大小接近但内容随机。
- 检测（内存）：进程内存扫描发现第二个 `MZ` 头、明文 C2 URL 或高熵区域被解密后的 PE；对 `.data` 区域做周期快照比对可发现运行时解密。
- 检测（行为）：解码后立即出现进程注入、C2 请求或文件收集；可将「高熵 .data + 早期解密 + 注入」作为组合规则。
- 防御：启用内存扫描/EDR 对 RWX 私有内存与跨进程写的监控；应用白名单阻止未签名样本；YARA 规则关注「高熵 .data + XOR 循环 + 内嵌 PE 特征」而非固定字符串。
- 分析建议：优先动态断在解码循环之后 dump，一次拿到全部配置与载荷；静态重写解码时注意密钥可能随索引/已解码字节滚动，不能简单假设单字节常量。
