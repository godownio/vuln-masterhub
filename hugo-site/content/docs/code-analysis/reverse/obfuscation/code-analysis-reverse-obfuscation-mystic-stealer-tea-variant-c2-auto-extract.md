---
id: code-analysis-reverse-obfuscation-mystic-stealer-tea-variant-c2-auto-extract
title: Mystic Stealer 类样本 C2 自动化提取：TEA 变种常量识别 + 指令特征码内联密钥 + .rdata 扫描解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: mystic-stealer-tea-variant-c2-auto-extract
tags:
- reverse
- obfuscation
- malware-analysis
- tea
- xtea
- config-extraction
- c2
- regex
- pe
- rdata
- automation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:31:46+08:00'
  notes: 已对照原文全文与10张图核对：32位无壳PE、0xC6EF3720/0x61C88647常量与32轮<<4/>>5结构、四个内联密钥0x7D935554/0x7A3B0639/0x4C774985/0x08F036C0、更新顺序v1先于v0且sum暂存、.rdata扫描流程与正则分组顺序均与原文一致；测试向量6f928688...已本机复跑解出http://193.233.254.61/。未验证点：未对真实样本批量运行脚本；原文未给组件版本，未设置versions；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-mystic-stealer-tea-variant-c2-auto-extract/
draft: false
kb_aliases:
- Mystic Stealer C2 提取
- TEA 变种配置解密
- XTEA 魔改密钥内联
- 0xC6EF3720 常量识别
- 常量展开与多态混淆
- 恶意样本 C2 批量提取
- 指令特征码密钥提取
---

## 一句话结论

Mystic Stealer 用常量展开 + 多态混淆隐藏 C2：C2 配置以改进型 XTEA 加密存放在 `.rdata`，密钥以立即数内联在解密函数里。识别 `0xC6EF3720`/`0x61C88647` 常量与 32 轮 `<<4`/`>>5` 结构后，用指令字节特征码一次性提取四个 key，再遍历 `.rdata` 候选数据块逐块解密并搜索 `http`，即可自动化还原 C2（原文样本解出 `http://193.233.254.61/`）。

## 原理

- **常量展开**：混淆器不直接写常量，而是用位移/加减在运行时算出（如把 8 写成 `2+2+2+2`），使静态常量搜索失效；但解密算法本身仍需要固定常量和轮数，这些值无法完全消失。
- **多态混淆**：每个样本用不同的简单数学运算在栈上构造字符串、在运行时解密；编译器优化会把解密密钥内联并分散到解密函数各处。因此不能依赖固定字符串或固定密钥，必须从算法结构上识别。
- **算法识别**：改进型 XTEA/TEA 的典型特征是 32 轮循环、两个 32 位 word 交替更新、`(v<<4)` 与 `(v>>5)` 混合、以及 delta 常量。原文样本中可直接搜到 `0xC6EF3720`（解密初始 sum）与 `0x61C88647`（等价于 `-0x9E3779B9` 的 delta）；findcrypt 的 `TEAN` 规则也用这两个字节序列 `20 37 EF C6` / `47 86 C8 61` 匹配。
- **样本解密顺序（与标准 TEA 不同）**：
  - 初始 `sum = 0xC6EF3720`，`delta = 0x61C88647`，32 轮；
  - 每轮先更新 `v1 -= ((v0<<4)+k2) ^ ((v0>>5)+k3) ^ (v0+sum)`；
  - 暂存 `temp_sum = sum`，再 `sum += delta`；
  - 最后用 `temp_sum` 更新 `v0 -= ((v1<<4)+k0) ^ ((v1>>5)+k1) ^ (v1+temp_sum)`。
  - 这一步顺序很关键：如果按标准 TEA 的先 v0 后 v1 或先加 sum 再算 v1，会解出乱码。
- **密钥映射**：原文从伪代码/汇编对照得到 `k0=0x7D935554`、`k1=0x7A3B0639`、`k2=0x4C774985`、`k3=0x08F036C0`。注意汇编里立即数的出现顺序是 k3、k2、k0、k1，正则分组要按这个顺序取，再重排为 `[k0,k1,k2,k3]`，否则解密失败。
- **C2 存放与定位**：加密 C2 放在 `.rdata`，没有固定偏移；用 `pefile` 取 `.rdata`，按连续 3 个以上 `\x00` 切成候选块，去掉首尾 `\x00` 后对每块尝试 0–15 字节的起始偏移，按 8 字节分组解密，命中 `http` 即认为找到 C2。
- **为什么可自动化**：算法常量、指令序列、密钥立即数、密文所在节都是样本内必有的静态特征；即使每个样本密钥不同，正则只要把四个立即数字节变成通配捕获即可批量提取。

## 触发条件

- 目标为 32 位 Windows PE，无壳或轻量壳，代码段可读。
- 存在 TEA/XTEA 家族解密函数：32 轮循环、`0xC6EF3720`/`0x61C88647` 常量、`<<4`/`>>5` 与两个 32 位 word 交替更新。
- 四个 32 位密钥以立即数内联在解密函数中，且指令序列在样本间保持稳定（同一混淆器/编译器生成）。
- 加密 C2 位于 `.rdata`（或可枚举的数据节），密文按 8 字节块排列。
- 分析者可运行 Python + pefile；样本不依赖强反调试（静态提取不需要执行样本）。

## 利用步骤

1. 用 PE 工具确认架构与节布局；在 IDA 中定位疑似解密函数（大量位移/异或/加减、32 次循环）。
2. 搜索 `0xC6EF3720` 与 `0x61C88647`（或小端字节 `20 37 EF C6`、`47 86 C8 61`）快速确认 TEA/XTEA 家族；也可用 findcrypt 的 `TEAN` 规则辅助。
3. 对照伪代码与汇编确认更新顺序、轮数、delta、初始 sum，并确定四个 key 的变量映射。
4. 从解密函数的指令字节构造特征码：把四个 key 立即数字节替换为 `(....)` 捕获组，保留周围的 `shr/shl/add/xor/sub/lea` 操作码。
5. 用 `re.search` 在文件字节中匹配特征码，按捕获顺序取 k3、k2、k0、k1，重排为 `[k0,k1,k2,k3]`。
6. 用 `pefile` 读取 `.rdata`，按 3 个以上 `\x00` 切分候选块；对每块尝试 0–15 字节偏移，按 8 字节分组调用解密函数。
7. 在解密结果中搜索 `http`/`https`，截断到 `\x00` 取第一个 URL；用已知测试向量验证算法实现（原文 `6f928688f64c75a5c916e8abe4560c29e279d7b750aba83f` → `http://193.233.254.61/`）。
8. 批量样本：把特征码进一步收敛为通配形式（固定操作码、key 通配），配合 VT vtgrep 或本地 YARA 扫描样本库，对命中样本重复步骤 5–7。

## PoC

TEA 变种解密（原文脚本核心）：

```python
import struct

def u32(x):
    return x & 0xffffffff

def tea_decrypt_block(v0, v1, k):
    k0, k1, k2, k3 = k
    sum_val = 0xC6EF3720
    delta = 0x61C88647
    for _ in range(32):
        v1 = u32(v1 - (((v0 << 4) + k2) ^ ((v0 >> 5) + k3) ^ (v0 + sum_val)))
        temp_sum = sum_val
        sum_val = u32(sum_val + delta)
        v0 = u32(v0 - (((v1 << 4) + k0) ^ ((v1 >> 5) + k1) ^ (v1 + temp_sum)))
    return struct.pack("<2L", v0, v1)

def decrypt(data, k):
    n = (len(data) // 8) * 8
    blocks = struct.unpack(f"<{n // 4}I", data[:n])
    return b"".join(tea_decrypt_block(blocks[i], blocks[i+1], k)
                    for i in range(0, len(blocks), 2))
```

密钥提取与 `.rdata` 扫描（简化）：

```python
import re, struct, pefile

egg = (rb'\xc1\xe8\x05\x05(....)\x33\xc8\x8b\xc3\xc1\xe0\x04\x05(....)'
       rb'\x33\xc8\x2b\xf1\x8b\xc6\xc1\xe0\x04\x05(....)\x8d\x0c\x37'
       rb'\x33\xc8\x8d\xbf\x47\x86\xc8\x61\x8b\xc6\xc1\xe8\x05\x05(....)'
       rb'\x33\xc8\x2b\xd9\x83\xed\x01')

data = open("sample.exe", "rb").read()
m = re.search(egg, data)
k3 = struct.unpack("<I", m.group(1))[0]
k2 = struct.unpack("<I", m.group(2))[0]
k0 = struct.unpack("<I", m.group(3))[0]
k1 = struct.unpack("<I", m.group(4))[0]
keys = (k0, k1, k2, k3)

pe = pefile.PE(data=data)
rdata = next(s.get_data() for s in pe.sections if b".rdata" in s.Name)
for chunk in re.split(rb"\x00{3,}", rdata):
    chunk = chunk.strip(b"\x00")
    if len(chunk) < 8:
        continue
    for off in range(min(len(chunk) - 7, 16)):
        out = decrypt(chunk[off:], keys)
        if b"http" in out:
            print(out.split(b"\x00")[0].decode("utf-8", "ignore"))
            raise SystemExit
```

验证向量：

```text
密文: 6f928688f64c75a5c916e8abe4560c29e279d7b750aba83f
密钥: 0x7D935554, 0x7A3B0639, 0x4C774985, 0x08F036C0
明文: http://193.233.254.61/
```

## 变体与关联

- 变体：标准 XTEA/XXTEA 或 TEA 的其他魔改（轮数、delta、更新顺序不同）；先按常量与结构识别，再对照伪代码还原顺序。
- 变体：密钥不是立即数而是从数据段/注册表读取；此时可在 `CryptDecrypt`/解密函数入口下断点，或回溯密钥加载点。
- 变体：C2 不在 `.rdata` 而在 `.data`/资源节/堆；把扫描范围换到对应节，或对整体文件做对齐扫描。
- 变体：批量狩猎时把指令特征码收敛为 YARA/VT vtgrep 规则，只保留操作码骨架与 key 通配，避免被单个样本的密钥差异干扰。
- 关联：[[code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt]]（同一类“配置加密 + 离线解密”的 CryptoAPI 路径）；[[code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract]]（多级载荷/配置提取）；[[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]（轻量字符串混淆还原）。
- 关联：findcrypt 插件、IDAPython 字符串/常量搜索可加速算法识别；批量样本可用 PE 节熵与导入表特征先做初筛。

## 检测与防御

- 检测（分析侧）：文件中同时出现 `0xC6EF3720` 与 `0x61C88647`、32 轮循环、`<<4`/`>>5` 交替更新，是 TEA/XTEA 家族的高置信特征；findcrypt/YARA 可先命中再人工确认。
- 检测（防御侧）：监控进程读取自身 `.rdata` 后调用解密函数并解析出 URL 的行为链；对含 TEA 常量与内联密钥的 PE 做静态告警。
- 防御：该混淆只提高分析成本，不构成安全边界；C2 配置应通过服务端下发或使用平台密钥管理，避免把长期密钥与密文一起打包。
- 响应：提取 C2 后封禁域名/IP，更新 YARA 与网络检测规则；同一特征码可回溯同家族其他样本，批量提取配置并关联基础设施。
