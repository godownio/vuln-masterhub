---
id: code-analysis-reverse-unpacking-speakeasy-memory-dump-base64-pe
title: Speakeasy 仿真运行 UPX 样本并 dump 内存：定位 Base64 内嵌 PE 二阶段
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: speakeasy-memory-dump-base64-pe-stage2
aliases:
- Speakeasy 脱壳
- Speakeasy 内存镜像
- TVqQ Base64 PE
- 内存 dump 找二阶段
- UPX + 内嵌 PE
tags:
- reverse
- unpacking
- speakeasy
- emulation
- memory-dump
- base64
- pe
- upx
- malware
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:49:22+08:00'
  notes: 已对照原文与images 12/14核对：UPX壳、导入表仅LoadLibraryA/GetProcAddress/VirtualProtect、Speakeasy run_module+get_memory_dumps、内存镜像搜索TVqQ长Base64、解码得二阶段PE、.hello/.mydata RC4加密与.rdata密钥、后续AES/UUID均与原文一致。未验证点：未复跑Speakeasy；TVqQ严格对应MZ\x90的Base64（MZ本身为TVo=），作为PE检索启发式成立，卡内表述略宽。
---

## 一句话结论

对 UPX 壳、导入表只有 `LoadLibraryA`/`GetProcAddress`/`VirtualProtect` 的样本，用 Speakeasy 仿真运行并 dump 客户机内存，可避免直接执行恶意代码就拿到解包后的镜像；在 dump 中搜索以 `TVqQ` 开头的长 Base64（`MZ` 的 Base64 前缀），解码即得二阶段 PE，再继续逆向其 RC4/AES 逻辑。

## 原理

- UPX 把原始 PE 压缩到壳节，运行时 stub 解压、修复导入并跳到 OEP；如果样本被改过（节名/入口/压缩算法），`upx -d` 可能失败。动态仿真是替代方案：只让 stub 在模拟器里跑，不执行最终业务代码。
- Speakeasy 加载 PE 后模拟 Windows API，`run_module(mod, all_entrypoints=True)` 执行入口；`get_memory_dumps()` 返回客户机内存区域，其中包含解压后的代码与数据。把它写成文件即得到“内存镜像”。
- 二阶段载荷常以 Base64 文本嵌在解包后的数据里。`MZ`（`4D 5A`）的 Base64 前缀是 `TVqQ`（更完整地看 `TVqQ...`），因此可用正则 `TVqQ[A-Za-z0-9+/=]{1000,}` 在内存镜像中定位长 Base64 块；解码后若以 `MZ` 开头，就是一个完整 PE。
- 示例二阶段 PE 的 `.hello`/`.mydata` 节被 RC4 加密，密钥在 `.rdata`；`.hello` 解密后是输入校验主逻辑，`.mydata` 保存密钥、IV、校验常量与最终泄露的 UUID。分析时先定位 RC4 的 KSA/PRGA 特征（256 字节数组、交换、异或），再用 `.rdata` 中的密钥解密两个节。
- 这样分层的原因：第一层 UPX 只是压缩，第二层 Base64 是编码，第三层 RC4 是加密；每层都需要不同的处理方式，不能把内存镜像直接当最终样本。

## 触发条件

- 样本为 UPX 或类 UPX 壳，`upx -d` 失败/不可用；导入表极少（`LoadLibraryA`、`GetProcAddress`、`VirtualProtect` 等）。
- 不想或不能在真实主机运行样本；有 Speakeasy（或 Qiling/Unicorn）仿真环境。
- 解包后的内存镜像里存在长 Base64 文本或嵌入的 PE/ELF 数据。
- 需要继续分析二阶段（RC4/AES/配置/外联地址）。

## 利用步骤

1. 静态分诊：`file`、`strings`、PE 节表、导入表；确认 UPX 特征或异常入口。
2. 用 Speakeasy 加载样本，`run_module(..., all_entrypoints=True)`；遍历 `get_memory_dumps()`，把内存区域写盘。
3. 在 dump 中搜索 `TVqQ`/`UEsDB`/`f0VMR` 等 Base64 头，或直接搜索 `MZ`/`PK`/`ELF` 原始字节；对命中的长 Base64 解码并校验文件头。
4. 将二阶段 PE 放入 IDA/Ghidra；检查节区（如 `.hello`、`.mydata`）是否高熵，定位解密函数。
5. 识别 RC4：256 字节 S 数组、KSA 交换循环、PRGA 的 `S[i]+S[j]` 取字节异或；从 `.rdata` 提取密钥，解密目标节。
6. 解密后分析输入校验/AES 表/配置，提取硬编码 UUID、密钥或外联地址；必要时再用 Speakeasy 仿真二阶段。

## PoC

```python
from speakeasy import Speakeasy

se = Speakeasy()
mod = se.load_module("challenge1.exe")
se.run_module(mod, all_entrypoints=True)

# 取第一块内存 dump；实际样本可能有多个区域，需遍历
name, base, size, is_free, proc, data = next(se.get_memory_dumps())
open("unpacked.bin", "wb").write(data)
```

```python
import re, base64

buf = open("unpacked.bin", "rb").read()
# MZ 的 Base64 前缀是 TVqQ；长串才可能是完整 PE
m = re.search(rb"TVqQ[A-Za-z0-9+/=]{1000,}", buf)
stage2 = base64.b64decode(m.group())
open("stage2.exe", "wb").write(stage2)
print(stage2[:2])          # b"MZ"
```

```python
# RC4 特征（解密 .hello/.mydata 时按目标实现填 key）
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)
```

## 变体与关联

- 变体：不同壳（UPX 改版、ASPack、自定义 LZ）都可用 Speakeasy/Qiling/Unicorn 仿真；只需让 stub 跑到 OEP 并 dump 目标区域。
- 变体：二阶段不一定是 Base64 PE；也可能是原始 shellcode、ELF、ZIP、加密 blob；先看内存镜像中的文件头/高熵块。
- 变体：Base64 前缀随文件类型变化（`MZ`→`TVqQ`、`PK`→`UEsDB`、ELF→`f0VMR`）；也可直接搜索原始 magic。
- 关联：[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（改版 UPX + Unicorn 仿真，另一种 dump 实现）、[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]（二阶段 PE 加密加载）、[[code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump]]（调试器 dump shellcode）。
- 边界：Speakeasy 对某些 API/反调试支持有限，样本可能跑不到 OEP；内存 dump 可能被截断或分片；Base64 可能被拆分/混淆，需按上下文拼接。

## 检测与防御

- 分析侧：优先在隔离环境用仿真器跑壳，不直接执行未知样本；对 dump 做熵分析、字符串与 magic 扫描。
- 检测：PE 导入表极少 + UPX/壳特征；内存镜像中出现 `TVqQ`/`UEsDB` 长 Base64 或嵌入 PE；进程/仿真器加载后出现异常内存写与跳转。
- 防御：不要仅依赖 UPX 特征判断样本；对下载/邮件附件做静态+动态沙箱；限制临时目录执行与出站网络；对内存 dump 中的嵌入 PE 做二次扫描。
