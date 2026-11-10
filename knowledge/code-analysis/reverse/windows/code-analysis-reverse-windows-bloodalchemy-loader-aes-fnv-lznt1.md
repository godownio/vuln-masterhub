---
id: code-analysis-reverse-windows-bloodalchemy-loader-aes-fnv-lznt1
title: BloodAlchemy/Deed RAT 多阶段加载链：BrDifxapi.exe DLL 侧加载 → DIFX AES-128-CBC 解壳 → FNV-1a 自解密 + LZNT1 → 45AB45AB 自定义载荷映射
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: bloodalchemy-dll-sideload-aes-fnv-lznt1-loader
aliases:
- BloodAlchemy 加载链
- BloodAlchemy 分析
- DIFX 解密
- BrLogAPI.dll 侧加载
- 45AB45AB 载荷格式
- FNV-1a + LZNT1 解壳
- Deed RAT 载荷结构
tags:
- reverse
- windows
- malware
- bloodalchemy
- deed-rat
- shadowpad
- dll-sideloading
- aes
- fnv1a
- lznt1
- shellcode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:58:43+08:00'
  notes: 已对照原文与20张图核对：三文件布局与大小（BrDifxapi.exe 111472/BrLogAPI.dll 129536/DIFX 66112）、计划任务 Tasks\Dell\BrDifxapi（图3）、BrLogAPI.dll 读 DIFX 后 aes_init/aes_dec(dec_shellcode+16,enc_data)（图4）、AES128 CBC 与文件前16字节密钥（图5）、FNV-1a offset_basis 2166136261/prime 16777619 自解密（图6）、RtlDecompressBuffer LZNT1 输出0x17000（图7）、45AB45AB 载荷头与三节 rep movsb 映射（图8）、Deed RAT 54 45 ED DE/0x20/0x1740 对比（图19）均一致。PoC 仅 AES 第一层骨架且注明 IV 需按 aes_init 校正，未执行样本。卡片只覆盖加载链，与配置解密、行为狩猎两卡为不同技术面，非重复。无 affected_versions（恶意软件样本无版本区间，文中未给）、无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
---

## 一句话结论

BloodAlchemy（Deed RAT/ShadowPad 变种）用 `BrDifxapi.exe` 侧加载同目录的 `BrLogAPI.dll`，DLL 读取无扩展名文件 `DIFX`，以文件前 16 字节为 AES-128-CBC 密钥解密出第一层 shellcode；shellcode 再以 FNV-1a 为核心的自定义算法逐字节解密、用 LZNT1（`RtlDecompressBuffer`）解压，得到 magic 为 `45AB45AB` 的自定义 PE 式载荷，按节表把各节映射到 `0x400000` 基址后跳入入口点执行。

## 原理

- **入口与文件布局**：攻击者劫持 VPN 设备维护供应商账号后下发三个文件到 `C:\windows\`：`BrDifxapi.exe`（111472 字节）、`BrLogAPI.dll`（129536 字节）、`DIFX`（66112 字节），并创建计划任务 `C:\Windows\System32\Tasks\Dell\BrDifxapi` 做持久化。`BrDifxapi.exe` 是正常程序，启动时按 Windows DLL 搜索顺序从自身目录加载同名依赖 `BrLogAPI.dll`，形成 DLL 侧加载。
- **第一层：DIFX + AES-128-CBC**：`BrLogAPI.dll` 拼出 `DIFX` 文件名后 `CreateFileA`/`GetFileSize`/`ReadFile` 读入全部内容，`VirtualAlloc` 出可写可执行缓冲；`aes_init` 后 `aes_dec(dec_shellcode + 16, enc_data)`——把文件前 16 字节当作 AES 密钥，剩余部分作为密文，按 AES-128-CBC 解密（原文说明密钥即文件前 16 字节），再 `VirtualProtect` 改执行权限并调用解密出的 shellcode。
- **第二层：FNV-1a 自解密 + LZNT1**：第一层 shellcode 内部的解密循环使用 FNV-1a 的参数：offset basis `2166136261`（0x811C9DC5）、prime `16777619`（0x01000193），对密文字节做哈希运算派生逐字节密钥流并异或（原文标注为 "custom dec" / "FNV-1a" 处理），随后调用 `RtlDecompressBuffer`（压缩格式 2 = LZNT1，输出缓冲 `0x17000`）解压出最终载荷。
- **第三层：45AB45AB 自定义载荷格式**：解压结果不是标准 PE，而是仿 PE 的自定义结构：magic `45 AB 45 AB`、插件 ID `0x10`、入口点 `0x698C`、原始基址 `0x400000`、绝对偏移 `0`、虚拟分配大小 `0x17000`、原始数据大小 `0x16FAB`、代码基址 `0x1000`，随后是节表（节 1：VA 0 / 原始地址 0x50 / 大小 0x10FA0；节 2：VA 0x11000 / 原始地址 0x10FFD / 大小 0x39E0；节 3：VA 0x15000 / 原始地址 0x149DD / 大小 0x180A）。shellcode 按节表把原始数据复制到 `imagebase + VA`，再从入口点偏移跳转执行，等于在内存中手工完成 PE 映射。
- **与 Deed RAT 的关系**：Deed RAT 使用同型但不同常量的结构：magic `54 45 ED DE`、插件 ID `0x20`、入口点 `0x1740`、虚拟分配大小 `0x5000` 等；入口点后的异常处理、插件加载启动函数、插件名、配置结构（加密数据偏移）与持久化目录/文件名也高度相似，因此 BloodAlchemy 判定为 Deed RAT 的演化版本。
- **为什么能离线还原**：AES 密钥、FNV-1a 参数、LZNT1 格式与节表偏移全部硬编码在样本/载荷中，静态分析即可逐层解出最终载荷，无需运行恶意代码。

## 触发条件

- 拿到 BloodAlchemy 感染文件集（`BrDifxapi.exe`、`BrLogAPI.dll`、`DIFX`）或内存中对应的 shellcode/载荷。
- 反分析环境具备 IDA/Ghidra 等反汇编器、Python（pycryptodome）与 Windows LZNT1 解压能力（或调用 `RtlDecompressBuffer` 的脚本/工具）。
- `DIFX` 完整未被截断；AES 解密需要正好前 16 字节密钥与其余密文。
- 自定义载荷的节表与入口点需按实际样本解析，不同版本常量可能变化（Deed RAT 与 BloodAlchemy 即不同）。

## 利用步骤

1. **定位侧加载点**：检查 `C:\Windows` 下同名 EXE/DLL 组合与计划任务；在 `BrLogAPI.dll` 中搜索 `DIFX` 字符串及 `CreateFileA`/`ReadFile`/`aes_init`/`aes_dec` 调用，确认读取与解密逻辑。
2. **提取 AES 密文**：把 `DIFX` 前 16 字节作为 key，其余作为密文；用 AES-128-CBC 解密得到第一层 shellcode（原文代码：`aes_dec(dec_shellcode + 16, enc_data)`）。
3. **解 FNV-1a 层**：在 shellcode 中定位 offset basis `0x811C9DC5` 与 prime `0x01000193` 循环，按样本实现复刻逐字节密钥流并异或；随后识别 `RtlDecompressBuffer` 调用（格式 2、输出大小 0x17000）做 LZNT1 解压。
4. **解析自定义载荷**：按 `45AB45AB` 结构读取插件 ID、入口点、原始基址、虚拟分配大小、节数与各节（VA/原始地址/大小）；把各节复制到 `imagebase + VA` 的缓冲。
5. **转成可分析格式**：若需 IDA 分析，可按节表重建内存镜像并设置入口点（`imagebase + entrypoint`），或直接对重组后的缓冲做反汇编。
6. **对比家族**：检查 magic/插件 ID/入口点/节表常量是否匹配 Deed RAT（`54 45 ED DE`/0x20/0x1740）或 BloodAlchemy（`45AB45AB`/0x10/0x698C），辅助家族归类。

## PoC

第一层 AES 解密的离线脚本骨架（仅处理已提取的 `DIFX`，不运行样本）：

```python
from Crypto.Cipher import AES

def decrypt_difx(path):
    data = open(path, "rb").read()
    key, ciphertext = data[:16], data[16:]
    # 原文称 AES-128-CBC；若样本使用全零/固定 IV，按实际样本的 aes_init 参数补 IV
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
    plain = cipher.decrypt(ciphertext)
    return plain

# 说明：IV 需按样本 aes_init 的实际参数校正；解出的是第一层 shellcode
```

后续 FNV-1a 自解密与 LZNT1 解压需按样本反汇编复刻，无通用一行式 PoC（原文给出的是 IDA 反汇编与恢复过程截图）。

## 变体与关联

- **变体（家族）**：Deed RAT 使用 `54 45 ED DE` magic、插件 ID 0x20、入口 0x1740；ShadowPad 为其前身。同族不同版本的插件 ID、入口点与节表大小会变化，需以实际样本为准。
- **变体（加载方式）**：DLL 侧加载依赖合法 EXE 的同目录加载顺序；也可改为注册服务/计划任务直接加载恶意 DLL，行为特征随之变化。
- **变体（加密层）**：AES 密钥/IV、哈希参数、压缩算法都可能被改版替换；识别思路是找硬编码密钥与解压/内存映射调用链。
- 关联：[[code-analysis-reverse-windows-bloodalchemy-config-1byte-key-decrypt]]（同一样本的配置解密与字段）、[[defense-detection-bloodalchemy-deed-rat-behavior-ioc]]（同族行为与狩猎特征）、[[code-analysis-reverse-windows-amadey-api-hash-loader-c2-config]]（另一家族的 API hash + 内存 PE 加载）、[[pentest-c2-early-bird-apc-injection-debug-process-variant]]（本族随后使用的注入手法）。
- 边界：DIFX 被截断、样本改了 AES 模式/IV、或 FNV-1a 参数/节表被混淆时，需按实际反汇编调整。

## 检测与防御

- **检测**：监控 `C:\Windows` 下非微软签名的同名 EXE/DLL 组合与无扩展名文件；检测 `BrDifxapi.exe` 加载同目录 `BrLogAPI.dll` 的侧加载行为；内存/文件扫描 `45AB45AB`、`54 45 ED DE` magic 与 `DIFX` 字符串；关注计划任务 `\Dell\BrDifxapi`。
- **防御**：启用 DLL 搜索顺序加固（`SetDefaultDllDirectories`/安全 DLL 搜索模式）、WDAC/AppLocker 限制可执行目录；对合法 EXE 做完整性校验；EDR 监控 `VirtualAlloc` + AES 解密 + `RtlDecompressBuffer` 组合与内存映射执行。
- **响应**：隔离感染主机与 VPN 设备，吊销被劫持的维护账号；提取 `BrDifxapi.exe`/`BrLogAPI.dll`/`DIFX` 样本与计划任务、持久化目录，交由逆向确认变种。
