---
id: code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode
title: PE 签名改 NO 的内嵌 PE 自解密 shellcode：MZ/NO 双特征定位 + 逐字节 XOR 还原 + DllEntryPoint 执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: mz-no-modified-pe-embedded-xor-shellcode
aliases:
- PE 签名改 NO（MZ 保留）
- PE 头伪装
- 内嵌 PE shellcode
- XOR 0x3 解密
- DllEntryPoint shellcode
- 修改 DOS stub
- 节名去点
- Cobalt Strike 内存 PE
tags:
- windows
- reverse
- pe
- shellcode
- embedded-pe
- xor
- pe-header
- av-evasion
- cobaltstrike
- yara
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:27:44+08:00'
  notes: 已对照原文与23张图：0xB 处20字节存根、0x28 处 0x3A818 字节循环异或（dl 初值3并随已解密字节滚动）、FUN_SearchPE 按 ZM(MZ)+e_lfanew 处 ON(NO) 双特征定位、LoadLibrary/GetProcAddress、DllEntryPoint 指令序列、YARA 命中 Cobalt Strike、CobaltStrikeParser 配置均与图10-23一致。已修正原卡把伪装点误写为 MZ 改 NO：图为 MZ(4D5A) 保留、PE 签名(0xF0 处)改为 4E4F( NO )，标题/正文已改并重写 staging 草稿。未运行样本。
---

## 一句话结论

样本的 235KB shellcode 自带两段解密逻辑：偏移 0xB 处先解密 20 字节自修改存根并调用，偏移 0x28 处再逐字节 XOR 解密 0x3A818 字节，得到一个 PE 签名 `PE\0\0` 被改成 `NO`（MZ 仍保留）、DOS stub 字符串被改、节名去掉前导点的 PE；加载器在内存中按 `MZ`（`'ZM'`）与 PE 头处的 `NO`（`'ON'`）双特征定位并修复/映射该 PE，动态解析 LoadLibrary/GetProcAddress，最终跳到类似 `DllEntryPoint` 的入口执行 Cobalt Strike 载荷。

## 原理

- **两段式自解密 shellcode**：shellcode 起始处并非直接是 payload；偏移 0xB 处有一段 20 字节的后续载荷，被解密后负责循环异或解密主载荷；偏移 0x28 处是 0x3A818 字节的加密 PE。解密循环初值 `dl=0x3`，每条指令对目标字节做 XOR，并在循环中 `add dl, [已解密字节]` 更新密钥（原文概括为“按字节异或 0x3”，实际是随明文滚动的密钥，分析时应以反汇编为准）。
- **PE 头伪装**：正常 PE 以 `4D 5A`（MZ）开头、DOS stub 含 `This program cannot be run in DOS mode`、节名为 `.text/.rdata/.data/.reloc`。样本把 PE 签名 `PE\0\0` 改成 `NO`（`4E 4F 00 00`，MZ 保留）、修改 DOS stub 文本、节名去掉前导点（`text/rdata/data/reloc`），使基于 `MZ`、DOS stub 字符串、标准节名的静态签名/YARA 规则失效。
- **加载器的自识别**：`FUN_SearchPE` 在内存中按 WORD 比较 `'ZM'`（小端即字节 `MZ`），再取 `e_lfanew = *(DWORD*)(base+0x3C)`，要求落在 `[0x40, 0x400)`，然后比较 `*(DWORD*)(base+e_lfanew) == 'ON'`（小端即 `NO\0\0`）。也就是说，加载器自己知道签名被改成 `NO`，用“MZ + NO”双特征定位 PE，而不是搜索标准 `PE\0\0`。
- **执行方式**：动态调用 `LoadLibrary`/`GetProcAddress` 解析 API，使用 `VirtualAlloc`/`VirtualProtect` 准备可执行内存，跳转到新代码空间；入口指令序列与 DLL 的 `DllEntryPoint` 一致（`cmp [ebp+fdwReason],1`、`call __security_init_cookie`、`call __DllMainCRTStartup`、`retn 0Ch`），说明内嵌的是一个被当作 shellcode 加载的 DLL。
- **家族识别**：内存 dump 出的 PE 虽被改头，但仍可被 YARA 规则（如 Cobalt Strike Beacon 字符串规则）命中；用 CobaltStrikeParser/1768 解析可还原 HTTPS Beacon 配置（端口、sleep/jitter、多个 `/api/v2/getconfig` C2、User-Agent、HttpPostUri、Cookie 元数据 SESSIONID/JSESSION 等），从而确认 Cobalt Strike 家族并提取 IOC。
- 这类“改 PE 头 + 加密内嵌 PE + 自解密存根”手法针对静态扫描；运行时仍会留下私有可执行内存、手动映射、动态 API 解析与网络回连等行为特征。

## 触发条件

- 分析者已获得解密后的外层 shellcode（从上层 loader 的内存、进程 dump 或载荷解密流程），样本为 Windows PE/shellcode。
- shellcode 与目标进程架构一致；内嵌 PE 的依赖 DLL 在目标进程可加载。
- 分析环境具备 IDA/x64dbg、Python、YARA、CobaltStrikeParser/1768 等工具。
- 若要在真实目标上运行，需有可写可执行内存与出网通道；检测方未拦截修改 PE 的内存加载与 C2 外连。

## 利用步骤

（按样本分析链描述，非本机复现。）

1. 取得外层 shellcode，反汇编起始处：定位偏移 0xB 的 20 字节存根与偏移 0x28 的主载荷，记录解密循环的初值与密钥更新方式。
2. 按存根算法解密 0x3A818 字节主载荷（原文概括为逐字节 XOR 0x3；以调试器实际执行的 `dl` 更新逻辑为准）。
3. 在解密结果中搜索 `MZ` 与 `NO` 双特征：`data[i:i+2] == b'MZ'`，且 `e_lfanew = u32(data[i+0x3C:])` 落在 `[0x40,0x400)`、`data[i+e_lfanew:i+e_lfanew+4] == b'NO\x00\x00'`；同时检查 DOS stub 是否被改、节名是否缺少前导点。
4. 还原 PE：把 `NO` 改回 `PE\0\0`（MZ 已保留）、补回 DOS stub 与节名，或在调试器中让样本完成映射后 dump 内存映像；用 IDA 打开，确认入口为 `DllEntryPoint` 形态。
5. 在 `LoadLibrary`/`GetProcAddress`、`VirtualAlloc`/`VirtualProtect` 下断点，记录 API 解析与内存映射过程；在最终间接跳转处确认入口地址与 `ImageBase + AddressOfEntryPoint` 对应。
6. 对还原后的 PE 跑 YARA（Cobalt Strike Beacon 字符串）与 CobaltStrikeParser/1768，提取 C2、端口、sleep/jitter、URI、User-Agent、Cookie 元数据等配置，完成家族确认与 IOC 输出。
7. 提取的 PE 作为普通样本继续逆向；结合上层 Python 加载链（见关联卡）还原完整投递路径。

## PoC

扫描 `MZ + NO` 双特征（在解密后的数据上运行）：

```python
import struct

data = open('decrypted_stage.bin', 'rb').read()

for i in range(len(data) - 0x400):
    if data[i:i+2] != b'MZ':
        continue
    e_lfanew = struct.unpack_from('<I', data, i + 0x3C)[0]
    if 0x40 <= e_lfanew < 0x400:
        sig = data[i + e_lfanew:i + e_lfanew + 4]
        if sig == b'NO\x00\x00':
            print(f'modified PE at {i:#x}, e_lfanew={e_lfanew:#x}')
```

```python
# 按原文概括的逐字节 XOR 0x3 还原（实际密钥随明文滚动，需以存根反汇编为准）
raw = bytearray(open('stage.bin', 'rb').read()[0x28:0x28 + 0x3A818])
for i in range(len(raw)):
    raw[i] ^= 0x03
open('stage.dec.bin', 'wb').write(raw)
```

```text
# 还原 PE 后
yara cobaltstrike_rules.yar stage.dec.bin
python CobaltStrikeParser.py stage.dec.bin
# 或 python 1768.py stage.dec.bin
```

## 变体与关联

- 头伪装变体：PE 签名→NO（MZ 保留）、DOS stub 改写、节名去点/改随机名；也可改 `e_lfanew` 或追加垃圾头，加载器相应调整搜索逻辑。
- 解密变体：单字节 XOR、滚动 XOR、RC4/AES、aPLib/UPX 二次压缩；本样本为“20 字节存根 + 滚动 XOR”的自修改结构。
- 载体变体：内嵌 DLL 改为 EXE、反射 DLL（sRDI）、Donut 生成的 shellcode；执行方式改为线程/APC/回调。
- 关联卡片：[[pentest-c2-shellcode-embedded-pe-bytewise-api-decrypt-loader]]（shellcode 内嵌 PE 自加载、栈上 API 名还原与手动映射）、[[pentest-c2-pe-import-camouflage-section-layout-randomization]]（PE 导入表/段布局静态对抗）、[[code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract]]（aPLib shellcode 提取）、[[pentest-c2-apt-q27-signed-photo-loader-s3-manifest-encrypted-shellcode-memory-pe]]（XOR shellcode 内嵌 UPX PE）、[[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]（CS 配置提取）、[[pentest-c2-python-oss-staged-loader-pickle-xor-shellcode]]（本样本的上层 Python 加载链）。
- 边界：若样本在内存中完成映射后再 dump，看到的可能是已修复的 PE 头（MZ/PE 正常），需要从原始 shellcode 解出加密载荷才能观察伪装；YARA 只命中少量字符串时需结合配置解析与行为确认家族。

## 检测与防御

- 静态检测：文件中同时存在 `MZ` 与 `e_lfanew` 处的 `NO\0\0`；DOS stub 字符串异常；节名缺少前导点或不符合常见工具链；固定偏移处存在高熵/加密块与“解密 20 字节存根 + 循环 XOR”的指令模式；对还原后的 PE 跑 Cobalt Strike YARA 规则。
- 动态检测：私有可执行内存中出现完整 PE 结构（即使头被改）、运行中批量 `LoadLibrary`/`GetProcAddress`、`VirtualAlloc`/`VirtualProtect` 后跳转到非模块内存、入口为 `DllEntryPoint`、进程向多个 `/api/v2/getconfig` 地址发起 HTTPS 请求。
- 防御：部署针对修改 PE 头的 YARA/内存扫描规则；监控 WinHTTP/WinINet 异常外连与 CS 配置特征；限制用户目录可执行内存与未签名 DLL 加载；封禁 C2 地址与 OSS/云存储恶意桶。
- 响应：dump 进程内存还原内嵌 PE，提取配置与 C2，清理上层 Python 脚本、LNK 与持久化，修复钓鱼入口；对同批样本复用同一加载器的其他变体做家族排查。
