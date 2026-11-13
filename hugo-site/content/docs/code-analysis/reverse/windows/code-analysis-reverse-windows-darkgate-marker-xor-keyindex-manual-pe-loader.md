---
id: code-analysis-reverse-windows-darkgate-marker-xor-keyindex-manual-pe-loader
title: DarkGate Delphi 加载器：zhRVKFlX 标记定位加密块、key[i]^(len-i) 递变解密钥、自累加索引 XOR 解 payload，手动映射 PE 后 jmp eax
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: darkgate-marker-xor-keyindex-manual-pe-loader
tags:
- windows
- darkgate
- loader
- xor
- marker
- manual-pe-mapping
- reflective-loading
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V493
  verified_at: '2026-11-11T00:01:20+08:00'
  notes: 已对照原文与图17-23核对：zhRVKFlX 标记定位、Decrypted_key[i]=enc[i]^(len-i) 解得 roTSOEnY、自累加索引 XOR（k=(k+key[k])%len，归零置 len-1）、0x69BFF 解出约 433KB、MZRE 头与三次 jmp trampoline、VirtualAlloc RWX+节映射+导入解析+基址重定位+jmp eax、TLS 回调（图16）均一致；已修正原误写图18为图16。未验证点：未对样本复跑解密；原文未给版本，未设 affected_versions；frontmatter 无 sources/source_url
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-darkgate-marker-xor-keyindex-manual-pe-loader/
draft: false
kb_aliases:
- zhRVKFlX 标记
- roTSOEnY
- DarkGate loader
- mw_Key_decryption
- mw_Decrypt_payload
- mw_Execute_Payload
- 手动映射 PE
- 自累加密钥索引 XOR
---

## 一句话结论

DarkGate 的 Delphi 加载器从 `AutoIt3.exe` 命令行取得脚本路径并读入 `script.au3`，用 8 字节标记 `zhRVKFlX` 定位紧随其后的加密 blob；加密的 8 字节密钥按 `plain[i] = enc[i] ^ (len - i)` 还原出 `roTSOEnY`，payload 则用“当前密钥字节与数据异或、再以 `k = (k + key[k]) % len` 滚动索引（归零时置为 len-1）”的链式 XOR 解密；最后 `VirtualAlloc(MEM_COMMIT, PAGE_EXECUTE_READWRITE)` 手动复制 PE 头/节、解析导入、处理基址重定位并 `jmp eax` 进入入口，全程不落盘。

## 原理

- **脚本即载荷容器**：加载器不把加密 RAT 放在自己体内，而是放在 AutoIt 脚本尾部；运行时读取 `AutoIt3.exe` 的启动参数拿到 `.au3` 路径，`ReadFile` 读入整份脚本到内存，再在其中搜索 8 字节标记。标记既是定位符也是构建标识：同一构建的所有模块/组件共享一个 8 字节主密钥（本例 `zhRVKFlX`），不同阶段以不同方式使用它（当标记、当密钥、或经变换生成新密钥）。
- **密钥本身也被加密**：blob 前 8 字节是加密后的密钥；`mw_Key_decryption` 逐字节计算 `Decrypted_key[i] = encrypted_key[i] ^ (BufferSize - i)`（`BufferSize` 为密钥长度，i 从 0 开始，即依次异或 8,7,…,1）。这是位置相关的单字节 XOR，密钥短且算法固定，静态即可解出 `roTSOEnY`。
- **自累加索引 XOR**：`mw_Decrypt_payload` 对每个密文字节执行 `out[i] = key[k] ^ in[i]`；随后更新 `k = (k + key[k]) % len(key)`，若 `k` 变为 0 则重置为 `len-1`。因为 `key[k]` 是密钥字节（非随机），索引序列由密钥自身决定、可预测且与数据无关，解密方只需同一密钥即可生成同样的密钥流；这种“滚动索引”比固定循环 XOR 少了周期性特征，但仍是纯异或、可完全离线还原（本例 blob 约 0x69BFF 字节，解出约 433KB 的 PE）。
- **手动映射 PE**：`mw_Execute_Payload` 先用 `VirtualAlloc(NULL, size, MEM_COMMIT, 0x40)` 分配 RWX 内存；把 PE 头和每个节按 `VirtualAddress`/`PointerToRawData`/`SizeOfRawData` 复制到对应偏移；遍历导入目录，用 `LoadLibraryA`/`GetProcAddress` 填充 IAT；处理 `.reloc` 基址重定位（按 `SizeOfBlock` 与每项高 4 位类型判断）；随后跳转入口。图 16 的加载器代码还包括 TLS 回调处理；最终通过 `__asm { jmp eax }` 把控制权交给加载后的 PE 入口。
- **入口跳转链**：解密出的加载器以 `MZRE`（`4D 5A 52 45`）开头，仍保留 MZ/PE 结构；shellcode 入口先执行三次 `jmp`（`90 E9 xx xx xx xx` 形态的 trampoline）落到尾部的 `dec ebp; pop edx; ...; call [eax]` 存根，再调用手动 PE 加载器。这样同一块数据既能被当作 shellcode 跳入，又保留 PE 结构供映射。
- **为什么有效**：恶意逻辑以“AutoIt 脚本里的标记 + 加密数据”存在，文件层面看不到 PE；密钥与数据同处一个文件但经过位置变换；内存中才出现完整 PE，静态扫描只能看到脚本与加载器骨架。

## 触发条件

- 加载器作为 AutoIt 链的一环被启动，`AutoIt3.exe` 的命令行带有脚本路径参数（或加载器能读到脚本文件）。
- 脚本尾部存在 8 字节标记与加密 blob；密钥按上述位置 XOR 可解出（算法固定，不依赖环境）。
- 进程允许 `VirtualAlloc` RWX 与手动映射；目标 PE 的导入 DLL 可用、重定位信息完整。
- 分析侧：拿到加载器与 `script.au3`；或已解出加载器二进制，可静态复现两段 XOR。

## 利用步骤

1. **定位载体**：确认 `AutoIt3.exe` 进程命令行与脚本路径，读取 `.au3` 文件；搜索 `zhRVKFlX`，记录其后密文起点与长度。
2. **解密钥**：取标记后的前 8 字节，按 `enc[i] ^ (8 - i)` 解出明文密钥（示例 `roTSOEnY`）。
3. **解 payload**：按滚动索引 XOR 还原整个 blob；检查结果是否以 `MZRE`/`MZ` 开头、是否含 PE 头。
4. **静态映射或动态 dump**：按 PE 头解析节表、导入表、重定位表；或在调试器中于 `VirtualAlloc` 后、`jmp eax` 前 dump 内存中的映射结果。
5. **跟进载荷**：把解出的 PE 作为 DarkGate RAT 分析（配置解密、C2、持久化）；记录 8 字节主密钥与标记作为同构建关联 IOC。
6. **验证解密**：用同样的密钥/索引算法重放，确认输出长度与节表一致（本例约 433KB）。

## PoC

解密算法复现（按反编译逻辑整理，未执行样本）：

```python
def decrypt_key(enc: bytes) -> bytes:
    n = len(enc)
    return bytes(b ^ (n - i) for i, b in enumerate(enc))

def decrypt_payload(blob: bytes, key: bytes) -> bytes:
    out = bytearray()
    k = 0
    for b in blob:
        out.append(b ^ key[k])
        k = (k + key[k]) % len(key)
        if k == 0:
            k = len(key) - 1
    return bytes(out)

key = decrypt_key(blob[:8])          # 示例结果 b"roTSOEnY"
plain = decrypt_payload(blob[8:], key)
```

手动映射关键步骤（伪代码）：

```c
p = VirtualAlloc(NULL, image_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(p, headers, SizeOfHeaders);
for each section: memcpy(p + VirtualAddress, raw + PointerToRawData, SizeOfRawData);
for each import: h = LoadLibraryA(name); *(FARPROC*)iat = GetProcAddress(h, func);
apply base relocations;
((void(*)())entry)();
```

无独立可执行 PoC；上述算法可直接用于样本离线解密。

## 变体与关联

- **密钥使用方式**：同一 8 字节主密钥可当标记、当密钥、或经自定义 XOR 生成子密钥；不同模块/阶段的用法不同，但构建内共享。
- **滚动 XOR 变体**：索引增量可换成 `+1`、`+key[i]`、`^key[i]` 等；只要密钥流与数据无关就可离线重放。
- **PE 映射**：可换成反射 DLL（ReflectiveLoader）、`NtMapViewOfSection`、模块踩踏等；本卡为自写 `mw_Execute_Payload`。
- **载体**：加密 blob 可放在脚本、资源、配置文件或远程下载；本例放在 AutoIt 脚本尾部并用命令行取路径。
- **关联卡**：AutoIt 外部字符表混淆卡（同一家族的前置脚本层）、DarkGate C2 协议卡、反射/手动 PE 加载通用卡。
- **边界**：8 字节密钥若按构建随机化，跨样本不能复用；滚动索引若换成数据相关变换，需动态跟踪；TLS 回调/异常目录处理在不同编译版本可能不同。

## 检测与防御

- **文件/脚本**：搜索 AutoIt 脚本中的 `zhRVKFlX` 一类 8 字节重复标记与高熵尾部；检查脚本是否被 `AutoIt3.exe` 以路径参数加载。
- **行为**：监控进程从命令行读取 `.au3`、随后 `VirtualAlloc` RWX、复制 PE 节、解析导入并 `jmp` 到无模块内存；RWX 页上的 PE 映射是强特征。
- **内存**：对 AutoIt 进程做内存扫描，查找 `MZRE`/`MZ` 头与手动映射的 PE；提取后按导入/重定位完整性判断。
- **策略**：限制 AutoIt3 解释器运行与脚本目录写入；EDR 对 `VirtualAlloc(PAGE_EXECUTE_READWRITE)` + `LoadLibrary/GetProcAddress` 循环 + 跳转入口的组合告警；开启 ACG/CFG 增加内存执行门槛。
