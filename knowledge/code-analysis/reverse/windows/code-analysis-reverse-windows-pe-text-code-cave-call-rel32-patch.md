---
id: code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch
title: PE .text 代码空洞自动化注入：E8 call rel32 劫持、重定位清零与断点验证
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-text-code-cave-call-rel32-patch
aliases:
- 白利用代码空洞
- PE .text patch
- E8 call rel32 劫持
- code cave 注入
- DLL 代码空洞
- titanengine 单步追踪
- reloc 清零
- DLLHijacking-Patcher
tags:
- windows
- pe
- code-cave
- binary-patch
- shellcode
- relocation
- aslr
- titanengine
- defense-evasion
- dll
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:46:13+08:00'
  notes: 已对照原文（仅图片链接的 PPT）与25张幻灯片逐张核对：白利用+PE .text patch 主题、DLL 搜索顺序、canary 导出验证、E8 call rel32 改写公式(rel32=payload-(call+5))、RSP 16字节对齐、DllMain 路径与 .reloc 清零三障碍、TitanEngine Analyzer/Patcher/Validator/Recorder 四组件、BP-1/BP-2 判定、MessageBox Demo 与同一 DLL 5 模板 VT 全绿、GitHub DLLHijacking-Patcher 均与幻灯片一致。未验证点：原文未给完整工具源码，卡片 PoC 为骨架伪代码且未复跑；VT 全绿仅代表演示时点；confidence=medium 合适；无组件版本。
---

## 一句话结论

在合法 DLL 的 `.text` 段中找一段不在执行路径上的连续代码空洞，把一条 `E8 call rel32` 指令的 4 字节相对偏移改指向空洞中的 PIC shellcode，并清零覆盖 payload 区的 `.reloc` 条目避免 ASLR 重定位改写，即可让签名宿主进程在正常加载/调用该 DLL 时执行 shellcode；配合单步执行追踪可自动发现可注入 call 点、最大连续空洞并做断点验证。

## 原理

- PE 的 `.text` 段常因对齐、编译填充存在未使用的连续字节（code cave）。只要不覆盖实际执行路径上的指令，就可以把 shellcode 放进这些空洞，不需要新增 section、不需要 `VirtualAlloc` 申请 RWX、也不需要创建线程，payload 直接位于 DLL 的合法可执行内存中。
- 劫持点优先选 `E8 call rel32`：opcode 固定为 `E8`，后跟 4 字节相对偏移；32/64 位通用、只改 4 字节、不涉及寄存器、不改变调用语义。改写公式为 `rel32 = payload_entry - (call_instruction_addr + 5)`，`call` 压入的返回地址仍是原下一条指令，被调用函数正常 `ret` 后继续执行。`FF 15 call [mem]`、`FF D0 call rax` 等间接调用涉及指针/寄存器与对齐约束，稳定性和可篡改性较差。
- 可注入点必须在目标导出函数的执行路径上，且最好不在初始化区域（init region）。用调试器单步记录 DLL 从加载到第一个导出函数执行之间的指令流/DllMain 链，把这部分标为不可碰；之后执行的代码为 analyzable region，所有 patch 点与代码空洞都从这里找，避免在加载阶段就覆盖/执行 payload，导致走不到目标导出。
- 代码空洞搜索：解析 PE 头得到 `.text` 的 RVA 与大小；不可用区域 = init region + patch 点之前的执行路径；可用 = `.text` - 不可用；选择最长连续可用区间，避免 shellcode 被切分到多个不连续空洞。
- ASLR 重定位是关键干扰：PE `.reloc` 表列出需要按 image base delta 修正的地址。若 payload 区被重定位条目覆盖，加载器会在运行时改写这些字节，导致 shellcode 损坏、崩溃或静默失效。需要解析 `.reloc`，找出与 payload 区重叠的条目并把对应 relocation 项/块置 0（`reloc[i] = 0 for hit`），确保 payload 不被 loader 改写。
- x64 栈对齐必须核算：进入 shellcode/被调函数时需满足 System V/Windows x64 的 16 字节对齐约定（入口 `RSP % 16 == 8`）；patch 点选择不当、或目标函数序言对 RSP 的调整不同，都会在 `movaps` 一类指令上崩溃。payload 入口可按需加 `push/pop` 或调整空洞落点。
- 验证闭环：在 patch 点下断点 BP-1、在 payload 入口下断点 BP-2。两者都命中 = patch 正确且被执行；BP-1 命中而 BP-2 未命中 = 跳转无效/相对偏移算错；BP-1 未命中 = 该 patch 点未执行到。失败点应记录并不再复用。
- 自动化四组件：Analyzer（TitanEngine 调试器单步追踪、记录指令流/DLL 加载事件/内存断点、区域抽象、找 call 点与代码空洞）、Patcher（填入 shellcode、改写 `E8 rel32`、修复 `.reloc`）、Validator（真实运行宿主 + BP-1/BP-2 验证）、Recorder（按 `sha256(dll)` 缓存 init region/patch 点/验证结论，模板复用，失败原因入库）。原文用该流水线把 MessageBox shellcode 注入被签名宿主加载的 DLL，演示 5 个变体 VT 全绿、同一宿主 DLL 生成 5 个不同入口模板。

## 触发条件

- Windows x64，目标 DLL 会被签名宿主 EXE 加载（DLL 搜索顺序劫持、侧加载、可替换的合法 DLL 等）。
- 攻击者能修改 DLL 文件或投放同名 DLL；DLL 的 `.text` 中存在足够大的连续代码空洞，且能找到执行路径上的 `E8 call rel32`。
- payload 为位置无关（PIC）shellcode，不依赖固定加载基址；若 payload 含绝对地址，需自行处理或配合重定位。
- 目标 DLL 的 `.reloc` 可解析、payload 区可避开或清零重定位条目；目标未启用会阻止未签名 DLL 加载的 WDAC/AppLocker DLL 规则。
- 验证环境能运行宿主 EXE，并能在 patch 点与 payload 入口下内存断点。

## 利用步骤

1. 用 TitanEngine/调试器附加宿主进程，单步记录 DLL 加载事件与从 `DllMain` 到第一个导出函数执行的指令流，标出 init region；后续代码为 analyzable region。
2. 在 analyzable region 的指令流中搜索 `E8` call 指令，选择不在 init region、调用后能正常返回、且位于目标导出调用路径上的点。
3. 解析 PE 头获取 `.text` 范围，扣除 init region 与 patch 点前的执行路径，寻找最长连续可用空洞；记录空洞起点 RVA 与长度。
4. 将 PIC shellcode 写入空洞起点（不破坏首尾合法字节，长度不超过空洞），记录 payload 入口 RVA。
5. 计算并写回 `rel32 = payload_rva - (call_rva + 5)`（小端 4 字节），`E8` 保持不变。
6. 解析 `.reloc`，把与 `[payload_rva, payload_rva + len(sc))` 重叠的重定位条目/块清零，防止 ASLR 重定位改写 payload。
7. 按 call 点的 `RSP` 核算 payload 入口的 16 字节对齐；必要时在 shellcode 前插入栈调整指令。
8. 将 patched DLL 放回宿主目录，真实运行宿主 EXE；在 BP-1（patch 点）与 BP-2（payload 入口）下断点，确认两者命中。
9. 用 Recorder 记录 DLL hash、init region、patch 点、payload 模板与验证结论；同一 DLL 可生成多个不同入口的 harness 变体。

## PoC

以下为流程骨架（伪代码，未在本机复跑；实际需结合目标 PE 的指令边界与执行追踪结果）：

```python
import pefile, struct

dll = "target.dll"
pe = pefile.PE(dll)
text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text_rva, text_size = text.VirtualAddress, text.Misc_VirtualSize

# 1) Analyzer 给出：init_region、可执行路径、选定的 call_rva、空洞 payload_rva
call_rva = 0x1234          # E8 call rel32 的指令起始 RVA
payload_rva = 0x2000       # 连续代码空洞起点（示例）
shellcode = b"\x90" * 16   # 实际为 PIC shellcode

# 2) 写入 payload（文件偏移 = RVA - section VA + PointerToRawData）
off = payload_rva - text.VirtualAddress + text.PointerToRawData
pe.set_bytes_at_offset(off, shellcode)

# 3) 改写 E8 的 rel32
rel32 = payload_rva - (call_rva + 5)
pe.set_bytes_at_rva(call_rva + 1, struct.pack("<i", rel32))

# 4) 清零覆盖 payload 的 .reloc 条目（示意；按实际解析结构处理）
for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
    block_rva = block.struct.VirtualAddress
    for entry in block.entries:
        entry_rva = block_rva + entry.rva
        if payload_rva <= entry_rva < payload_rva + len(shellcode):
            entry.rva = 0   # 避免 loader 在 ASLR 重定位时改写 payload 字节

pe.write("target_patched.dll")
```

```text
验证判定（原文 Validator）：
  BP-1（patch 点）命中 + BP-2（payload 入口）命中 -> patch 正确有效
  BP-1 命中 + BP-2 未命中                         -> 跳转未生效/偏移错误
  BP-1 未命中                                     -> patch 点未执行到
```

## 变体与关联

- 变体：没有 `E8 call rel32` 时可用 `FF 15 call [mem]`/`FF D0 call rax`，但要处理指针/寄存器与对齐；也可选 `jmp rel32`（`E9`）但会破坏返回流程。
- 变体：patch 目标可以是 EXE 的入口点/函数而不是 DLL `.text`（见关联的签名 EXE PIC patch 卡）；也可在多个 DLL/多个导出上生成不同入口模板。
- 变体：若 `.text` 无足够空洞，可考虑新增 section、其他可执行 section、或代码复用/ROP，但这会改变文件结构、增加检测面。
- 关联：[[pentest-c2-signed-exe-pic-shellcode-patch-certificate-table]]（向签名 EXE 入口/函数写入 PIC shellcode 并保留证书表）、[[pentest-c2-pic-shellcode-text-peb-eat-http-loader]]（PIC shellcode 开发）、[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（E9 inline hook 的同类 PE patch）、[[pentest-persistence-dll-search-order-hijack-proxy-forwarding]] 与 [[pentest-c2-dll-sideload-export-forwarding-host-whitelist]]（把 patched DLL 送进签名宿主的投放方式）。
- 边界：代码空洞必须足够大且不覆盖执行路径；`.text` 运行时通常不可写，必须改文件而非内存；清零 `.reloc` 可能影响共享该重定位块的合法代码；CFG/ACG/WDAC/EDR 镜像完整性校验可能拦截；patch 后 DLL 签名破坏，但宿主 EXE 签名仍有效，不能把“宿主签名有效”当成整体可信。原文的 VT 全绿仅代表演示样本与当时引擎，不能保证长期或对所有产品有效。

## 检测与防御

- 检测：对比磁盘 DLL 与内存镜像的 `.text` 差异；监控 `.text` 中 `E8` 目标指向非函数入口/代码空洞、以及从空洞处执行代码；EDR 记录 DLL 镜像加载后的内存写入/私有提交；检查 `.reloc` 被异常清零的 PE；关注签名宿主加载无签名/签名失效 DLL、以及同名 DLL 从用户可写目录加载。
- 防御：启用 WDAC/AppLocker DLL 规则与签名强制；对关键 DLL 做加载前完整性校验（Authenticode + 哈希基线），不要只校验宿主 EXE；启用 CFG/ACG 与 Arbitrary Code Guard，阻止向可执行镜像写入并执行；对高价值进程启用 EDR 内存扫描与镜像完整性监控。
- 加固：减少可写目录中的 DLL 搜索路径；对 Microsoft Store/第三方应用目录做权限最小化；监控 LOLBin 与签名宿主的异常子进程/弹窗/网络行为；VT 全绿不能作为放行依据，应结合行为检测。
