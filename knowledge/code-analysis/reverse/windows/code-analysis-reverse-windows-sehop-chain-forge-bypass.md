---
id: code-analysis-reverse-windows-sehop-chain-forge-bypass
title: SEHOP 校验链伪造绕过：next-SEH 指向原链末尾合法记录、handler 覆盖为 shellcode
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: sehop-chain-forge-bypass
aliases:
- SEHOP 绕过
- 伪造 SEH 异常处理链
- next SEH 指向末尾
- SEH_Record 伪造
- RtlCaptureContext 终极异常处理
- __except_handler3
- 异常处理链完整性绕过
tags:
- windows
- seh
- sehop
- exception-handler
- stack-overflow
- mitigation-bypass
- x86
- exploit
- reverse
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V507
  verified_at: '2026-11-11T04:42:31+08:00'
  notes: 已对照13430原文与全部13图核对：图01 SEH栈链示意；图02-04 VS关闭SDL/GS/CFG/Spectre/DEP/DYNAMICBASE；图05 test函数反汇编（缓冲区距ebp 0xE0）；图06-10 SEH链 0x19FE84→0x19FF54→0x19FFCC→0x19FFE4(FFFFFFFF)、尾记录handler 0x76F692E8=ntdll.RtlCaptureContext+108（文章正文另处写0x76F692C5/+E5，截图以0x76F692E8/+108为准，卡取截图值正确）；图11 缓冲区起始0x19FDB4；图12 SEH_Record[0]地址0x19FE84（偏移0xD0，payload 0xD8=216字节）；图13 覆盖后next=0x19FFE4、handler=0x19FDB4。卡片原理'SEHOP只校验链尾完整性、不校验handler'、伪造next指向原链尾记录、handler覆盖为shellcode与原文一致；PoC常量与截图一致。保留说明：原文仅演示到链伪造完成/内存覆盖，未截图展示shellcode执行效果，卡内已如实说明且confidence=medium，属可复现的控制流劫持而非纯理论；SEHOP对链在栈内且next单调递增的隐含检查卡内未展开，本例next(0x19FFE4)>当前(0x19FE84)满足，不影响方法成立。dedup：库内无SEHOP绕过卡，最近候选为OllyDbg SEH链定位、SEH异常逻辑分析，非同链，保留。非组件版本类affected_versions为空；无sources/source_url；未运行PoC。
---

## 一句话结论

SEHOP 不校验每个 handler 是否可信，只沿 `next SEH` 指针走链并检查链尾是否为系统预定的终极异常处理器；因此栈溢出覆盖当前 SEH 记录时，把它的 `next SEH` 指针改成原链中最后一个合法记录的地址（该记录 `next=0xFFFFFFFF`、handler 为 ntdll 终极处理器），再把 handler 覆盖为 shellcode 地址，就能让 SEHOP 校验通过，而异常分发最终调用被覆盖的 handler 执行 shellcode。

## 原理

- **SEH 记录结构**：x86 的 SEH 记录在栈上，每个记录是 `[next SEH 指针][handler 指针]` 共 8 字节；TEB 的 `ExceptionList`（FS:[0]）指向当前链头。发生异常时系统从链头开始依次调用 handler。
- **SEHOP 的检查方式**：SEHOP（Structured Exception Handler Overwrite Protection）在分发异常前沿 `next SEH` 指针遍历整条链，要求链最终到达系统预定的终极异常处理器（原文示例为 `ntdll!RtlCaptureContext+108`，`next=0xFFFFFFFF`）；如果链断开、成环或结尾不是该处理器，就认为 SEH 记录被溢出破坏并终止进程。它检查的是**链的完整性/结尾**，并不校验每个 handler 本身是否合法（后者是 SafeSEH 的职责）。
- **伪造思路**：当前记录被覆盖后，其 `next SEH` 原本指向下一条记录；攻击者把它改成原链中最后一个记录的地址。SEHOP 从当前记录出发，沿该指针直接走到合法尾记录（`next=0xFFFFFFFF`、handler 为 ntdll 终极处理器），于是判定链完整、校验通过；随后异常分发调用当前记录的 handler——此时已被覆盖为栈上 shellcode 的地址。
- **为什么能成功**：SEHOP 的信任模型是“只要链尾正确，链中间就没有被破坏”，但攻击者可以跳过被破坏的中间记录，直接复用原链中仍然合法的尾记录；而 handler 字段与 next 字段在同一个 8 字节记录里，溢出时两者可分别覆盖。
- **前提与边界**：需要知道合法尾记录的栈地址与 shellcode 地址（通常要求关闭 ASLR 或先泄露栈地址）；SafeSEH 必须关闭或 handler 落在其登记表中，否则栈上 handler 会被 SafeSEH 拦截；DEP 关闭或 shellcode 位于可执行内存，或改用 ROP；x64 使用表驱动的 SEH（不在栈上链式保存），本手法不适用。
- **与普通覆盖返回地址的区别**：直接覆盖返回地址/虚函数表不需要经过异常分发，因而完全不触发 SEHOP；SEHOP 只影响“通过覆盖 SEH handler 劫持控制流”这条路径。

## 触发条件

- Windows x86 进程，SEHOP 已启用（现代 Windows 常见默认开启）。
- 存在可覆盖栈上 SEH 记录的溢出（缓冲区到 SEH 记录的距离可计算）。
- 能获得/预测合法尾记录的栈地址与 shellcode 缓冲区地址（ASLR 关闭、栈地址泄露或信息泄露配合）。
- SafeSEH 关闭或 handler 地址在安全 SEH 表中；DEP 关闭或使用可执行栈/ROP 链。
- 程序能触发异常（如除零、访问违例），使异常分发走到伪造的 SEH 记录。

## 利用步骤

1. 在调试器中确定溢出缓冲区起始地址、到 `SEH_Record[0]` 的偏移（本例缓冲区距 SEH 记录 0xD0，payload 共 216 字节）以及 handler 字段位置（偏移 0xD4）。
2. 手动遍历当前 SEH 链（TEB `ExceptionList` → 各记录），记录最后一个合法记录：`next=0xFFFFFFFF`，handler 为 `ntdll` 的终极异常处理器；记下该记录地址（本例 0x0019FFE4）。
3. 构造 payload：缓冲区起始放 shellcode；用 NOP 填充到 `SEH_Record[0].next` 偏移；写入合法尾记录地址；紧接写入 shellcode 起始地址作为新 handler。
4. 触发异常（本例 `zero = 5 / zero` 除零）；SEHOP 沿伪造的 next 指针走到合法尾记录，校验通过；异常分发调用被覆盖的 handler，跳入 shellcode。
5. 在调试器中确认 `SEH_Record[0]` 的 next 已指向尾记录、handler 已指向缓冲区；观察 shellcode 是否执行（原文演示到链伪造完成，未展示 shellcode 的可见效果）。

## PoC

```python
import struct

p32 = lambda x: struct.pack("<I", x)

shellcode = b"\x90" * 16          # 占位，实际替换为 MessageBox/反弹 shell 等 payload
last_seh_record = 0x0019FFE4      # 原 SEH 链最后一个合法记录（next=0xFFFFFFFF）
sehandler_field = 0x0019FDB4      # 缓冲区起始，shellcode 地址

offset_next = 0xD0                # 缓冲区到 SEH_Record[0].next 的偏移
payload = shellcode + b"\x90" * (offset_next - len(shellcode))
payload += p32(last_seh_record)   # SEH_Record[0].next -> 合法尾记录
payload += p32(sehandler_field)   # SEH_Record[0].handler -> shellcode
open("111.txt", "wb").write(payload)
```

```text
# 伪造后的内存（原文调试器）：
# 0019FE84  0019FFE4   指向 SEH_Record[1] 的指针（实际直接指向链尾记录）
# 0019FE88  0019FDB4   被覆盖的 handler（缓冲区/shellcode）
# 0019FFE4  FFFFFFFF   SEH 链结束
# 0019FFE8  76F692E8   ntdll.RtlCaptureContext+108（终极异常处理器）
```

## 变体与关联

- 变体：直接覆盖返回地址/虚函数表，不经过 SEH，天然不受 SEHOP 限制。
- 变体：若 SafeSEH 开启，可把 handler 指向已登记的安全 handler 或利用 SafeSEH 自身缺陷；也可用 ROP 链替代栈上 shellcode 以绕过 DEP。
- 变体：SEHOP 的“链尾必须为 ntdll 终极处理器”在不同 Windows 版本上处理器地址不同，需要按目标环境确认。
- 关联：[[code-analysis-reverse-windows-ollydbg-seh-chain-handler-locate]]（定位 SEH 链与 handler）、[[code-analysis-reverse-windows-seh-exception-logic-jump-z3-serial]]（SEH 异常逻辑分析）、[[code-analysis-reverse-windows-jmp-esp-dll-aes-shellcode-stack-overflow-loader]]（Windows 栈溢出 + jmp esp shellcode）。
- 边界：x64 表驱动 SEH、SEHOP+SafeSEH+ASLR+DEP 全部开启且无信息泄露、无法触发异常、handler 不在可执行内存时，本手法失败。

## 检测与防御

- 检测：异常发生前检查 SEH 链，若 handler 字段指向栈/堆等非模块地址，或 next 指针绕过中间记录直接指向链尾，属可疑伪造；监控进程在异常处理前对栈上 SEH 记录的写入。
- 防御：保持 SEHOP 与 SafeSEH 开启（现代 Windows 默认），启用 ASLR/DEP/CFG；对关键进程启用更严格的缓解策略；不要把栈地址泄露给攻击者。
- 加固/分析：分析样本时手动走一遍 SEH 链，核对链尾是否为系统终极处理器；不要只看 handler 是否在模块内，还要看 next 指针是否被篡改。
