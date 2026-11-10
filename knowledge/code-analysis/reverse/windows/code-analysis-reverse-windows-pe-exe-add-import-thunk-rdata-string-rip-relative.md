---
id: code-analysis-reverse-windows-pe-exe-add-import-thunk-rdata-string-rip-relative
title: 给已有 EXE 加功能注入：rdata 追加字符串 + 在 .text 尾部造函数跳转桩 + 序言后插入 RIP 相对寻址调用
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-exe-patch-add-import-thunk-string-rip-relative
aliases:
- PE 文件代码注入
- 扫雷弹窗注入
- 给 exe 加 MessageBoxA
- rdata 追加字符串
- 手工造导入函数桩
- ASLR 下 RIP 相对寻址改写
- 静态补丁加代码
tags:
- pe
- code-cave
- binary-patch
- rip-relative
- aslr
- x64
- windows
- reverse
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:34:18+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文一致处：rdata 段末尾用010 editor追加PE injected与You are injected!、参照exit桩在text末尾造MessageBoxA跳转桩、注入点必须放在sub rsp,0E0h之后、用RIP相对寻址(字节码49 c7 c1 40 10 00 00 / 4c 8d 05 xx / 48 8d 15 xx / 48 c7 c1 00 00 00 00)、先填近似偏移再用Change Byte微调、最终目标MessageBoxA(0," You are injected!\,\PE injected\,0x1040)；具体RVA/位移数值仅见图片，卡内以公式与占位符给出，未编造
---

## 一句话结论

不新增 section、不改导入表结构，只在既有 PE 里做三处手术：把新字符串追加到 `.rdata` 末尾、在 `.text` 末尾照着已有导入函数的跳转桩再造一个目标 API 的桩、把调用代码插在目标函数序言（`sub rsp, 0xE0`）之后——全部用 RIP 相对寻址（`lea r8, [rip+off]` / `call` 相对跳转）来适配 ASLR，就能让原始程序在正常流程里执行注入代码（示例是点开程序时弹出指定标题与内容的窗口）。

## 原理

- **为什么不新建 section**：新增 section 会改变节表、文件大小与对齐，容易被校验/签名检查发现，也让重定位与装载器行为更复杂。往既有节的尾部追加（利用节末尾的对齐填充）只改动已有字节范围，改动面最小。
- **为什么在 `.rdata` 尾加字符串**：`.rdata` 是只读数据段，节末尾按 `FileAlignment` 对齐后通常有空隙；字符串放这里即成为合法的只读数据，能被 `lea` 引用，无需运行时分配。
- **为什么必须用 RIP 相对寻址**：x64 在 ASLR 下每次加载基址不同，绝对地址（`mov rdx, imm64`）会失效。`lea rdx, [rip+disp32]` 由装载器在指令语义里即时算出绝对地址，只要 `disp32` 是「目标 RVA − 下一条指令 RVA」，无论基址怎么变都正确。原文的做法是先按估算写一个 `.rdata` 范围内的偏移，再在调试器里按实际落地位置微调，直到命中。
- **为什么要手工造函数桩**：程序原本没有导入 `MessageBoxA`，但 `.idata` 里可能存在该函数的导入项（被别的模块引用），却没有任何可 `call` 的代码地址。照抄编译器为其他导入函数生成的那段桩（`jmp qword ptr [rip+off]` 形式），就得到一个可以直接 `call` 的函数入口，等价于「手工补一条导入 thunk」。桩里同样是 RIP 相对寻址指向 IAT 槽。
- **为什么代码必须插在序言之后**：`sub rsp, 0xE0` 才为当前函数分配好栈空间，在它之前插代码会让栈指针与函数预期不符，函数返回时堆栈失衡、直接崩溃；插在其后则复用函数已有的栈帧。
- **x64 调用约定约束**：前四个整型/指针参数用 `RCX`/`RDX`/`R8`/`R9`，且调用前必须保留 32 字节 shadow space（本例 `sub rsp` 已给出）；本例把 `hWnd=0`、`lpText`、`lpCaption`、`uType` 分别放 `rcx/rdx/r8/r9`，顺序错一个参数就弹不出来或直接崩。

## 触发条件

- 目标为 x64 PE（EXE），可静态修改后仍能被正常加载运行（无强完整性校验/签名强制）。
- `.rdata`、`.text` 节末尾存在足够大的对齐空隙（或能找到可安全复用的填充字节）。
- 程序中有可参照的导入函数桩可照抄（否则需要自行处理 IAT 结构）。
- 存在一个「每次都会执行、且序言之后有足够插入空间/可挪动后续指令」的函数作为注入点。
- 具备调试器（下断点、看 RIP 与内存、按实际地址微调位移）。

## 利用步骤

1. 备份原始文件（静态补丁不可逆）。
2. 在反汇编视图里定位 `.rdata` 末尾与 `.text` 末尾，记录两者的 RVA 与文件偏移。
3. 在 `.rdata` 末尾追加所需字符串（标题与内容），记下它们的 RVA；注意字符串需要以 `\x00` 结尾，且不要越过节的对齐边界。
4. 定位要注入的函数与它的序言（如 `sub rsp, 0xE0`），把插入点定在序言之后，避免破坏栈平衡。
5. 找一个已存在的导入函数桩（如 `exit`），照它的字节形态在 `.text` 末尾造目标 API 的桩，先用任意 `.idata` 范围内的偏移占位，后续在调试器里校正。
6. 计算注入代码：`lea r8, [rip + (str_caption - next_insn)]`、`lea rdx, [rip + (str_text - next_insn)]`、`mov rcx, 0`、`mov r9d, uType`，最后 `call` 刚造的桩。
7. 把汇编翻成字节码写入插入点（若汇编器报 `Invalid operand`，用十六进制编辑器按字节写，再在反汇编视图里核对）。
8. 运行程序并下断点：确认执行到插入点；用调试器读出字符串与桩的实际地址，按「目标 RVA − 下一条指令 RVA」修正两处 `disp32`，反复迭代直到 `lea` 解析出正确地址。
9. 确认最终效果（示例为点击程序时弹出标题/内容正确的窗口），并核对反编译伪代码是否与预期调用一致（`MessageBoxA(0, "...", "...", uType)`）。
10. 记录每处改动的 RVA/偏移与最终 `disp32` 值，便于复现或做同类改造。

## PoC

```asm
; 注入代码（插在 sub rsp, 0E0h 之后）
; 目标：MessageBoxA(0, "You are injected!", "PE injected", 0x1040)
mov  r9d, 1040h                ; 49 C7 C1 40 10 00 00
lea  r8,  [rip + disp_cap]     ; 4C 8D 05 xx xx xx xx   -> 标题
lea  rdx, [rip + disp_txt]     ; 48 8D 15 xx xx xx xx   -> 内容
mov  rcx, 0                    ; 48 C7 C1 00 00 00 00
call <MessageBoxA_thunk>       ; E8 xx xx xx xx（若桩在同段内）
```

```asm
; .text 末尾手工桩（形态照抄已有导入函数桩）
jmp qword ptr [rip + disp_iat]  ; FF 25 xx xx xx xx
```

```text
; 位移计算（x64 RIP 相对，全部以 RVA 计）
disp = target_rva - (instruction_rva + instruction_length)

; 关键约束
1) 字符串追加在 .rdata 尾，且不跨节边界
2) 注入代码必须在 sub rsp, 0E0h 之后
3) 桩的 disp 指向 .idata 中目标 API 的 IAT 槽
4) 每处 disp 都要在调试器里按实际地址复核后微调
```

（字节码取自原文示例；`disp` 的具体数值依赖目标 PE 布局，需按上述公式与调试验证。）

## 变体与关联

- **变体一**：注入点换成程序启动时必经的初始化函数，效果变为「一运行就执行」；代价是更容易被行为监控注意到。
- **变体二**：不造函数桩，改为在 `.text` 空隙里直接写一段自包含 shellcode（`VirtualProtect` + 加载器），适用于目标 API 未被导入程序的情况。
- **变体三**：目标 API 需要更多参数时，按 x64 约定把第 5 个及之后的参数压栈，并注意 16 字节对齐与 shadow space。
- **变体四**：把「加一个弹窗」换成「解一段加密 payload 并跳转」，即静态补丁型木马化的最小骨架。
- **关联**：[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]]（同为在既有 PE 的 `.text` 空洞里放代码并改写 `E8 rel32`，但对象是 DLL 侧加载、并处理 `.reloc` 清零与自动化验证流水线；本条是 EXE 加功能、靠 RIP 相对寻址与新造导入桩，不涉及 `.reloc`）、[[code-analysis-reverse-windows-iat-hook-install-messagebox]]（同样围绕 IAT/导入函数做改写，方向是运行时 hook 而非静态补丁）、[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]] 的「code cave」概念是本节「节尾空隙」的近亲。

## 检测与防御

- **完整性校验**：对可执行文件做签名校验 + 节哈希/整文件哈希白名单；重点比对 `.text`/`.rdata` 节的内容哈希与节大小是否与官方一致（追加内容会改变节尾字节，但不动节表，需按字节比对才能发现）。
- **异常特征**：`.text` 尾部出现不属于任何函数、以 `lea r8/rdx, [rip+...]` + `call` 结尾的孤立代码块；`.rdata` 尾部出现可读英文字符串；`.idata` 中存在某 API 的导入项但该 API 在原始构建中从未被调用。
- **运行时**：非预期进程调用 `MessageBoxA`/`User32` 弹窗 API（尤其来自无窗口的 CLI 程序）；加载后立即出现与程序功能无关的 GUI 行为。
- **加固**：开启 WDAC/AppLocker 的签名与哈希规则，禁止未签名/被修改的二进制执行；对分发渠道做文件级签名校验。
