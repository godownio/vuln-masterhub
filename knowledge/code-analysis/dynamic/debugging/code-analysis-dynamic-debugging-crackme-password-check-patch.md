---
id: code-analysis-dynamic-debugging-crackme-password-check-patch
title: x64dbg 动态调试破解密码校验：改寄存器/ZF 与二进制补丁绕过本地及服务端验证
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: x64dbg-password-check-register-zf-patch
aliases:
- x64dbg 破解密码校验
- strcmp 断点改寄存器
- 零标志位 ZF 绕过
- check_pass 补丁
- 服务端验证补丁
- crackme 密码爆破
tags:
- reverse-engineering
- x64dbg
- dynamic-analysis
- debugging
- crackme
- patch
- strcmp
- zf
- winsock
- x86-64
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T13:15:29+08:00'
  notes: 已对照原文与 img/01-18 核对：x64dbg 断点在正确/错误字符串比较处、RCX=输入/RAX=passwordI、改 EAX/RAX 1→0、cmp eax,1+jne 改 ZF/跳转、bin patch，以及服务端验证程序在 recv 后比较 Valid\n 并改 ZF/补丁的第二种场景均与原文一致；PoC 为操作要点而非脚本；未在本机重跑 crackme。
---

## 一句话结论

对带密码校验的 crackme，用 x64dbg 在“错误/正确”字符串交叉引用或 `strcmp`/比较指令处下断点，观察比较寄存器中的输入与正确值；随后修改函数返回值寄存器（把 `EAX/RAX` 的 1 改成 0）、在比较前把两个寄存器改成相同值、翻转零标志位 ZF，或直接把条件跳转/NOP 打成补丁，即可让任意输入通过校验。对“密码发给服务端验证”的程序，同样可在 `recv` 后的比较/分支处改 ZF 或补丁掉判断，生成不依赖服务器的破解版。

## 原理

- **返回值决定分支**：`check_pass` 这类函数把比较结果放进返回寄存器（x64 为 `RAX`，其中低 32 位为 `EAX`）；`main` 用 `cmp eax, 1` / `test eax, eax` 等指令决定打印 “Correct” 还是 “InCorrect”。返回值或被比较的寄存器是可控的中间状态，修改它就能改变控制流。
- **比较指令设置标志位**：`cmp`/`test` 不直接产生布尔值，而是设置 ZF（相等/为零时 ZF=1）；随后的 `je/jne` 依据 ZF 跳转。把 ZF 置 1（或把 `jne` 改成 `jmp`/NOP）即可让“密码错误”的分支被跳过。
- **正确值就在进程内存里**：明文比较时，正确密码会以字符串常量形式存在于 `.rdata`，或在使用前被加载到寄存器；断在 `strcmp`/比较点即可直接读出。对于 XOR/哈希等变换，正确值则是变换后的数组或摘要，需要按算法逆推（见关联卡片）。
- **服务端验证的客户端仍然可补丁**：即使密码由服务器判断，客户端仍要在本地接收响应并比较 `"Valid"`/`"InValid"`；比较结果和分支在客户端进程中，修改 ZF、比较寄存器或跳转即可绕过，服务器是否可达不再是必要条件。
- **二进制补丁可持久化**：调试器里改寄存器只影响当前进程；把 `mov eax,1` 改成 `xor eax,eax`、把 `jne` 改成 `jmp`/NOP、或把比较改成恒等，并保存到文件，就得到任意密码都能通过的程序副本。

## 触发条件

- 目标程序使用本地明文/变换后的密码比较，或接收服务端验证结果后在本地做字符串比较。
- 程序未对代码段做完整性校验/反调试（或有但可绕过），允许调试器附加、下断点与修改内存。
- 比较点可通过字符串交叉引用（`"Correct"`/`"InCorrect"`/`"Valid"`/`"Invalid"`）、API 断点（`strcmp`、`lstrcmp`、`memcmp`）或单步跟踪定位。
- 攻击者能在本机运行目标（crackme/授权校验/离线客户端）。

## 利用步骤

1. 用 x64dbg 载入程序，运行到输入提示；在 `"Correct"`/`"InCorrect"` 字符串上查交叉引用，或在导入表给 `strcmp`/`lstrcmp` 下断点。
2. 输入任意密码（如 `123321`），在比较点停下；观察寄存器：本例 `RCX` 为输入 `123321`、`RAX` 为正确值 `passwordI`，说明 `check_pass` 内部使用 `strcmp`。
3. 定位返回值的赋值：在比较后的 `mov eax, 1`（错误）与 `mov eax, 0`（正确）分支处下断点；命中错误分支时把 `EAX/RAX` 改为 0，继续运行，程序打印 “Correct”。
4. 或者直接改标志位/跳转：在 `cmp eax, 1; jne ...` 处把 ZF 置 1，或把 `jne` 改成 `jmp`/NOP；也可用 “汇编” 功能把 `mov eax,1` 改为 `xor eax,eax`。
5. 对服务端验证程序：在 `WSAStartup/socket/connect/send/recv` 调用链上跟踪，找到 `recv` 后与 `"Valid\n"` 的比较点；在 `test eax,eax; jne ...` 处把 ZF 置 1（或修改比较前寄存器使两者相等），使本地判定恒为通过。
6. 确认结果后，把修改写回文件（补丁）或记录寄存器/ZF 操作，形成可复现的破解步骤；必要时对多个比较点逐一处理。

## PoC

无独立脚本；以下为 x64dbg 操作要点（地址/寄存器名按目标调整）：

```text
# 1) 在 "Correct"/"InCorrect" 字符串交叉引用处或 strcmp 下断点
bp <check_pass 内比较地址>
bp strcmp

# 2) 输入任意密码，命中后观察
#    RCX = "123321"（输入）
#    RAX = "passwordI" / "Valid\n"（正确值）

# 3) 方式一：跳过错误分支（cmp eax,1; jne 错误分支）
#    在 jne 处将 ZF 置 1，或把 jne 汇编为 jmp / NOP

# 4) 方式二：改返回值（错误分支 mov eax,1）
#    单步到 mov eax,1 后执行：r eax=0

# 5) 方式三：改比较前寄存器，使 rax 与 rdx 指向同一值
#    r rax=rdx

# 6) 补丁持久化：右键指令 -> 汇编，把 mov eax,1 改为 xor eax,eax，
#    或把 jne 改为 jmp，保存到可执行文件
```

## 变体与关联

- 变体：正确值不是明文而是 XOR/哈希/编码后的数组；此时需要在反汇编中找到密钥/码表并逆推（见 [[code-analysis-reverse-crypto-encoding-identification-decrypt]]）。
- 变体：校验逻辑被内联（没有独立 `strcmp` 调用），可用 `"Correct"` 字符串交叉引用、`cmp` 指令扫描或内存断点定位。
- 变体：服务端验证可结合 hosts 重定向/本地假服务器返回 `Valid`；或直接补丁客户端比较点，二者效果相同。
- 变体：加壳/反调试程序需先脱壳或绕过反调试（见 `code-analysis/reverse/anti-debug`、`code-analysis/reverse/unpacking` 下的卡片）。
- 边界：若程序使用代码签名/完整性自校验、远程证明或密钥在 TPM/安全硬件中，单纯改本地寄存器可能被检测或无法得到可用结果。

## 检测与防御

- 检测（逆向侧）：`"Correct"/"InCorrect"` 成对字符串、`strcmp`/`memcmp` 导入、`cmp eax,1` 后接 `jne`、函数返回 0/1 的模式，都是密码校验的典型特征。
- 防御（软件作者）：不要把“是否授权”的最终判断放在客户端；服务端做权威校验并对结果签名；对代码段做完整性校验、反调试与混淆；避免明文存储正确密码或可逆变换后的密码。
- 防御（检测补丁）：校验关键代码段哈希、检测调试器/断点（INT3、硬件断点寄存器）、对关键分支做冗余校验；授权令牌使用服务端签发且短期有效。
