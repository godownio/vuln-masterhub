---
id: code-analysis-dynamic-debugging-ollydbg-memory-breakpoint-registration-keygen
title: OllyDbg 内存断点还原注册算法并写注册机：GetDlgItemTextA 定位输入缓冲，Name 大写 ASCII 累加 ^0x5678 与 Serial 十进制转整数 ^0x1234 比对
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: ollydbg-memory-breakpoint-registration-algorithm-keygen
tags:
- reverse
- ollydbg
- dynamic-analysis
- memory-breakpoint
- keygen
- crackme
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V411-fix
  verified_at: '2026-11-09T15:02:33+08:00'
  notes: V411 核对指出：原理中『字符 <0x41 或 >0x5A 则进入小写处理 sub al,0x20』与汇编不符——0040138B 的 jb 目标是 004013AC（压 0x30/字符串并 call MessageBoxA 的失败弹窗，数字/空触发弹窗的来源），并非小写转换；小写转换在 00401394，由 0040138F 的 jnb（al>=0x5A，含 'Z'）进入并 call 004013D2。已重写 Name 算法段与步骤4，并在 PoC 注释注明 'Z'(0x5A) 会被减成 ':' 的边界。其余算法/注册机 Test→17676 核对不变。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-ollydbg-memory-breakpoint-registration-keygen/
draft: false
kb_aliases:
- OllyDbg 注册机
- 内存断点
- 内存访问断点
- 注册算法还原
- keygen
- GetDlgItemTextA 断点
---

## 一句话结论

用 `GetDlgItemTextA` 断点拿到输入框缓冲区地址，再对缓冲区设“内存访问”断点，让程序在真正读取 Name/Serial 的校验代码处中断；顺着读取点还原出 Name 的大写 ASCII 累加（^0x5678）与 Serial 的十进制字符串转整数（^0x1234）后比较的算法，即可写出等效注册机（Name `Test` → Serial `17676`）。

## 原理

- **API 断点定位输入**：`GetDlgItemTextA(hDlg, nIDDlgItem, lpString, cchMax)` 的第 3 个参数就是接收用户输入的内存缓冲区。在函数入口或返回处断下，从栈/寄存器即可读出该地址；`Ctrl+F9` 执行到返回后，缓冲区里就是用户输入的字符串（如 `Test`）。
- **内存访问断点定位消费点**：对缓冲区首字节设 OllyDbg 内存断点（访问），程序任何读写该地址的指令都会中断——正好落在校验函数读取首字符的循环处，避免在成千上万条指令里盲找。
- **Name 算法识别**：循环逐字节取值，`test al,al` 判串尾；字符 `<0x41`（如数字）经 `0040138B` 的 `jb 004013AC` 跳到失败弹窗（压 0x30/字符串并 `call MessageBoxA`，即数字输入触发弹窗的来源），不做转换；字符 `>=0x5A` 经 `0040138F` 的 `jnb 00401394` 进入 `call 004013D2` 执行 `sub al,0x20`（小写转大写；注意 `'Z'`=0x5A 也会被减成 `':'`=0x3A，与常规 toupper 的边界不同，本卡示例 `Test` 不触发该边界）；累加循环 `mov bl,[esi]; add edi,ebx; inc esi` 把处理后的 ASCII 相加；最后 `xor edi,0x5678` 得到 Name 校验值。
- **Serial 算法识别**：`mov al,0xA; mov bl,[esi]; test bl,bl; sub bl,0x30; imul edi,eax; add edi,ebx; inc esi` 即 `value = value*10 + (digit-'0')`，把用户输入的十进制数字串解析成整数；最后 `xor edi,0x1234`。
- **比较与注册机**：`cmp eax,ebx; je 成功`，其中 `eax = nameSum ^ 0x5678`、`ebx = serialVal ^ 0x1234`。因此令 `serialVal = nameSum ^ 0x5678 ^ 0x1234` 即可；由于输入框把 Serial 当十进制串解析，注册机需把该结果按十进制打印（`Test`：0x140^0x5678=0x5738，再 ^0x1234=0x450C=17676）。
- **为什么可行**：校验只依赖可逆的对称运算（ASCII 累加 + 固定异或），没有签名/密钥，算法完全可从动态跟踪中还原。

## 触发条件

- 原生 Win32 程序，注册框使用 `GetDlgItemTextA`/`GetWindowTextA` 读取输入，且未加壳/无强反调试。
- 校验全部在本地完成，结果可由输入经确定性算法计算。
- OllyDbg 可以附加并在输入缓冲区上下内存断点（内存断点同一时刻只能设一个，Name/Serial 需分两次运行分析）。

## 利用步骤

1. OllyDbg 载入程序，`Ctrl+N` 找到 `USER32.GetDlgItemTextA` 并下断点；`F9` 运行，在注册框输入 `Test` / `666666` 并点 OK。
2. 断在 `GetDlgItemTextA` 时查看栈参数：第 3 个参数 `lpString` 即输入缓冲区地址；`Ctrl+F9` 执行到返回，在内存窗口确认 `Test` 已写入。
3. 选中缓冲区首字节，右键“断点→内存访问”；`F9` 运行到读取该地址的校验代码。
4. 跟踪 Name 循环：确认字符 `<0x41` 走失败弹窗分支、`>=0x5A` 走 `sub al,0x20`（注意 `'Z'` 边界）、ASCII 累加与 `xor 0x5678`；记录 `nameSum`。
5. 重开一次程序，对 Serial 缓冲区设内存访问断点，跟踪 `*10 + digit` 的十进制解析与 `xor 0x1234`。
6. 找到 `cmp eax,ebx; je` 的最终比较，确认两路结果。
7. 写注册机：`serial = (Σtoupper(name) ^ 0x5678 ^ 0x1234)`，按十进制输出；用 `Test` 验证得到 `17676`，输入后弹出成功提示。

## PoC

```text
# 还原出的算法（注册机核心）
# 注意：程序对 al>=0x5A 减 0x20，'Z'(0x5A) 会被转成 ':'(0x3A)，与常规 toupper 边界不同
nameSum = sum( toupper(name) 的 ASCII 字节 )
serial  = (nameSum ^ 0x5678 ^ 0x1234)   # 以十进制字符串输入

# 验证：Test
# 'T'+'E'+'S'+'T' = 0x54+0x45+0x53+0x54 = 0x140
# 0x140 ^ 0x5678 = 0x5738 ; 0x5738 ^ 0x1234 = 0x450C = 17676
```

```text
# OllyDbg 操作链
Ctrl+N -> USER32.GetDlgItemTextA -> 断点 -> F9 -> 输入 Test/666666
栈第 3 参数 -> 缓冲区地址 -> 内存窗口选中 "Test" -> 右键 断点 -> 内存访问
F9 -> 命中校验循环 -> 单步还原算法
# Serial 需另开一次运行，对 Serial 缓冲区设内存访问断点
```

## 变体与关联

- 变体：内存断点换成硬件断点（Dr0-Dr3，最多 4 个，可同时观察 Name/Serial）；读取 API 换成 `GetWindowTextA`；算法中出现查表、CRC、乘法逆元时可用单步+已知输入输出拟合。
- 关联：与 [[code-analysis-dynamic-debugging-ollydbg-messagebox-return-address-jcc-patch]] 为同一 crackme 的“注册机路线”；与 [[code-analysis-dynamic-debugging-serial-data-constraint-memory-proximity]]（用假序列号在内存邻近处找真序列号）相比，本卡是完整算法还原；与 [[code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate]] 的“定位对话框回调/控件 ID”互补——本卡直接以输入缓冲区为锚点。
- 与 [[code-analysis-reverse-windows-hardcoded-serial-lstrcmp-api-breakpoint]] 的区别：那张针对硬编码字符串比较，本卡是计算型序列号。

## 检测与防御

- 检测：调试器附加、对输入缓冲区的内存/硬件断点；程序导入 `GetDlgItemTextA` 且在注册流程中被频繁断点。
- 防御（软件保护侧）：序列号使用非对称签名或服务器校验，避免本地可逆算法；对输入做混淆/多轮变换并混入机器绑定信息；加入完整性校验与反调试。
- 分析侧注意：OllyDbg 内存断点同一时刻只支持一个，Name/Serial 需分开运行；断点多时用“禁用”而非删除；内存断点不会显示在普通 CC 断点列表中。
