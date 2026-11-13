---
id: code-analysis-reverse-obfuscation-autoit-external-chartable-index-concat
title: AutoIt 脚本以外部 test.txt 作字符索引表：按 $A[n] 拼接还原命令与十六进制 shellcode，再 Execute/DllStructSetData/VirtualProtect/EnumWindows 执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: autoit-external-chartable-index-concat
tags:
- windows
- autoit
- obfuscation
- string-table
- execute
- virtualprotect
- enumwindows
- shellcode
- malware-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V493
  verified_at: '2026-11-11T00:01:56+08:00'
  notes: 已对照原文与图13-17核对：test.txt 76 字节、StringSplit(FileRead(@ScriptDir & "\test.txt"), "", 2)、$A[61]&$A[48]... 下标拼接、$ZZNdmOFL 十六进制串、DllStructCreate("byte[47172]")、VirtualProtect 0x40、EnumWindows 回调、CProgramDataSophos 拼接残缺均一致。未验证点：未取样本实跑还原脚本；原文未给版本，未设 affected_versions；frontmatter 无 sources/source_url
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-autoit-external-chartable-index-concat/
draft: false
kb_aliases:
- test.txt 字符表混淆
- AutoIt 索引拼接
- $ZZNDMOFL
- DllStructCreate byte[47172]
- EnumWindows 回调执行 shellcode
- script.au3
- AutoIt Execute 重建代码
---

## 一句话结论

AutoIt 脚本把所有字符串、代码片段和二进制载荷都拆成单字符，存进同目录一个 76 字节的 `test.txt`；运行时用 `StringSplit(FileRead(...), "", 2)` 得到字符数组，再按硬编码下标以 `$A[61] & $A[48] & ...` 的形式拼接出命令、比较条件与十六进制字符串，交给 `Execute()` 执行；最后把拼出的十六进制串用 `BinaryToString("0x" & ...)` 还原为字节写入 `DllStructCreate("byte[47172]")` 缓冲区，`VirtualProtect` 改为 `PAGE_EXECUTE_READWRITE` 后通过 `EnumWindows` 回调执行。

## 原理

- **外部字符表**：脚本不直接出现 `DllCall`、`VirtualProtect`、十六进制 shellcode 等敏感字符串，而是把构成这些字符串的字符集中放在 `test.txt`（示例 76 字节）。脚本按固定下标从数组取字符拼接，因此静态看 `script.au3` 只有大量 `$A[数字]` 运算，`strings` 也拿不到有效关键字。
- **StringSplit 按字符拆分**：AutoIt 的 `StringSplit($str, "")`（空分隔符）会把字符串拆成单个字符组成数组，默认数组下标从 1 开始、`$A[0]` 保存元素个数。脚本随后用 `$A[n]` 取字符拼出 `$ZZNDMOFL` 等变量，或以 `Execute($A[x] & $A[y] & ...)` 动态执行拼出的代码。
- **`Execute()` 是代码执行入口**：AutoIt 的 `Execute(string)` 会把字符串当表达式/语句求值；因此只要把 `DllCall(...)`、`FileExists(...)`、`DllStructCreate(...)` 等调用拼成字符串，就能在不出现明文关键字的情况下执行。示例还拼出 `FileExists("CProgramDataSophos")` 一类环境检查（原文指出目录名因混淆/拼接错误而缺少反斜杠）。
- **为什么用十六进制字符串装载荷**：拼接出的 `$ZZNdmOFL` 是不带 `0x` 前缀的十六进制字符序列；`BinaryToString("0x" & $ZZNdmOFL)` 把它还原为原始字节，`DllStructSetData($pt, 1, ...)` 写进 `DllStructCreate("byte[47172]")` 分配的缓冲。这样 shellcode 在脚本里以“字符表 + 下标”形式存在，没有连续的高熵二进制特征。
- **回调执行**：`VirtualProtect(..., 0x40)` 把缓冲区改为可读写执行；`DllCall("user32.dll", "int", "EnumWindows", "ptr", DllStructGetPtr($pt), "lparam", 0)` 把缓冲区地址当作 `WNDENUMPROC` 回调传给 `EnumWindows`，系统枚举窗口时调用该地址，shellcode 获得执行。该原语不创建线程，规避以 `CreateThread` 为锚点的检测。
- **可替换性**：字符表与下标表都是构建期生成的，换一个样本只需换 `test.txt` 和下标常量；同一套脚本骨架可反复使用，因此检测应针对“外部字符表 + 下标拼接 + Execute”的结构而不是单一样本哈希。

## 触发条件

- 目标运行 `AutoIt3.exe`（或编译后的 AutoIt EXE）执行 `script.au3`，且 `test.txt` 与脚本位于同一目录（`@ScriptDir`）。
- 脚本具备读取文件、`DllCall` 与 `Execute` 权限；Windows 进程允许分配/修改可执行内存并把地址作为回调传入 `EnumWindows`。
- 分析侧：拿到脚本与 `test.txt`；缺任意一个都无法静态还原字符串（字符表缺失时下标无意义）。

## 利用步骤

1. **提取脚本**：从 AutoIt 编译样本/释放链中取出 `script.au3` 与同目录 `test.txt`，记录文件大小（示例 76 字节）与内容。
2. **重建字符数组**：按 AutoIt 语义把 `test.txt` 拆成单字符数组（1-based，`$A[0]` 为长度），或直接用 Python 以 `chars[n-1]` 模拟。
3. **还原拼接表达式**：定位 `$A[数字] & $A[数字] ...` 形式的赋值与 `Execute(...)` 调用，按顺序求值；可用脚本模拟 AutoIt 的 `&` 拼接与 `Execute` 语义，或手工替换下标。
4. **提取载荷**：从还原出的 `$ZZNdmOFL`/十六进制串中去掉非十六进制字符，`bytes.fromhex()` 得到二进制；示例载荷以 `MZRE`（`4D 5A 52 45`）开头，是后续 PE/加载器 shellcode。
5. **确认执行原语**：核对还原出的 `DllStructCreate`/`DllStructSetData`/`VirtualProtect`(0x40)/`EnumWindows` 调用与偏移，动态调试时在 `EnumWindows` 前 dump 缓冲区。
6. **后续分析**：按 shellcode/PE 加载器流程继续（导入解析、重定位、解密下一阶段）。

## PoC

字符串还原思路（Python 模拟 AutoIt 下标拼接，不含样本真实字符表）：

```python
chars = open("test.txt", "rb").read().decode("latin-1")
def A(n):            # AutoIt 数组 1-based；$A[0] 为长度
    return chars[n-1] if n >= 1 else str(len(chars))
expr = [61, 48, 63, 12, 48, 48, 48, 48, 21, 23, 22, 5, 13]  # 示例下标
s = "".join(A(i) for i in expr)
print(s)
# 对 $ZZNdmOFL 同理拼接出十六进制串后：
# blob = bytes.fromhex(hexstr)
# open("stage.bin","wb").write(blob)
```

还原出的 AutoIt 执行骨架（示意）：

```autoit
$A = StringSplit(FileRead(@ScriptDir & "\test.txt"), "", 2)
$ZZNdmOFL = $A[61] & $A[48] & $A[63] & ...
$PT = Execute(DllStructCreate("byte[47172]"))
Execute(DllCall("kernel32.dll", "BOOL", "VirtualProtect", "ptr", DllStructGetPtr($PT), "int", 47172, "dword", 0x40, "dword*", Null))
Execute(DllStructSetData($PT, 1, BinaryToString("0x" & $ZZNdmOFL)))
Execute(DllCall("user32.dll", "int", "EnumWindows", "ptr", DllStructGetPtr($PT), "lparam", 0))
```

无独立可执行 PoC；上述为分析还原方法。

## 变体与关联

- **同族不同混淆**：同一 DarkGate AutoIt 载荷家族另有 `.a3x` 内 `_ENCRYPT` 的 XOR+BitNOT 折叠密钥加密（见关联卡）；本卡的外部字符表 + 下标拼接与它是两套可独立替换的字符串保护。
- **字符表来源**：`test.txt` 可换成注册表值、环境变量、远程下载或脚本内嵌数组；下标可随机化/加密，甚至按构建生成不同表。
- **执行原语**：`EnumWindows` 可换成其他回调 API（`EnumChildWindows`、`EnumThreadWindows`、定时器回调等）；`VirtualProtect` 可换成 `VirtualAlloc(PAGE_EXECUTE_READWRITE)` 或 `NtProtectVirtualMemory`。
- **关联卡**：AutoIt3 解释器载荷宿主、本地回调/纤程执行原语、AutoIt a3x 提取与 XOR 解密、DarkGate Delphi 加载器（本脚本解出的后续阶段）。
- **边界**：`Execute` 的求值语义与 AutoIt 版本相关；`test.txt` 缺失或编码变化会导致还原失败；示例中的环境检查目录名本身因拼接错误而无效，说明混淆生成器可能带 bug。

## 检测与防御

- **脚本特征**：检测 AutoIt 脚本/编译样本中出现 `StringSplit(FileRead(...), "", 2)`、大量 `$A[数字]` 下标拼接、`Execute(`、`DllStructCreate("byte[...]")`、`DllCall(...VirtualProtect...)`、`EnumWindows` 的组合；检查脚本同目录是否存在小的 `.txt` 数据文件。
- **行为监控**：监控 AutoIt3 进程读取同目录文本后调用 `VirtualProtect`/`VirtualAlloc` 并把返回地址传给回调 API；关注 AutoIt 进程内出现无模块可执行内存页被 `EnumWindows` 等回调调用的调用栈。
- **文件侧**：对“脚本 + 字符表”成对出现、脚本几乎不含可读字符串的样本重点分析；保留 `test.txt` 以便还原。
- **策略**：非必要环境禁止 AutoIt3/AutoHotkey 解释器从用户目录运行；限制脚本解释器读取同目录数据文件并执行动态代码的行为；开启 ACG/CFG 可阻断把裸地址当回调执行。
