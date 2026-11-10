---
id: code-analysis-reverse-windows-keygenme-name-4byte-serial-keygen
title: KeygenMe 名称→4 字节序列号：逐字符 c²+((c>>1)+3)c-c 累加翻倍，Serial 前 4 字节小端比较，按字符集约束枚举 Name 生成合法 Serial
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: keygenme-name-to-4byte-serial-keygen
tags:
- reverse
- windows
- crackme
- keygen
- ollydbg
- api-breakpoint
- serial
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:20:34+08:00'
  notes: 已对照原文与图01-08核对：GetDlgItemTextA 两控件、0x401309-0x401334 每个字符 c²+((c>>1)+3)c-c 后 ESI 翻倍、0x401336 CMP ESI,[403138] 小端4字节、Name=A→0x3246→F2、0x40133C 75 15 NOP 均一致；复算 A 算法得 0x3246/F2。未运行样本
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-keygenme-name-4byte-serial-keygen/
draft: false
kb_aliases:
- KeygenMe 注册机
- Name 生成 Serial
- GetDlgItemTextA 断点
- 4 字节小端比较
- 字符集约束枚举
- NOP JNZ 爆破
- TASM/MASM CrackMe
---

## 一句话结论

该 KeygenMe 用 `GetDlgItemTextA` 读取 `Name/Serial`，对 `Name` 的每个字节 `c` 累加 `c*c + (((c>>1)+3)*c - c)` 并把累加值整体翻倍，循环结束后把 32 位结果与 `Serial` 前 4 字节按小端比较；由于合法 Serial 的每个字节还必须是 62 字符集内的 ASCII 字符，很多 `Name` 根本算不出可打印序列号，实用做法是枚举候选 `Name` 直到 4 字节结果全部落在字符集内，或直接把比较后的 `JNZ` 补丁成 NOP。

## 原理

- **输入与校验位置**：程序是 32 位 GUI（TASM/MASM，无壳），区配 106/107 两个控件分别调用 `GetDlgItemTextA` 读 `Name` 与 `Serial`，缓冲区各 26 字节；若任一为空则弹 “Give me more material hehe!!”，否则进入算法。用 OllyDbg 在 `GetDlgItemTextA` 下断，点 Check 即停在 0x004012BD 的调用处，向下单步即可看到完整校验流程。
- **Name 算法**（0x00401309–0x00401334 的循环）：
  1. 取 `Name` 当前字节 `c = name[i] & 0xFF`；
  2. `ESI += c*c`；
  3. `EBX = (c >> 1) + 3; EBX *= c; EBX -= c; ESI += EBX`；
  4. `ESI += ESI`（整体左移 1 位，等价乘 2）；
  5. `i++`，直到处理完 `lstrlenA(Name)` 个字符。
  逐步化简：每字符贡献 `2*(c² + ((c>>1)+3)c - c) = 2*(c² + (c>>1+3)c - c)`，循环按 32 位自然溢出（`ESI` 为 DWORD）。
- **比较方式**：0x00401336 处 `CMP ESI, DWORD PTR DS:[403138]`，`403138` 是 `Serial` 输入缓冲区起始，即把 `ESI` 与 `Serial` 的**前 4 个字节按小端 DWORD** 比较；`Serial` 第 5 字节起不参与校验。因此合法 Serial 只需头 4 字节等于计算结果。
- **字符集约束为什么导致枚举**：写注册机时要把 32 位结果按小端拆成 4 个字节，每个字节必须是可直接输入的 ASCII 字符。若某字节为 0x00–0x2F、0x7B–0xFF 等不可打印值，就无法构造出可通过 `GetDlgItemTextA` 输入的 Serial（程序按原始字节比较，不做 hex 解码）。所以常见思路不是“为任意 Name 算 Serial”，而是枚举 Name（如数字/大小写字母 62 字符集），筛出 4 字节全部为可打印字符的组合，再用该 Name/Serial 登录；文章示例 `Name=A` 时 `ESI=0x3246`，Serial 为 `F2`。
- **补丁路径**：比较后 0x0040133C 是 `JNZ SHORT 0x00401353`（机器码 `75 15`），把该跳转 NOP 掉即可让任意 `Name/Serial` 顺序走到成功分支，无需理解算法。这与“写 keygen”是两条等价路径。

## 触发条件

- 目标为本地 Windows 32 位 GUI 授权校验程序，校验逻辑在客户端完成（无服务端二次校验），且无壳/未做强反调试。
- 能使用 OllyDbg/IDA 等调试器附加或静态分析目标；有可输入的 `Name`、`Serial` 控件。
- 需要为任意/指定 `Name` 生成可输入的 Serial，或只需绕过本次本地校验（补丁场景）。
- 若目标 Name 的 4 字节结果包含不可打印字节，则 keygen 需要枚举 Name；如果必须用固定 Name，只能走补丁路径。

## 利用步骤

1. 用 PEiD 确认位数/编译器/壳（本例 32 位 TASM/MASM、无壳）；导入 OllyDbg。
2. `Ctrl+N` 查看导入表，对 `GetDlgItemTextA` 下 `BPX` 断点；F9 运行，输入任意 `Name/Serial` 点 Check，断在读取控件的调用处。
3. 单步/`F8` 越过两次 `GetDlgItemTextA`，定位 `Name` 长度检查与 0x00401309–0x00401334 的逐字符循环；记录 `c*c` 项与 `((c>>1)+3)*c - c` 项、最后 `ESI += ESI`。
4. 在 0x00401336 确认 `CMP ESI, [Serial]` 是小端 DWORD 比较；确认 Serial 仅前 4 字节参与。
5. 写注册机：按 `Name` 字节实现算法，把结果按小端拆 4 字节并检查每字节是否在可输入字符集内；对固定 Name 无解时改为枚举 Name（或直接做第 6 步补丁）。
6. 补丁替代：把 0x0040133C 的 `75 15` 改为 `90 90`，保存为新文件，任意非空 `Name/Serial` 均通过（文章用 `R/R` 验证）。
7. 在目标程序输入生成的 `Name/Serial`（或补丁文件），确认弹出成功提示。

## PoC

无漏洞利用 PoC；以下为按汇编重写的 keygen 计算与枚举脚本（未对目标程序实跑，算法用文章示例校验：`Name=A → 0x3246 → Serial "F2"`）。

```python
CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def name_to_num(name: str) -> int:
    n = 0
    for c in name.encode("latin1"):          # 目标用 MOVZX，按无符号字节
        n = (n + c * c) & 0xFFFFFFFF
        e = (((c >> 1) + 3) * c - c) & 0xFFFFFFFF
        n = (n + e) & 0xFFFFFFFF
        n = (n * 2) & 0xFFFFFFFF
    return n

def num_to_serial(n: int):
    h = f"{n:x}"                              # 与文章 keygen 一致：不补前导 0
    if len(h) % 2:
        return None                          # 奇数个 hex 字符无法按字节配对
    out = []
    for i in range(0, len(h), 2):
        b = int(h[i:i+2], 16)
        if chr(b) not in CHARS:
            return None                      # 该字节不可输入
        out.append(chr(b))
    return "".join(reversed(out))

assert name_to_num("A") == 0x3246 and num_to_serial(0x3246) == "F2"

# 枚举长度 1-2 的 Name，输出可输入的合法 Name/Serial
for L in (1, 2):
    for i in range(len(CHARS) ** L):
        s, x = "", i
        for _ in range(L):
            s = CHARS[x % len(CHARS)] + s
            x //= len(CHARS)
        ser = num_to_serial(name_to_num(s))
        if ser:
            print(s, ser)
```

## 变体与关联

- 变体：`Serial` 只比较前 4 字节，后面可带任意后缀；若目标把比较改为 `lstrcmpA` 或逐字节循环，则 keygen 必须输出完整字符串。
- 变体：文章 C++ keygen 用 `std::string` 与 `char` 做 `c*c`，对 >0x7F 的非 ASCII 字节会按有符号 char 处理，与目标 `MOVZX` 的无符号语义不一致；PoC 已按目标汇编使用无符号字节。
- 变体：不写 keygen，直接 NOP 比较后的条件跳转，属于通用“本地校验补丁”路径；检测/定位思路与 keygen 相同。
- 关联：[[code-analysis-reverse-windows-winhex-license-crc32-keygen]]（商业程序注册算法逆向与 keygen）、[[ctf-reverse-keygenme4-xor-chain-crc32-keygen]]（KeygenMe 序列号校验逆推）、[[code-analysis-dynamic-debugging-crackme-password-check-patch]]（调试器改标志位/补丁绕过）。

## 检测与防御

- 检测：程序侧可检测调试器（`IsDebuggerPresent`/PEB）、对代码段做校验和、检测 `JNZ` 处字节被改为 `90 90`；也可把关键比较下沉到服务端或加密狗，避免仅靠本地常量/算法判定。
- 防御：授权校验不要只依赖客户端一次性比较；对输入做服务端签发/验签，序列号与用户/硬件绑定并带完整性保护；对二进制做签名与完整性校验，增加补丁与内存修改成本。
- 说明：本文是 CrackMe 逆向学习场景，针对本地授权校验，severity 记为 low；仅用于授权的逆向分析。
