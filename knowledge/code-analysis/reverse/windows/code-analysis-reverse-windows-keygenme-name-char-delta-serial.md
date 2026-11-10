---
id: code-analysis-reverse-windows-keygenme-name-char-delta-serial
title: Name/Serial 逐字符差值注册码：Serial[i] = Name[i] - (NameLen - i)，长度 ≥5 校验与注册机
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: name-char-delta-serial-keygen
aliases:
- AD_CM#2
- ArturDents CrackMe#2
- Name Serial 注册机
- 逐字符差值注册码
- K_qaoqd
- GetDlgItemTextA 双控件
tags:
- reverse
- windows
- crackme
- ollydbg
- keygen
- name-serial
- api-breakpoint
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T05:58:17+08:00'
  notes: 已对照原文全文与图21-29核对：两次GetDlgItemTextA读Name(0x403080)/Serial(0x403280)、lstrlenA后CMP EAX,5长度门槛、LOOPD循环MOV DL,[EAX];SUB DL,CL;CMP [EBX],DL与公式Serial[i]=Name[i]-(NameLen-i)均一致，图29 Reverse→K_qaoqd与PoC输出吻合；与name-4byte卡(cos0.926)公式和Serial语义完全不同，force新增成立；无sources；dup-scan早于建卡；无版本--clear；未复跑样本
---

## 一句话结论

该 CrackMe 用两次 `GetDlgItemTextA` 分别读取 Name 与 Serial，先要求 Name 长度 ≥5，再逐字符校验 `Serial[i] == Name[i] - (NameLen - i)`（即每个字符减去“剩余长度”）；按该公式写注册机即可为任意合法 Name 生成 Serial（样本 Name `Reverse` → Serial `K_qaoqd`）。

## 原理

- **双输入控件**：程序是 `DialogBoxParamA` 对话框程序，Name、Serial 两个编辑框；第一次 `GetDlgItemTextA` 把 Name 读入 `0x00403080`，第二次把 Serial 读入 `0x00403280`。
- **长度门槛**：`lstrlenA(Name)` 后 `CMP EAX,5`，小于 5 弹 `Your name must be at least five characters long!` 并中止；这既是业务约束也是 keygen 的输入条件。
- **逐字符差值校验**：循环初始化 `EAX=Name`、`EBX=Serial`、`ECX=NameLen`，每轮 `MOV DL,[EAX]; SUB DL,CL; CMP [EBX],DL; JNZ fail`，然后 `INC EAX; INC EBX; LOOPD`。`LOOPD` 每轮先把 `ECX` 减 1 再判断，因此第 i 个字符（0 基）比较的是 `Name[i] - (NameLen - i)`。
- **字节语义**：`DL` 是 8 位寄存器，减法按字节取模 256；结果对应可打印 ASCII 时可直接作为 Serial 输入，若某字符结果为不可打印/零字节，则 `GetDlgItemTextA` 无法输入该字节，需要换 Name。
- **成功分支**：全部字符相等后弹 `Yeah, you did it!`；任一处不等即跳出循环走失败分支。

## 触发条件

- 目标为本地 Windows 32 位 GUI 注册校验程序（原文 `AD_CM#2.exe`，ArturDents CrackMe#2，无壳、无强反调试）。
- 校验逻辑在客户端完成，使用 Name/Serial 双输入，无服务端二次校验。
- 可用 OllyDbg 对 `GetDlgItemTextA` 下断并单步跟踪循环。

## 利用步骤

1. 运行程序，确认 Name/Serial 两个输入框与 `Check it, baby!` 按钮；随便输入触发失败。
2. 导入 OllyDbg，`Ctrl+N` 查看导入表，在 `GetDlgItemTextA` 下断；F9 运行，输入 `Reverse/88888888` 点验证。
3. 第一次断下时 `Ctrl+F9` 到返回，查看缓冲区 `0x00403080` 是否为 Name；F8 越过长度检查（`CMP EAX,5`）。
4. 继续运行到第二次 `GetDlgItemTextA`，确认 Serial 缓冲区 `0x00403280`；向下定位循环（`MOV DL,[EAX]; SUB DL,CL; CMP [EBX],DL; JNZ`）。
5. 记录循环初值 `ECX=NameLen` 与 `LOOPD` 的减一语义，得出 `Serial[i]=Name[i]-(NameLen-i)`。
6. 写注册机生成 Serial，输入验证；若目标 Name 产生不可打印字符，改为枚举 Name（如字母/数字组合）直到 Serial 全部可输入。

## PoC

最小 Python 注册机（与原文 C++ 等价）：

```python
name = "Reverse"           # 长度 >= 5
assert len(name) >= 5
serial = "".join(chr((ord(c) - (len(name) - i)) & 0xFF) for i, c in enumerate(name))
print(serial)              # Reverse -> K_qaoqd
```

原文 C++ 核心：`Serial.push_back(Name[i] - (Name.length() - i));`

## 变体与关联

- 变体：差值改为 `+`、异或、按位取反；循环用 `ECX` 计数而非 `LOOPD` 时注意循环边界差一；长度门槛换成 ≥4/≥6。
- 关联：[[code-analysis-reverse-windows-keygenme-name-4byte-serial-keygen]]（Name→4 字节小端 Serial）、[[code-analysis-reverse-windows-crackme-volume-serial-hypotenuse-keygen]]（卷序列号 + Name hash）、[[code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate]]（对话框输入定位）。
- 边界：逐字节减法可能产生不可打印字符；固定 Name 无解时只能换 Name 或补丁比较分支。

## 检测与防御

- **逆向检测（防守方视角）**：客户端 Name/Serial 算法可被完整还原并写注册机；长度门槛与逐字符比较不构成保护。
- **加固**：许可证由服务端签发并对 Name/机器信息签名；客户端仅做签名验证（公钥内置），不要用可逆的逐字符变换。
- **审计线索**：`GetDlgItemTextA` 两次调用 + `lstrlenA` 长度比较 + `LOOPD` 逐字符比较，是典型 Name/Serial 校验结构。
