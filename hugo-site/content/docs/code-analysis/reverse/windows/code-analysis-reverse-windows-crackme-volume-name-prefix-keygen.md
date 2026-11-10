---
id: code-analysis-reverse-windows-crackme-volume-name-prefix-keygen
title: 卷标绑定注册码：GetVolumeInformationA 取卷名 + 4562-ABEX/L2C-5781 前后缀，前 4 字符两轮各 +1 生成 Serial
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: volume-name-prefix-suffix-keygen
tags:
- reverse
- windows
- crackme
- ollydbg
- keygen
- volume-serial
- api-breakpoint
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372-fix
  verified_at: '2026-11-09T06:29:29+08:00'
  notes: V372 核对指出示例串转录错误：图20 实际为 L2C-5781U{uvem4562-ABEX（卷标 System 前 4 字符 Syst 各 +2 = U{uv，其余 em 不变），原卡写作 U{uem/U{ue 漏字符 v。已修正一句话结论、原理与 PoC 注释为 U{uvem；标题与原理小标题改为『两轮各 +1（等价 +2）』避免误读。算法与 force 理由不变。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-crackme-volume-name-prefix-keygen/
draft: false
kb_aliases:
- 卷标注册码
- GetVolumeInformationA 注册码
- abexcm5
- 4562-ABEX
- L2C-5781
- 卷名绑定注册机
---

## 一句话结论

该 CrackMe 用 `GetVolumeInformationA` 读取当前卷的卷标（如 `System`），拼接 `4562-ABEX` 后把前 4 个字符各加 1 两次，再拼到 `L2C-5781` 之后作为合法 Serial（样本生成 `L2C-5781U{uvem4562-ABEX`），最后用 `lstrcmpA` 与用户输入比较；注册机必须在目标机同一目录运行以读到相同卷标。

## 原理

- **卷标作为环境绑定值**：`GetVolumeInformationA(NULL, VolumeNameBuffer, 0x32, &VolumeSerialNumber, ...)` 返回当前工作目录所在卷的卷标（volume label）与卷序列号。程序取卷标参与序列号计算，使序列号绑定当前机器/分区，换盘后失效。
- **固定前后缀**：程序先 `lstrcatA(VolumeNameBuffer, "4562-ABEX")`，把固定串追加到卷标后面；最终 Serial 以 `"L2C-5781"` 开头，再接变换后的 `VolumeNameBuffer`。
- **前 4 字符两轮各 +1（等价 +2）**：对 `VolumeNameBuffer[0..3]` 连续执行两轮 `+= 1`（等价每个字符 +2），后续字符不变。样本卷标 `System` → 前四字符 `Syst` → `U{uv`，拼接后为 `U{uvem4562-ABEX`。
- **比较**：`GetDlgItemTextA` 读入用户 Serial，`lstrcmpA(计算值, 输入)`；相等走 `Well Done! Yep, you entered a correct serial!`，不等走 `The serial you entered is not correct!`。
- **环境一致性**：卷标随分区/系统安装变化，注册机需读取目标机同一卷的卷标；原文提示注册机要与注册程序放在同一目录，确保 `GetVolumeInformationA(NULL, ...)` 解析到同一卷。

## 触发条件

- 目标为 Windows 32 位 GUI 注册校验程序（原文 `abexcm5.exe`，TASM/MASM，无壳）。
- 校验算法在客户端完成，使用 `GetVolumeInformationA` 取卷标/卷序列号，无强反调试。
- 可用 OllyDbg 对 `GetDlgItemTextA`/`GetVolumeInformationA`/`lstrcatA`/`lstrcmpA` 下断并读取参数与缓冲区。

## 利用步骤

1. 运行 `abexcm5.exe`，输入任意 Serial 点 Check，确认错误提示；用 Exeinfo PE 确认 32 位、汇编、无壳、GUI。
2. 导入 OllyDbg，`Ctrl+N` 查看导入，`GetDlgItemTextA` 下断；F9 运行并输入 Serial，命中后 `Alt+F9` 返回主程序（EIP 约 0x0040107D）。
3. 向下单步：`GetVolumeInformationA(NULL, VolumeNameBuffer, 0x32, ...)` 读取卷标；`lstrcatA(VolumeNameBuffer, "4562-ABEX")`；观察两轮 `VolumeNameBuffer[0..3] += 1`；`lstrcatA(Serial, "L2C-5781")` 后再拼接变换后的缓冲区。
4. 记录固定串与变换规则，确认最终 `lstrcmpA` 比较的参数。
5. 写注册机：读取当前卷标 → 追加 `4562-ABEX` → 前 4 字符 +1 两次 → 前缀 `L2C-5781`；把 keygen 放到目标程序同目录运行，输入生成值验证。
6. 若卷标为空或读取失败，按实际返回值/错误码调整（`GetVolumeInformationA` 失败时缓冲区可能保持空串）。

## PoC

按原文算法复写的最小 C++（需与目标程序同目录运行）：

```cpp
#include <windows.h>
#include <iostream>
int main() {
    char vol[0x32] = {0}; DWORD vsn=0, maxlen=0, flags=0;
    if (!GetVolumeInformationA(NULL, vol, sizeof(vol), &vsn, &maxlen, &flags, NULL, NULL)) return 1;
    char serial[MAX_PATH] = "L2C-5781";
    char tail[MAX_PATH] = "4562-ABEX";
    lstrcatA(vol, tail);
    for (int i = 0; i < 2; ++i) { vol[0]++; vol[1]++; vol[2]++; vol[3]++; }
    lstrcatA(serial, vol);
    std::cout << serial << std::endl; // 样本卷标 System -> L2C-5781U{uvem4562-ABEX
    return 0;
}
```

## 变体与关联

- 变体：用卷序列号（DWORD）而非卷标、读取 C:/D: 多卷、对卷标做哈希/查表；前后缀与增量步数都可替换。
- 关联：[[code-analysis-reverse-windows-crackme-volume-serial-hypotenuse-keygen]]（另一个 GetVolumeInformationA 卷序列号绑定样本）、[[code-analysis-reverse-windows-keygenme-name-4byte-serial-keygen]]（Name→Serial keygen）、[[code-analysis-reverse-windows-winhex-license-crc32-keygen]]（许可证算法逆向）。
- 边界：卷标可由用户修改，绑定强度低于卷序列号；若校验前还对 Serial 做额外哈希，需继续跟踪。

## 检测与防御

- **逆向检测（防守方视角）**：客户端卷标绑定只能提高复制成本，无法阻止同机 keygen；卷标本身用户可改。
- **加固**：把注册校验移到服务端，或在许可证中签名绑定机器指纹（多因素、服务端可验证），不要仅依赖客户端比较。
- **审计线索**：导入表出现 `GetVolumeInformationA` + `lstrcatA` + `lstrcmpA` 组合时，优先检查卷标/卷序列号参与注册码的算法。
