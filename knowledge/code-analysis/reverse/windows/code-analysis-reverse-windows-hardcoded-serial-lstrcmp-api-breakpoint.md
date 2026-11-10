---
id: code-analysis-reverse-windows-hardcoded-serial-lstrcmp-api-breakpoint
title: 硬编码注册序列号定位：GetWindowTextA/lstrcmpA 断点直接在比较参数中读取明文 Serial
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: hardcoded-serial-api-breakpoint-locate
aliases:
- 硬编码注册
- 硬编码序列号
- GetWindowTextA 断点
- lstrcmpA 断点
- BP WindowsAPI
- cannabis
tags:
- reverse
- windows
- crackme
- ollydbg
- api-breakpoint
- hardcoded-serial
- lstrcmp
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T05:58:15+08:00'
  notes: 已对照原文全文与图01-09核对：图03导入表GetWindowTextA/lstrcmpA/MessageBoxA、图06比较参数处明文cannabis、图09输入cannabis提示Correct!均与卡一致；原理/步骤准确；无sources/source_url；dup-scan(11-08)早于建卡(11-09)无本卡pair；dedup最高非自身候选为related(0.90)非重复；无受影响版本--clear；未复跑样本
---

## 一句话结论

当注册校验把正确序列号明文写在程序里时，在 `GetWindowTextA`（读取输入）与 `lstrcmpA`（字符串比较）下断点，单步到比较调用处即可在栈参数/内存窗口中直接看到内嵌的明文 Serial；原文样本 `crackme.exe` 中比较参数为 `cannabis`，输入后提示 `Correct! You entered the right password!`。

## 原理

- **硬编码注册**：校验代码直接把固定字符串作为比较对象，例如 `lstrcmpA(用户输入, "cannabis")`；序列号不是算法生成，而是作为立即数/只读数据存在于 PE 的 `.rdata` 或栈上。
- **API 是稳定锚点**：GUI 程序一般用 `GetWindowTextA`/`GetDlgItemTextA` 读取输入框，用 `lstrcmpA`/`lstrcmpiA` 或自写逐字符比较校验；这些导入函数在 `Ctrl+N` 名称窗口可见，`BP <API>` 一次即可拦截所有调用。
- **比较参数泄露真值**：`lstrcmpA` 的两个参数分别指向用户输入与内嵌字符串；命中后 `Alt+F9` 执行到返回，再查看栈顶参数或数据窗口即可读到明文。
- **分支后果**：比较结果在 `EAX`（相等为 0），随后 `OR EAX,EAX` / `TEST` 影响 ZF，条件跳转决定成功或失败；也可据此把 `JNZ` 补成 `NOP` 做本地绕过。

## 触发条件

- 目标为本地 Windows 32/64 位 GUI 授权校验程序，客户端完成校验，无壳或易脱壳，未做强反调试。
- 正确序列号为硬编码字符串（不含环境绑定/加密变换）。
- 可使用 OllyDbg/x64dbg 等调试器附加运行，能对导入 API 下断。

## 利用步骤

1. 运行程序，输入任意 Serial 触发错误弹窗，确认校验入口（原文为 `Password` 输入框 + `Check` 按钮）。
2. 将程序导入 OllyDbg，`Ctrl+N`（或右键 → 查找 → 当前模块中的名称）查看导入表，定位 `GetWindowTextA`、`lstrcmpA`、`MessageBoxA`。
3. 在 `GetWindowTextA` 与 `lstrcmpA` 上设置函数断点（快捷键区可直接 `BP MessageBoxA` 等），`F9` 运行并输入任意值点击 Check。
4. 断在 `GetWindowTextA` 后 `Alt+F9` 返回主程序；继续 `F9` 到 `lstrcmpA` 断点，查看栈参数或数据窗口中的第二个字符串指针。
5. 读到明文 Serial（原文为 `cannabis`），输入验证；失败分支对应 `MessageBoxA("Nope!")`，成功分支对应 `Correct!`。
6. 若比较后仍有变换，继续单步确认是直接比较还是先解密/拼接；硬编码场景通常在比较参数处即得真值。

## PoC

原文样本验证：

```text
输入 Serial: cannabis
结果: Correct! You entered the right password!
```

调试器关键观察点：

```asm
; lstrcmpA(用户输入, 内嵌字符串)
0040124F  ...        ; 比较结果非 0 时跳转到 Nope 分支
```

无漏洞利用代码；该场景为本地注册校验逆向定位。

## 变体与关联

- 变体：`lstrcmpiA`（忽略大小写）、`wcscmp`（宽字符）、自写逐字符比较（此时在 `GetWindowTextA` 返回后单步跟循环）；硬编码串也可能先经简单异或/反转。
- 关联：[[code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate]]（对话框输入定位）、[[code-analysis-dynamic-debugging-crackme-password-check-patch]]（改寄存器/ZF 与补丁绕过）、[[code-analysis-dynamic-debugging-serial-data-constraint-memory-proximity]]（内存邻近搜索真序列号）。
- 边界：若校验前对输入做哈希/加密，或正确值由算法生成，则不能直接在比较参数读到明文，需要继续分析变换函数。

## 检测与防御

- **逆向检测（防守方视角）**：硬编码 Serial 无法防止本地逆向；任何出现在客户端的明文密钥都可被调试器/内存搜索读取。
- **加固**：校验放服务端；客户端只保存签名/许可证并由服务端验证；对本地授权做代码混淆、反调试只能提高成本，不能作为安全边界。
- **红队/审计**：对软件授权逻辑优先检查 `lstrcmp*`、`MessageBox` 成功/失败分支与只读数据段中的可疑字符串。
