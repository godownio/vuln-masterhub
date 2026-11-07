---
id: code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation
title: 银狐样本轻量字符串混淆：@ 隔字符插入、栈上字符串与 API 包装还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: silverfox-light-string-api-obfuscation
aliases:
- 间隔插入 @ 字符的字符串混淆
- 间隔插入 @ 字符串
- 栈上字符串
- API 包装函数
- 银狐样本字符串还原
- malware string deobfuscation
tags:
- malware-analysis
- silverfox
- obfuscation
- strings
- stack-strings
- api-wrapper
- ida
- windows
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V96
  verified_at: '2026-11-05T19:59:35+08:00'
  notes: 已对照原文与16张图片核对；@隔字符、栈上逐字符字符串、Sleep wrapper、样本/诱饵背景均相符；卡片开头“两类轻量混淆”与正文列出的三类（@、栈上字符串、API包装）表述不一致，属轻微文字问题，不影响技术内容。
---

## 一句话结论

银狐（SilverFox）名单类样本中常见两类轻量混淆：一是把真实字符串每隔一个字符插入 `@`，二是不把字符串放进全局数据而是拆成栈上的逐字符赋值，并把敏感 API 包一层无意义 wrapper；这三类模式逻辑简单、可静态快速还原，识别后能直接恢复样本的字符串比较、服务名和 API 调用意图。

## 原理

- **@ 隔字符插入**：样本把真实字符串 `bdservichost.exe` 写成 `b@d@s@e@r@v@i@c@e@h@o@s@t@.@e@x@e`，再通过一个解密/比较函数（原文示例为 `sub_53E090(&buf, L"b@d@s...")` 后接 `sub_410290`/`sub_53E000`）在运行时去掉 `@`。静态字符串扫描只能看到带 `@` 的形态，按“删掉所有 `@`”即可还原。
- **栈上字符串**：不写入 `.rdata` 全局字符串，而是在循环/函数里逐个字符赋值，例如 `v20[0]='b'; v20[1]='d'; ...; v20[16]='e'; v20[17]=0;`，随后把 `v20` 传给比较或 API 调用。这样字符串不会出现在全局字符串表中，基于全局字符串的 YARA/strings 规则会漏检。
- **API 包装**：真正调用 `Sleep` 的代码被替换成 `call sub_10001F2F0`，而 wrapper 内部只有 `Sleep(a1)`；编译器/混淆器可为每个敏感 API 生成类似的单参数或固定参数 wrapper，使 IAT 交叉引用和 API 名称不再直接出现在调用点。
- 这三类混淆的共同点是“运行时才恢复明文/才暴露 API”，但恢复逻辑本身很浅：没有复杂加密、没有控制流平坦化，也没有依赖环境状态；因此适合先静态还原，再进入强混淆函数分析。
- 识别顺序建议：先看带周期性 `@` 的字符串和其消费者；再看循环中的逐字节赋值/宽字符赋值；最后沿 `call sub_xxx` 的单层 wrapper 找真实 API。三层可以叠加，例如栈上字符串再经 wrapper 比较。

## 触发条件

- 样本为 Windows PE（银狐常见诱饵为“裁员名单/补偿方案”WPS/PDF/RAR/EXE），字符串可能在 ANSI 或宽字符（`L"..."`）中。
- 轻量混淆与其他强混淆可能同时存在于同一样本；本方法只覆盖字符串/API 层，不解决 VM 调用混淆。
- 需要 IDA/Ghidra 等静态工具和基本反编译；栈上字符串可能被编译器优化成多次 `mov byte ptr [rbp+..], imm` 或合并为常量写入，需要按实际汇编处理。
- API wrapper 可能被内联或进一步混淆；如果 wrapper 内还调用其他 wrapper，需要递归跟一层。

## 利用步骤

1. 在 IDA 字符串窗口搜索含多个 `@` 的字符串，统计 `@` 是否约每两个字符出现一次；对候选字符串去掉全部 `@`，观察是否形成可读的文件名、服务名、URL、注册表路径或 API 名。
2. 查看这些字符串的交叉引用：常见消费者是 `sub_53E090`/`sub_410290`/比较函数；确认解密逻辑只是删 `@` 后，可批量重命名或在注释中写入明文。
3. 对栈上字符串，定位函数内连续的逐字符赋值（伪代码 `v20[0]='b'` 或汇编 `mov byte ptr [rbp+var], imm`），按索引拼接；若字符是宽字符，注意每字符 2 字节和 `mov word ptr`。
4. 对调用点 `call sub_xxx` 且 `sub_xxx` 只有一行转发的 wrapper，进入 wrapper 看真实 API（如 `Sleep`、`CreateFileW`、`WinExec`），建立 `wrapper → API` 映射并批量重命名。
5. 将还原后的字符串和 API 调用放回上层逻辑，判断样本在做什么（例如比较主机名/服务名、创建互斥体、加载配置、发起网络请求）；对仍是强混淆的函数转入 VM 调用还原流程（见关联卡片）。
6. 动态验证：在调试器中运行到解密/赋值之后，直接从栈/内存 dump 字符串，与静态结果比对；注意样本可能检测调试器，先处理反调试。

## PoC

```python
# IDAPython：批量提取并还原 @ 隔字符字符串（IDA 7.x/8.x）
import idautils

for s in idautils.Strings():
    raw = str(s)
    if '@' not in raw:
        continue
    # 典型形态：@ 数量约为长度的一半，且去掉后无残留 @
    if raw.count('@') * 2 >= len(raw) - 1:
        plain = raw.replace('@', '')
        print("0x%x  %r  ->  %r" % (s.ea, raw, plain))
```

```c
// 原文中的轻量 API 包装示例：调用点看不到 Sleep，只有 wrapper
void __fastcall sub_10001F2F0(DWORD a1)
{
    Sleep(a1);          // wrapper 内部才是真实 API
}
// 调用点：sub_10001F2F0(1000LL);  // 实际执行 Sleep(1000)
```

```c
// 栈上字符串示例（原文还原形态）
v20[0] = 'b'; v20[1] = 'd'; v20[2] = 's'; v20[3] = 'e';
v20[4] = 'n'; v20[5] = 'v'; v20[6] = 'i'; v20[7] = 'c';
v20[8] = 'e'; v20[9] = 'h'; v20[10] = 'o'; v20[11] = 's';
v20[12] = 't'; v20[13] = '.'; v20[14] = 'e'; v20[15] = 'x';
v20[16] = 'e'; v20[17] = 0;
if (!sub_100031230(v30, v20)) break;   // 后续比较/使用
```

## 变体与关联

- **变体：多字符分隔符/异或后再插 `@`**：先对字符串做单字节 XOR 或加减，再插 `@`；需要先识别解密循环，再按分隔符还原。
- **变体：栈上字符串用算术构造**：不直接写 `'b'`，而是写 `0x62`、`'b' ^ key` 或通过 `sprintf`/`memcpy` 拼接；需要模拟表达式或动态 dump。
- **变体：API wrapper 多层/参数变换**：wrapper 可能调整参数顺序、填充默认参数或调用 `GetProcAddress` 动态解析；沿调用链递归还原。
- **关联卡片**：[[code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore]]（同一样本的强 VM 调用混淆还原）、[[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]（另一类字符串/整数数组混淆）、[[code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream]]（指令重叠反汇编对抗）。
- **边界**：仅靠 strings/YARA 会漏掉栈上字符串；若样本在运行时才从网络下载字符串或使用强加密，本方法只能恢复静态可见部分。

## 检测与防御

- **检测**：对 PE 做多策略扫描——全局字符串、`.rdata` 原始字节、反编译伪代码中的逐字符赋值、调用图上的单行 wrapper；对“周期性 `@`”字符串建立 YARA 规则，并对去 `@` 后的明文做二次匹配（如服务名、浏览器路径、C2 域名）。
- **行为检测**：银狐样本常伴随诱饵文档、`SeDebugPrivilege` 提权、远程进程写入、线程池执行 shellcode、在 `C:\Program Files (x86)\Internet Explorer` 释放白加黑文件；结合这些行为而非仅靠字符串判定。
- **加固**：终端启用 AMSI/ETW 与内存扫描，定期扫描进程解密后的字符串；对 Office/WPS 宏、压缩包内可执行文件做隔离；限制普通用户对浏览器安装目录的写入。
- **分析侧**：静态还原后用调试器在解密点下断并 dump，交叉验证；不要直接运行样本，所有字符串/代码均视为不可信数据。
