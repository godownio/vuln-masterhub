---
id: code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell
title: 假验证码投递 HTA 伪装 mp3 的多层脚本脱混淆：JS fromCharCode 数组 → 十六进制 XOR → PowerShell 字符码
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: fake-captcha-hta-js-charcode-powershell-multistage-deobfuscation
tags:
- reverse
- obfuscation
- hta
- javascript
- powershell
- clickfix
- malware-analysis
- windows
- multistage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V246
  verified_at: '2026-11-07T12:58:26+08:00'
  notes: 已对照原文及25张图核对：假 reCAPTCHA 页 execCommand copy、mp3 实为 HTA、fromCharCode 变量表、数组减601、hex XOR 0xCC、PowerShell $r、[CHar] 码点均一致；未验证点：未执行原始样本，仅按静态分层还原。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell/
draft: false
kb_aliases:
- 1'M no7 A rO6oT
- ClickFix
- HTA 伪装 mp3
- fromCharCode 数组
- 0xCC XOR
- PowerShell 字符码拼接
- '[Char] 混淆'
---

## 一句话结论

假“人机验证”页面把一条 PowerShell 命令写入剪贴板诱导用户粘贴执行（ClickFix），命令下载的 `.mp3` 实际是 HTA；HTA 内先隐藏窗口，再用变量名到数字的映射配合 `String.fromCharCode` 拼出 JS 解码器，数组元素减 601 得到十六进制串，逐字节 XOR 0xCC 后还原出 PowerShell 下载器；下一层 PowerShell 用 `$r` 式字符串拼接再把载荷交给 `[CHar]` 码点拼接，逐层静态解码即可取出最终脚本，全程无需执行原始载荷。

## 原理

- **ClickFix 投递**：页面用 JS 构造 `powershell ...` 命令，把 `###HOST###` 占位符替换为当前站点地址，写入隐藏 `textarea` 并调用 `document.execCommand("copy")`；用户看到的是“我不是机器人”验证框，实际剪贴板里是命令。该阶段只负责诱导执行，不是漏洞利用本身。
- **扩展名伪装**：下载的 `*.mp3` 文件头/内容包含 `<HTA:APPLICATION ...>` 与 `<script>`，说明它是 HTA（HTML Application）而非音频；Windows 依据宿主打开方式执行，扩展名不构成安全边界。HTA 里 `window.resizeTo(0,0); window.moveTo(-9999,-9999)` 用于隐藏窗口。
- **JS 变量名编码**：脚本先赋大量短变量 `SK=102;UP=117;...`，再用 `String.fromCharCode(SK,UP,...)` 按变量顺序拼出解码函数源码。变量名本身无语义，只有按赋值取值并按调用顺序拼接才能还原，静态关键字搜索会漏掉。
- **数组减偏移 + 十六进制 XOR**：还原出的函数把一个大整数数组的每个元素减 601 后 `String.fromCharCode`，得到十六进制字符串；再把每两个 hex 字符转字节并 XOR 0xCC，得到 PowerShell 下载命令。单字节 XOR 是对称的，直接再 XOR 0xCC 即还原。
- **PowerShell 下载器**：命令通过 `Net.WebClient`/`Invoke-Command` 等下载下一层 `*.jpg`，而该 jpg 又是 PowerShell 脚本；此层通常还会做隐藏窗口、`-nop`、`-ep` 等参数。
- **`$r` 字符串构造与 `[CHar]` 拼接**：第二层 PowerShell 用大量 `$r = +$()`、字符串拼接和变量替换构造待执行代码；文章把最终执行 `$r` 改为 `Write-Output` 以安全打印。打印出的下一层是 `iex ([CHar]36+[CHar]68+...)`，即用码点拼接隐藏 `iex (...)` 字符串；正则提取所有数字后 `chr()` 还原即可。
- **成立条件**：各层编码都是可逆的静态变换，且不依赖运行环境生成的一次性密钥；每层载荷都能完整下载到本地。若某层使用服务端下发密钥或强加密，则需要额外动态分析。

## 触发条件

- 遇到诱导“复制命令到运行框/PowerShell”的页面（假验证码、假浏览器更新、假错误修复）。
- 下载到扩展名与内容不符的媒体/图片文件，`strings` 可见 `<HTA:APPLICATION`、`<script`、`String.fromCharCode`、`[CHar]` 等特征。
- 样本为 HTA/JS/PowerShell 多层加载器，且分析环境已隔离、不需要执行载荷即可静态还原。

## 利用步骤

1. 在页面按 F12 查看源码，确认 `execCommand("copy")`、命令模板与 `###HOST###` 替换逻辑；记录下载地址但不要执行命令。
2. 下载载荷文件，用 `file`/十六进制/`strings` 检查 magic 与脚本特征，确认扩展名伪装（例如 mp3 中出现 HTA 头）。
3. 提取 HTA 的 `<script>` 内容，按变量赋值表还原 `String.fromCharCode` 参数，得到第一层 JS 解码函数；再按数组偏移（本题减 601）还原十六进制串。
4. 将十六进制串按字节 XOR 固定 key（本题 0xCC），得到下一层 PowerShell 下载命令；下载 jpg/下一层文件。
5. 审阅 PowerShell：把最终执行（`& $r`、`IEX $r`、`Invoke-Expression`）改为 `Write-Output`，或只做语法解析/字符串展开，不执行；在隔离环境中运行以打印下一层。
6. 对 `[CHar]NN+[CHar]MM+...` 形式，用正则提取码点并 `chr()` 拼接；重复“识别层类型 → 静态解码”直到得到明文脚本/配置/flag。
7. 记录每层哈希、下载 URL、脚本特征与最终行为，便于检测规则和 IOC 提取。

## PoC

```python
import re

# 1) JS String.fromCharCode 变量表：按赋值取出数值，按调用顺序拼接
# vals = {"SK": 102, "UP": 117, ...}
# s = "".join(chr(vals[name]) for name in order)

# 2) 数组减偏移 -> 十六进制串
# arr = [713, 712, ...]
# hexstr = "".join(chr(x - 601) for x in arr)

# 3) 十六进制串逐字节 XOR 0xCC -> PowerShell 文本
hexstr = "a5a9b49fb8adbeb8..."  # 从上一层还原出的完整串
plain = bytes(b ^ 0xCC for b in bytes.fromhex(hexstr)).decode("utf-8", "replace")

# 4) PowerShell [CHar] 码点拼接还原
text = 'iex ([CHar]36+[CHar]68+[CHar]101+[CHar]98+[CHar]117+[CHar]103)'
nums = re.findall(r"\[CHar\]\s*(\d+)", text, flags=re.I)
print("".join(chr(int(n)) for n in nums))

# 5) 对 $r 式拼接：只收集字符串常量/替换规则，最后改 Write-Output 打印，不执行
```

说明：文章中的大数组与 PowerShell 脚本较长，PoC 只保留各层等价的最小解码步骤；实际分析时用样本中的完整数组替换占位符，且不要运行原始脚本。

## 变体与关联

- 投递变体：假验证码、假更新、假“修复错误”页面；命令可指向 `mshta.exe https://...` 远程 HTA，也可先 `powershell` 下载本地 HTA，见 [[pentest-initial-access-fake-captcha-mshta-remote-hta]]（同一 ClickFix 投递 sink，本卡聚焦载荷多层脱混淆而非投递与持久化）。
- 载体变体：HTA 可伪装成 `.mp3`、`.jpg`、`.txt` 等；判断依据是内容中的 `<HTA:APPLICATION`、`<script language=...>`，不是扩展名。
- JS 变体：`String.fromCharCode`、`atob`、`eval`、十六进制/Base64 嵌套；可用正则做常量折叠，再人工语义重构。
- PowerShell 变体：`[CHar]` 码点拼接、整数数组减偏移、`-EncodedCommand`、`ScriptBlock.Create`、字符串替换表；分别见 [[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]、[[code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation]]。
- 关联：[[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]（VBE→PowerShell→.NET 多层样本分析流程）。
- 边界：若某层在运行时才生成密钥/异或值，静态解码会失败，需要沙箱动态转储；不要在真实主机执行样本。

## 检测与防御

- 用户侧：人机验证/浏览器更新不会要求复制并运行命令；看到“按 Win+R 粘贴”之类提示应立即停止。
- 主机侧：监控 `powershell.exe`/`mshta.exe` 由浏览器或 `explorer.exe` 拉起、带 `-nop -w hidden -ep` 等参数；监控下载 `.mp3`/`.jpg` 后紧接着脚本宿主读取该文件的行为。
- 文件侧：检测扩展名与内容不一致（音频/图片中出现 HTA/HTML/脚本头）；对 `String.fromCharCode` 大数组、`[CHar]` 长串、`document.execCommand("copy")` 页面做规则告警。
- 分析侧：在隔离虚拟机/纯静态环境中逐层解码，把执行改为输出；保留每层文件哈希与下载地址作为 IOC。
