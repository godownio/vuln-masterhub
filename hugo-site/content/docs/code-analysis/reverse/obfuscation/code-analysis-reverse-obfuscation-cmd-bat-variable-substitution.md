---
id: code-analysis-reverse-obfuscation-cmd-bat-variable-substitution
title: BAT/CMD 变量替换混淆还原：set 单字符片段 + EnableDelayedExpansion 运行时拼命令，静态搜不到关键字
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: cmd-bat-variable-substitution-deobfuscation
tags:
- reverse
- obfuscation
- bat
- cmd
- batch
- variable-substitution
- delayed-expansion
- malware-analysis
- windows
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:16:43+08:00'
  notes: 已对照原文与图4核对：set 短变量=单字符片段、setlocal EnableDelayedExpansion、运行时变量替换拼命令的描述与样本片段一致（dQ=u/UA=P/bg=n/Ug=R/TQ=M/Og=:/Uw=S/eA=x/Jw='/aA=h）；卡内还原脚本为通用方法、样例映射标注为开头片段。未验证点：原文/截图未给出完整的!变量!拼接使用行与全量set映射，'替换后还原出start chrome/powershell'为基于机制的推断，未执行样本验证；优先级建议以运行时cmd命令行取证为准（卡内已写明）。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-cmd-bat-variable-substitution/
draft: false
kb_aliases:
- 批处理变量替换混淆
- BAT set 变量拼接
- EnableDelayedExpansion 混淆
- vn.cmd 反混淆
- CMD 延迟扩展还原
- 批处理单字符变量
---

## 一句话结论

恶意 BAT/CMD 把 `powershell`、`Invoke-WebRequest`、URL、路径等命令拆成单字符/短片段，用成组的 `set <变量>=<片段>` 保存，再在 `setlocal EnableDelayedExpansion` 之后用 `!变量!` 在运行时拼回完整命令，使静态字符串搜索看不到任何关键字；还原只需提取全部 `set` 映射、对 `!NAME!` 反复做符号替换到不动点（或沙箱里用 `echo on` 捕获展开结果），最终命令里的下载地址、落盘路径和执行动作都会重新显形。

## 原理

- **两种变量展开时机不同**：`%VAR%` 在批处理“读取一行并解析”时展开一次；`!VAR!` 在启用延迟扩展（`setlocal EnableDelayedExpansion`）后于“执行该行”时展开。样本正是利用后者把碎片拼接推迟到运行时：`!dQ!!UA!!bg!...` 之类的表达式在执行前一刻才变成完整单词。
- **字符级切分**：变量值不一定是单词，常见单字符甚至符号，例如 `set dQ=u`、`set UA=P`、`set Og=:`、`set Jw='`——`:`、引号被单独存成变量，用于拼 `://` 或引号包裹的参数。说明混淆器按字符而非按语法切分，人工阅读时无法从片段猜出完整命令。
- **为什么能躲静态检测**：批处理是纯文本，检测规则通常匹配 `powershell`、`Invoke-WebRequest`、`http`、`.zip`、`Startup` 等连续字符串；变量拼接后这些字符串在文件中不存在，只有一堆无意义的 `set` 和 `!...!` 引用。执行时命令仍然是明文，因此行为不受影响。
- **作用域与顺序**：`setlocal` 之后的 `set` 在 `endlocal` 时失效；同名变量后赋值覆盖前值；如果 `set` 在 `setlocal EnableDelayedExpansion` 之前也没关系，变量本身仍在当前环境。还原时必须按文件顺序处理赋值，不能当成无序字典简单合并（除非确认无重复赋值）。
- **还原的确定性**：延迟扩展是确定性的文本替换，只要 `set` 映射完整，反复替换 `!NAME!` 到不再变化即可得到最终命令；若遇到 `%NAME%`（解析期展开）、`%%i` 循环变量、`%1` 参数、`call`/`cmd /c` 二次解析，需要按执行顺序模拟或直接在隔离环境用 `echo on`/替换 `@echo off` 观察展开结果。
- **最可靠的证据来源**：无论脚本怎么混淆，真正执行时进程命令行（`cmd.exe /c ...powershell.exe -windowstyle hidden ...`）和子进程参数都是明文；EDR/4688 命令行审计、沙箱行为日志比静态反混淆更可靠。

## 触发条件

- 拿到可疑 `.bat`/`.cmd` 文件，开头出现大量 `set` 语句且变量名很短（单字母/无意义串）、值多为单字符或片段；
- 文件后半段大量使用 `!变量!` 形式，且直接搜索 `powershell`、`http`、`curl`、`.exe` 等关键字几乎命中不到完整命令；
- 需要还原下载地址、落盘路径、持久化位置等 IOC，或判断脚本真实行为。

## 利用步骤

1. 通读脚本，标注 `setlocal`/`endlocal` 范围与 `EnableDelayedExpansion` 开关位置，按行序收集 `set NAME=VALUE`（注意重复赋值）。
2. 对每一行做迭代替换：先把 `!NAME!` 替换为对应值，重复直到该行不再变化；再处理 `%NAME%`（解析期展开）并按行序更新环境。
3. 遇到变量值互相引用时同样迭代；遇到 `%%i`、`%1`、`call set` 等动态构造时，改为在隔离环境（VM/沙箱）把 `@echo off` 改成 `echo on`，或用 `cmd /c` 运行并捕获展开后的命令行。
4. 检查还原结果：下载 URL、`Invoke-WebRequest`/`curl` 参数、落盘目录、Startup/注册表写入、后续执行的脚本名。
5. 把还原出的命令与进程审计日志（4688 命令行、EDR 遥测）交叉验证；记录为 IOC 后再处置样本。

## PoC

```python
import re

txt = open("vn.cmd", encoding="utf-8", errors="ignore").read()

# 1) 按行序收集 set 映射（演示：简单覆盖式，重复赋值取最后一次）
env = {}
for line in txt.splitlines():
    m = re.match(r"(?i)^\s*set\s+([A-Za-z0-9_]+)=(.*)$", line)
    if m:
        env[m.group(1)] = m.group(2)

# 2) 对含 !VAR! 的行迭代替换到不动点
def expand(line):
    prev = None
    while prev != line:
        prev = line
        line = re.sub(r"!([A-Za-z0-9_]+)!", lambda m: env.get(m.group(1), m.group(0)), line)
    return line

for line in txt.splitlines():
    if "!" in line and not line.strip().lower().startswith("set "):
        print(expand(line))
```

原文样本的映射开头形如：`set dQ=u`、`set UA=P`、`set bg=n`、`set Ug=R`、`set TQ=M`、`setlocal EnableDelayedExpansion`、`set Og=:`、`set Uw=S`、`set eA=x`、`set Jw='`、`set aA=h`；替换后即可还原出 `start chrome https://www.alibaba.com/`、`powershell -windowstyle hidden Invoke-WebRequest ...`、`Expand-Archive`、便携 `python ...project.py` 等命令。以上脚本为通用还原思路，未对原文样本执行。

## 变体与关联

- 变体：只用 `%VAR%`（无延迟扩展）的拼接——直接在解析期替换，逐行模拟即可；`for` 循环 + `call set` 动态生成变量名时，需要实际执行或模拟循环。
- 变体：变量值里再嵌套 `%OTHER%`/`!OTHER!`，迭代到不动点即可收敛；注意 `%%` 在批处理中表示转义的 `%`。
- 关联：[[code-analysis-reverse-obfuscation-powershell-braced-variable-format-reorder]]——PowerShell 侧的花括号变量/格式串重排混淆；[[pentest-c2-batcloak-batch-x509-crl-payload-loader]]——批处理加壳/自解码加载器，与本卡同属批处理滥用但手法不同。
- 关联：[[defense-forensics-python-infostealer-messaging-bat-telegram-browser]]——使用本混淆手法的完整投递链与窃密行为。
- 边界：混淆只影响阅读，不影响执行；最可靠还原点是运行时的进程命令行。若脚本使用多层 `cmd /c` 或编码后的 `powershell -EncodedCommand`，需继续按层解码。

## 检测与防御

- 检测（静态）：BAT/CMD 中 `set` 语句密度异常高、变量名极短、值多为单字符，且伴随 `setlocal EnableDelayedExpansion` 与 `!...!` 拼接；直接关键字搜索缺失但存在网络/落盘相关片段。
- 检测（动态）：`cmd.exe` 子进程拉起 `powershell.exe`/`curl.exe`/`certutil.exe` 且命令行含隐藏窗口、下载、解压、Startup 路径；脚本从 `%TEMP%`、压缩包解压目录或 `C:\Users\Public` 执行。
- 防御：开启命令行审计（4688 含命令行）与 PowerShell 脚本块日志；EDR 对“压缩软件/浏览器→cmd→powershell/curl”的进程链打分；限制普通用户目录执行脚本与写 Startup。
- 加固：企业侧对 `.bat`/`.cmd` 邮件附件与压缩包内脚本做内容检测与沙箱；对高密度 `set`+延迟扩展的批处理做启发式告警（仅作辅助，误报较高）。
