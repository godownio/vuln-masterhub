---
id: code-analysis-reverse-windows-dotnet-batch-ilspycmd-config-regex-extract
title: 批量 .NET 载荷配置抽取：ilspycmd 命令行批量反编译 + 正则抓 URL 与 PcHwid→StartupRegName 配置块，汇总 SMTP/FTP 凭据
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dotnet-batch-ilspycmd-config-regex-extraction
aliases:
- ilspycmd 批量反编译
- .NET 样本配置自动提取
- AgentTesla 配置正则
- PcHwid StartupRegName
- SMTP FTP 凭据批量提取
- 半自动化样本剖析
- 反编译配置字段
tags:
- reverse
- windows
- dotnet
- ilspy
- batch-analysis
- config-extraction
- malware-analysis
- smtp
- ftp
- regex
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T12:08:27+08:00'
  notes: 已对照原文与 img07-10/15-17 核对：ilspycmd 与 .NET SDK 6.0 安装、批量反编译 .decompiled.cs、URL 正则、PcHwid→StartupRegName 配置块正则与清洗步骤、SMTP/FTP 字段与最终凭据输出均一致；原文未对真实样本实跑脚本（文章有输出截图），卡内 Python 为按文章逻辑重写
---

## 一句话结论

对大批同族 .NET 木马载荷，先用 `ilspycmd` 命令行把每个程序集批量反编译成 `.decompiled.cs`，再用正则从源码中抓 `http(s)://` URL 与 `public static string PcHwid ... public static string StartupRegName` 之间的配置字段，即可不逐样本手工调试地批量导出 C2/下载地址、SMTP/FTP 服务器与账号口令等配置，实现半自动化 triage。

## 原理

- **为什么用命令行反编译**：同族 .NET 样本的配置字段通常以 `public static string/bool/int` 字面量形式编译进程序集；dnSpy 图形化操作无法批量，而 ILSpy 的命令行版本 `ilspycmd` 可对目录内每个样本执行 `ilspycmd -o ./output <assembly>`，输出 `<assembly>.decompiled.cs`，便于脚本遍历与正则匹配。
- **为什么配置结构可正则化**：AgentTesla 一类样本的配置类字段顺序/名称高度稳定，典型字段包括 `PcHwid`、`ThisComputerName`、`AsmFilePath`、`PublicIpAddress`、`PublicIpAddressGrab`、`IpApi`、`PublicUserAgent`、`PcState`、`Log_text`、`EnableKeylogger`、`EnableScreenLogger`、`EnableClipboardLogger`、`EnableTorPanel`、`EnableCookies`、`EnableContacts`、`DeleteBackspace`、`TorPid`、`KeyloggerInterval`、`ScreenInterval`、`LogType`、`FtpHost/FtpUser/FtpPassword`、`SmtpServer/SmtpPort/SmtpSender/SmtpPassword/SmtpReceiver`、`Downloader`、`AppAddStartup`、`HideFileStartup`、`StartupRegName` 等。用“从 `PcHwid` 到 `StartupRegName`”的跨行非贪婪匹配即可整块截取，再逐行去掉 `public static xxx`、`Convert.ToBoolean(`、`Convert.ToInt32(`、分号等包装，得到 `字段 = 值` 的清单。
- **为什么 URL 正则可补充情报**：配置块之外还可能有硬编码的下载/回连 URL（如 `http://host/wp-content/uploads/*.exe`、`https://api.ipify.org`、`http://ip-api.com/line/?fields=hosting` 等），独立的 `(http://|https://)\S+` 正则可以全部抓出，并用引号截断清理。二者结合可同时拿到“窃取方式（SMTP/FTP/Web Panel）”与“下载地址/公网 IP 查询服务”。
- **为什么不走十六进制特征**：直接对二进制搜 16 进制字符串只能拿到值，无法对应变量名（配置顺序/字段含义丢失）；反编译后的 C# 保留了字段名与布尔/整数语义，适合批量归类与横向对比。
- **环境要求**：`ilspycmd` 依赖 .NET SDK（文章使用 .NET SDK 6.0，安装 `dotnet-sdk-6.0.423-win-x64.exe` 后 `dotnet tool install --global ilspycmd`）；版本不匹配会报错。批量脚本可用 Go/Python/任意语言调用命令行，按 `.decompiled.cs` 是否已存在做缓存，避免重复反编译。

## 触发条件

- 已获取一批同族 .NET 载荷（例如从进程替换内存中还原出的最终 PE），且载荷未被强混淆到配置字段不可读（字符串明文或仅轻量混淆）。
- 本机可安装 .NET SDK 与 `ilspycmd`（或已有等价的命令行反编译工具），能对样本目录批量执行。
- 配置字段命名/顺序在同族样本中基本一致，可用固定起止锚点（如 `PcHwid` 与 `StartupRegName`）做区间匹配；变体若改了字段名，需要调整正则或改为按字段名列表扫描。
- 仅用于授权的恶意样本分析；脚本不运行样本，只处理反编译文本。

## 利用步骤

1. 准备载荷目录（如从 WriteProcessMemory 断点+内存雕刻得到的 PE 文件），确认均为 .NET 程序集（PEview/DIE 显示 .NET Assembly；`ilspycmd` 可处理）。
2. 安装 .NET SDK 6.0，执行 `dotnet tool install --global ilspycmd`，用 `ilspycmd --help` 验证；工具默认位于 `%USERPROFILE%\.dotnet\tools\ilspycmd.exe`。
3. 遍历目录：对每个样本执行 `ilspycmd -o ./output <sample>`，生成 `<sample>.decompiled.cs`；若输出已存在则跳过，形成缓存。
4. 对每个 `.decompiled.cs` 跑 URL 正则 `(http://|https://)[^\s]+`，去掉引号后的残余，输出所有 URL。
5. 跑配置区间正则 `(?s)public\s+static\s+string\s+PcHwid(.*?)public\s+static\s+string\s+StartupRegName`，对匹配文本去掉修饰符与 `Convert.ToBoolean/ToInt32(`、`)`、`;`、制表符，输出字段清单；再单独匹配 `StartupRegName` 行补上最后一项。
6. 人工/脚本汇总：按样本输出 `FtpHost/FtpUser/FtpPassword`、`SmtpServer/SmtpPort/SmtpSender/SmtpPassword/SmtpReceiver`、下载 URL 等，形成凭据与 IOC 列表；对字段缺失/格式异常的样本回退到 dnSpy 手工确认。

## PoC

无漏洞利用 PoC；以下为按文章流程重写的 Python 批量抽取脚本（未对真实样本实跑）。

```python
import re, subprocess, sys
from pathlib import Path

SAMPLE_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("samples")
OUT_DIR = Path("output"); OUT_DIR.mkdir(exist_ok=True)

CFG_RE = re.compile(r"(?s)public\s+static\s+string\s+PcHwid(.*?)public\s+static\s+string\s+StartupRegName")
URL_RE = re.compile(r"(?:http://|https://)[^\s]+")
START_RE = re.compile(r"public\s+static\s+string\s+StartupRegName.*")

def clean(block: str) -> str:
    for pat in ("\t", "public static string ", "public static bool ",
                "public static int ", "Convert.ToBoolean(", "Convert.ToInt32(",
                ");", ";"):
        block = block.replace(pat, "")
    return re.sub(r"\r?\n\s*\r?\n", "\n", block)

for sample in SAMPLE_DIR.rglob("*"):
    if sample.suffix.lower() not in (".exe", ".dll"):
        continue
    cs = OUT_DIR / (sample.stem + ".decompiled.cs")
    if not cs.exists():
        subprocess.run(["ilspycmd", "-o", str(OUT_DIR), str(sample)],
                       capture_output=True, text=True)
    if not cs.exists():
        print(f"[!] decompile failed: {sample}"); continue

    text = cs.read_text(errors="ignore")
    print(f"********** {sample.name} URL **********")
    for u in URL_RE.findall(text):
        print(u.split('"')[0])

    print(f"********** {sample.name} Config **********")
    m = CFG_RE.search(text)
    if m:
        print(clean(m.group(0).split("StartupRegName")[0]))
    else:
        print("未找到 PcHwid→StartupRegName 配置块")
    m2 = START_RE.search(text)
    if m2:
        print(m2.group(0).replace("public static string ", "").replace(";\r", "").replace(";", ""))
```

## 变体与关联

- 变体：字段名/顺序被改时，正则锚点失效；可改为“按 `public static (string|bool|int)` 全量抓取字段”，再用字段名白名单筛选；或对每个字段单独 `field\s*=\s*"([^"]*)"` 匹配。
- 变体：字符串被混淆（如 Obfuscar/XORStringsNet）时，先做字符串自动解密（dnlib/dnfile 还原），再反编译或直接对解密后的程序集跑本流程。
- 变体：样本为非 .NET（C++/Go/Delphi）时，ilspycmd 不适用，需要改用 IDA/Ghidra 或专用配置提取工具。
- 关联：[[code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve]]（前置步骤：从内存提取最终 .NET 载荷）、[[code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract]]（单样本配置解密）、[[code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt]]（配置字符串被混淆时的还原）、[[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]（XORStringsNet 字符串解密）。

## 检测与防御

- 检测：防御方可对邮件/网络侧 SMTP/FTP 登录与上传行为做异常检测（非业务主机连接外部 SMTP/FTP、批量信件），并结合进程内存中出现 .NET 程序集与配置字段；样本侧可检测 `ilspycmd`/dnSpy 等分析工具运行环境（但本流程离线，运行期不可见）。
- 防御：恶意样本作者可加密配置字符串、拆分字段、运行时从网络拉取配置以对抗静态抽取；防御方则需结合动态行为（网络连接、注册表启动项、键盘记录文件）交叉验证。
- 说明：本文是恶意样本批量分析/配置提取技术，severity 记为 low；仅用于授权分析和应急响应。
