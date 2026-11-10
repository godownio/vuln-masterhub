---
id: code-analysis-reverse-windows-badnews-rat-double-base64-aes-heartbeat
title: BADNEWS 远控木马 2024-07 样本逆向：双重 Base64+AES-CBC-128 通信、随机化心跳与指令集
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: badnews-rat-double-base64-aes-heartbeat-command-analysis
tags:
- windows
- malware-analysis
- reverse-engineering
- rat
- badnews
- patchwork
- apt
- c2
- aes
- base64
- heartbeat
- info-gathering
cve: []
severity: high
confidence: high
affected_versions: BADNEWS 2024-07 变种（样本 MD5 C58A7C4BAFFA401C71A1A333ECD0F956，692 KB 64 位 update.exe；原文与 2023-05 版本对比）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T01:07:55+08:00'
  notes: '已完整 Read content.md 并逐张 Read img/01-33 核对：01 11 个历史样本算法迭代表；02/03 DIE 2024-07 64 位 692KB MD5=C58A7C4BAFFA401C71A1A333ECD0F956、2023-05 32 位 337KB；04/33 指令码表（新增 3gnfm9/frgt45f、删除 3fgbfnjb3）；05 CyberChef base64->hex->AES-CBC-128->hex->base64；06 历史 strcpy 明文 key vs 本样本 _mm_load_si128 读 shellcode 段；07 反转/分块字符串；08-09 API/cmd 字符串混淆；10-11 三线程->单心跳线程；12-13 FUN_Sleep_random(214013*seed+2531011, HIWORD&0x7fff) 与 stoi/服务端状态分支；14/27 FUN_HEAPFREE 清理；15 互斥体 RfmbFv8D/F FindWindowA(ConsoleWindowClass)/ShowWindow；16 C2/URI/UA/API 字符串；17 uedf 格式串与 #**# 六段；18 key/IV 内存；19 UUID 解密 4FD94D56-E747-23EC-D45D-17479C16D2EF；20-26 外网 IP/国家/OS/USMBIOS UUID/本地 IP 64.46.102.128/用户名 qianlan；28-32 HttpSendRequestA/CreateThread/InternetReadFile/按 $ 分割指令。卡内加密顺序、key/IV、心跳、指令集、IOC 与原文一致；affected_versions 按原文样本 MD5/2024-07 变种标注。单卡为单个样本逆向分析，未过粗。dedup 候选 VBE/Java RAT/AdaptixC2/VShell/NjRAT 均为不同家族/协议，非同链。未执行样本，未 commit/未跑 index/embed、未改 taxonomy。'
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-badnews-rat-double-base64-aes-heartbeat/
draft: false
kb_aliases:
- BADNEWS RAT
- Patchwork BADNEWS
- 双重 Base64 AES-CBC-128
- BADNEWS 指令码
- uedf/fufokin 协议
- telsiairegion.xyz
- 随机化心跳周期
---

## 一句话结论

Patchwork 组织的 Windows 主战远控 BADNEWS 在 2024-07 变种中把上线/功能通信改成“内层 Base64 → AES-CBC-128 → 外层 Base64”的双层编码，AES key/IV 不再硬编码字符串而是放在 shellcode 段由 `_mm_load_si128` 读取；木马用 SMBIOS UUID、外网 IP/国家、本地 IP、用户名和 OS 版本拼接 `uedf=` 上线包，仅保留一个心跳线程并用 MSVC `rand` 加服务端状态分支生成随机睡眠周期，指令集新增 `3gnfm9`（心跳单包）与 `frgt45f`（cmd 直接回传）、删除 `3fgbfnjb3`（键盘记录），可实现文件窃取、命令执行、目录遍历、远程下载执行和屏幕截图。

## 原理

- **样本结构**：初始载荷 `update.exe` 为 692 KB 64 位 PE（MD5 `C58A7C4BAFFA401C71A1A333ECD0F956`，MSVC 19.36/VS2022，时间戳 2024-07-23/24），经 2 次 shellcode 释放后落地 280 KB 的 BADNEWS 本体；2023-05 对照样本为 337 KB 32 位 PE。投递阶段通过计划任务周期性执行实现持久化。
- **通信编码**：以线上线数据包 UUID 为例，处理顺序是 `UUID → Base64 → Hex → AES-CBC-128 加密 → 去 Hex/取密文 → Base64`，最后放进 HTTP POST 体并经 TLS 传输。原文给出的 key 为 `3732386B7042764C74396E636A70356C`，IV 为 `394C3878643347356F624C527558666B`；用 CyberChef 反向执行 `From Base64 → To Hex → AES Decrypt → From Base64` 可还原 UUID（如 `4FD94D56-E747-23EC-D45D-17479C16D2EF`）。
- **key/IV 隐藏**：历史样本用 `strcpy(AES_KEY, "qgdrbn8kl...")` 之类的明文字符串；本样本改为在 shellcode 段用 `_mm_load_si128(&xmmword_18FC5689150)` / `_mm_load_si128(&xmmword_18FC5689140)` 读取 16 字节常量，静态搜索字符串找不到 key，只能在代码引用或内存中定位。
- **信息搜集**：`GetSystemFirmwareTable('RSMB')` 读取 SMBIOS 表拿系统 UUID；`GetAdaptersInfo` 拿本地 IP；取当前用户名；依次尝试 `myexternalip.com/raw`、`api.ipify.org?format=csv`、`ifconfig.me/ip` 获取出口 IP；访问 `api.iplocation.net/?cmd=ip-country&ip=` 获取国家名；用一组版本字符串判断 OS（原文实测有误判：Win10 被识别成 Win8，说明该逻辑只做粗略字符串匹配）。
- **上线包格式**：`printf("%s=%s#**#%s#**#%s#**#%s#**#%s#**#%s", "uedf", UUID, 出口IP, 本地IP, 用户名, OS, 国家)`；功能请求体只有一个键值对 `fufokin=UUID密文`。未收集到的字段以 `NA` 填充。抓包可见 `uedf=` 后是 6 段 `#**#` 分隔的 Base64 密文/占位。
- **心跳随机化**：历史版本用 3 个线程（部分信息+心跳、功能模块、完整信息）；本样本只保留心跳线程，功能模块放主函数。历史 `FUN_Sleep_random()` 通过 `__acrt_getptd()` 取线程环境块指针，执行 `214013 * *(DWORD*)(ptd+24) + 2531011`（MSVC `rand` 的 LCG）并把结果写回、返回 `HIWORD(...) & 0x7fff`；外层再 `srand(time(0))` 并取模（截图中可见 `% 10000 + 1000` 的分支，原文称历史范围 1~33.767 秒）。本样本在随机数之外根据服务端状态做逻辑判断，`stoi` 解析失败会走异常/不同睡眠分支，产生更多心跳周期类型，增加流量侧按固定间隔检测的难度。
- **指令分发**：`InternetReadFile` 读取 C2 回包后，把指令按 `$` 分割成“指令$参数1$参数2”，用 if/else 分发。2024-07 指令集：`3hdfghd1` 指定文件读取回传；`3gjdfghj6` cmd 命令执行并写文件回传；`3gnfm9` 心跳包单包发送（新增）；`3fgjfhg4` 指定路径文件信息遍历读取回传；`3gnfjhk7` 远程文件下载并执行、回传状态；`3ngjfng5` 远程文件下载回传状态；`3fghnbj2` 屏幕截图回传；`frgt45f` cmd 命令执行直接回传结果（新增）。历史 `3fgbfnjb3` 读取 `%temp%\kednfbdnfby.dat` 键盘记录并回传，本版本删除。
- **免杀/反分析**：Windows API、HTTP 字段和敏感字符串以反转/分块形式存放在数据段（如 `eliFdaeRtenretnI` 反转即 `InternetReadFile`、`alCwodniWelosmoC` 反转即 `ConsoleWindowClass`），运行时解密；所有 API 通过 `GetProcAddress` 函数指针调用，降低反汇编可读性；创建互斥体 `RfmbFv8D` 防多开；`FindWindowA("ConsoleWindowClass")` + `ShowWindow` 隐藏控制台窗口；敏感内存块用后立即 `FUN_HEAPFREE` 清理，减少内存取证痕迹（文章也正是借一次释放过程定位到 AES 参数）。

## 触发条件

- 目标为 Windows 主机，攻击者通过钓鱼邮件/恶意初始载荷投递 `update.exe` 或同源样本；样本需要成功创建计划任务并运行。
- 主机可访问 C2 域名 `telsiairegion.xyz`（HTTPS），否则无法上线；C2 URI 为 `/1WrCVzW4kSDNbNTt/cqWf4vQlofzqFkc7.php`，User-Agent `Mozilla/5.0`，Content-Type `application/x-www-form-urlencoded`。
- 分析/检测方需要拿到样本、内存 dump 或 PCAP，并知道 AES key/IV，才能解密 `uedf`/`fufokin` 字段。

## 利用步骤

1. PE 识别：DIE 查看架构/编译器/时间戳（64 位、MSVC 19.36、2024-07-23），与历史 32 位样本对比；确认入口点与 `.text` 区段，判断是否加壳。
2. 定位混淆字符串：在数据段找反转/分块的 API 名、HTTP 字段（`Wininet.dll`、`InternetOpenA`、`InternetConnectA`、`HttpOpenRequestA`、`HttpSendRequestA`、`InternetReadFile`、`GetSystemFirmwareTable` 等），用 `GetProcAddress` 交叉引用还原调用关系。
3. 定位 AES 参数：搜索 `_mm_load_si128` 引用的 16 字节常量，或在内存释放点/堆块中抓 key/IV；用 base64→AES-CBC-128→base64 往返验证（UUID 与密文互转）。
4. 抓包或内存抓取上线请求：`POST /1WrCVzW4kSDNbNTt/cqWf4vQlofzqFkc7.php`，body `uedf=` 6 段 `#**#` 分隔；功能请求 body `fufokin=UUID密文`。
5. 解密并拆分 `#**#`，得到 UUID、出口 IP、本地 IP、用户名、OS、国家；UUID 来自 SMBIOS，可与目标主机资产表比对。
6. 逆向下发指令处理：`InternetReadFile` → 按 `$` 分割 → 指令码表映射；重点看 `frgt45f`/`3gjdfghj6` 的 cmd 执行、`3gnfjhk7` 的下载执行、`3fghnbj2` 的截图。
7. 逆向下发心跳：定位 `srand(time(0))`、`FUN_Sleep_random`、`stoi` 分支，还原不同服务端状态下的睡眠区间，用于流量检测/仿真。

## PoC

无武器化 PoC；以下为按原文协议实现的最小解密片段，仅用于分析验证（key/IV 为原文样本值）：

```python
import base64
from Crypto.Cipher import AES

KEY = bytes.fromhex("3732386B7042764C74396E636A70356C")
IV  = bytes.fromhex("394C3878643347356F624C527558666B")

def badnews_decrypt(field: str) -> bytes:
    outer = base64.b64decode(field)                 # 外层 Base64
    pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(outer)
    pt = pt[:-pt[-1]]                               # 去 PKCS#7 填充
    return base64.b64decode(pt)                     # 内层 Base64

# 原文示例：uedf 第一段密文解出 UUID
print(badnews_decrypt("Nudc74ukcfLaqw96hZcM05AFx4faIX8GFHLa9FZ9SBldmtuciInnwX0P1mKRIwcwZnCo5k449uWfVMry6m6Ttg==").decode())
# 4FD94D56-E747-23EC-D45D-17479C16D2EF
```

## 变体与关联

- 历史 BADNEWS 样本（2022-05 至 2023-11）的通信算法在 RC4+Base64、AES+Base64、XOR+RC4+Base64+HTTPS 等之间迭代，C2 从 `dayspringdesk.xyz`、`nevazisimayanews.club`、`housingpanel.info`、`bingoplant.live`、`merril.top`、`netrol.info`、`flamiting.bio` 等轮换；本卡只描述 2024-07 变种。
- 与同目录远控分析卡的关联：[[code-analysis-reverse-windows-njrat-vbnet-dnspy-install-c2-analysis]]、[[code-analysis-reverse-windows-amadey-api-hash-loader-c2-config]]、[[code-analysis-reverse-windows-remcos-settings-config-extraction]]。
- 变体要点：key/IV 定位方式从明文字符串改为 shellcode 段常量；线程模型从 3 线程改为单心跳线程；心跳从单一随机数取模改为随机数 + 服务端状态分支；指令集增删见上表。

## 检测与防御

- 流量侧：检测 `POST /1WrCVzW4kSDNbNTt/cqWf4vQlofzqFkc7.php`、`User-Agent: Mozilla/5.0`、`application/x-www-form-urlencoded`，body 以 `uedf=` 或 `fufokin=` 开头且含 6 段 `#**#` 分隔的双层 Base64；对 `telsiairegion.xyz` 及历史 C2 域名做封禁/情报匹配；结合 TLS SNI/证书、心跳间隔分布与 URI 熵值检测。
- 主机侧：监控 `GetSystemFirmwareTable('RSMB')` + `GetAdaptersInfo` + 用户名读取 + 访问 `myexternalip.com`/`api.ipify.org`/`ifconfig.me`/`api.iplocation.net` 的组合；监控 `FindWindowA("ConsoleWindowClass")` + `ShowWindow`、互斥体 `RfmbFv8D`、异常计划任务创建。
- 静态/内存：搜索数据段反转/分块字符串与 `GetProcAddress` 函数指针表；在 shellcode 段或内存释放点提取 16 字节 AES key/IV；对 `FUN_HEAPFREE` 前后的内存块做 dump。
- 防御：EDR/AV 加入上述 API 组合与 IOC；限制终端直接出网，强制 TLS 检查与域名信誉；及时清理异常计划任务；对钓鱼邮件附件和快捷方式做沙箱/静态检测。
