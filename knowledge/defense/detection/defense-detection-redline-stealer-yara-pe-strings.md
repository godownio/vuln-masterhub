---
id: defense-detection-redline-stealer-yara-pe-strings
title: RedLine 窃密木马静态检测：MZ 头 + 家族特征字符串组合的 YARA 规则
type: scenario
domain: defense
path: defense/detection
technique: redline-stealer-yara-rule-detection
aliases:
- RedLine YARA 检测
- RedLine 静态特征
- Happy.exe YARA 规则
- siyatermi.duckdns.org
- api.ip.sb geoip 检测
- YARA 恶意样本规则编写
tags:
- detection
- yara
- malware
- redline
- stealer
- static-analysis
- pe
- threat-hunting
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:36:52+08:00'
  notes: 已对照原文与8张图核对：YARA 保留字表、样本 PE 含 Happy.exe 与 MZ、api.ip.sb/geoip 宽字符串与 C# DownloadString、api.ipify.org/ipinfo.io 宽字符串、C2 siyatermi.duckdns.org:17044、Yandex/YaAddon 宽字符串、yara64 -r 命中 winlogon.exe 均与卡片一致；PoC 宽字符十六进制串与原文逐字节一致。原文 condition 中 mz at 0 后多余 and 为语法错误，卡片按可执行形式改写并注明。未验证点：未复跑 YARA 规则；目录内正常文件未命中为图08 仅一条命中的推断；原文未给样本哈希；未执行样本；frontmatter 无 sources/source_url。dedup 仅命中自身，RedLine 取证面与 .NET 加载器卡为不同技术原子，保留。
---

## 一句话结论

RedLine 窃密木马样本可用一条静态 YARA 规则识别：以 `{ 4D 5A }` 位于文件偏移 0 锁定 PE 文件，再要求命中归因特征字符串组合——样本名 `Happy.exe`、地理/IP 查询域名 `api.ip.sb`、`api.ipify.org`、`ipinfo.io`、C2 `siyatermi.duckdns.org:17044`、落地目录 `Yandex\YaAddon`，多个宽字符特征用布尔组合（名称 OR 三个查询域名同时命中 OR C2+目录同时命中）降低单字符串误报。

## 原理

- **PE 前置条件**：RedLine 是 Windows PE 木马，真实文件以 `MZ`（`4D 5A`）开头；规则先要求 `$mz at 0`，避免把内存转储、日志或文本中偶然出现的 URL 字符串判成样本。
- **归因字符串来自行为链**：样本运行后会访问 `api.ip.sb/geoip`、`api.ipify.org`、`ipinfo.io` 获取受害者公网 IP/地理位置，向硬编码 C2 `siyatermi.duckdns.org:17044` 回连，并创建 `Yandex\YaAddon` 目录存放窃取数据或持久化组件。这些字符串同时出现在二进制中，构成“查询公网 IP → 外联 C2 → 落地目录”的行为指纹。
- **宽字符匹配**：.NET 样本中的 URL/路径以 UTF-16LE 存放（原文十六进制串每字节间夹 `00`），YARA 侧应使用 `wide` 修饰符或等价 `{ 61 00 70 00 ... }` 十六进制串，直接按 ASCII 搜索会漏报。
- **组合条件降低误报**：`api.ipify.org`、`ipinfo.io` 这类公共 IP 查询域名本身常见于正常软件，单独命中不足以定性；规则要求三个查询域名同时命中，或 C2 域名与专属落地目录同时命中，或文件名 `Happy.exe`，把误报面收窄到家族样本组合特征。
- **可扩展性**：YARA 支持文本、十六进制（含 `??` 通配与 `[1-3]` 跳转）、正则三类字符串，以及 `#count`、`at`、`in`、`filesize` 等条件；对混淆样本可把固定字符串替换为带通配的十六进制片段，或增加字符串位置/数量约束。
- **为什么成立**：恶意样本的硬编码基础设施与落地路径在样本生命周期内相对稳定，且与正常 PE 中的字符串分布差异明显；静态扫描无需执行样本，适合在文件落地、邮件附件、样本仓库等环节批量筛查。

## 触发条件

- 具备待检文件（PE/.NET 可执行文件或内存转储落盘文件），可运行 YARA 扫描；不需要联网或执行样本。
- 样本保留硬编码字符串：`Happy.exe`、`api.ip.sb`、`api.ipify.org`、`ipinfo.io`、`siyatermi.duckdns.org:17044`、`Yandex\YaAddon` 中的若干项。
- 特征字符串以 UTF-16LE 宽字符形式存在（RedLine 原文样本即如此），规则需带 `wide` 或宽字符十六进制片段。
- 注意：若样本被改名、字符串被加密/压缩或 C2 已更换，固定字符串规则会漏报，需要结合行为/流量检测。

## 利用步骤

1. 从样本或沙箱报告中提取稳定字符串：文件名/互斥量、IP 查询域名、C2 域名与端口、落地目录。原文样本为 `Happy.exe`、`api.ip.sb`、`api.ipify.org`、`ipinfo.io`、`siyatermi.duckdns.org:17044`、`Yandex\YaAddon`。
2. 用十六进制视图确认字符串编码与相邻字节，把 UTF-16LE 字符串转为 `wide` 文本字符串或去掉 `00` 的十六进制串。
3. 编写 YARA 规则：`$mz at 0` 作为文件类型前置条件；用 OR/AND 组合归因字符串，优先使用“多字符串同时命中”的组合，避免单特征规则。
4. 在测试集上扫描，检查误报（正常软件中的 IP 查询库、安装包）与漏报（改名字符串加密变体），必要时增加字符串计数、偏移或正则约束。
5. 将规则部署到文件网关、EDR 自定义规则、样本处理流水线；命中后提取文件哈希、签名、C2 配置进一步研判。

## PoC

原文规则（注意原文条件部分有一处多余 `and`，实际部署前需删除；字符串为等价的宽字符十六进制写法）：

```
rule RedLine
{
    meta:
        date    = "2024-07-29"
        comment = "RedLine Yara"
    strings:
        $mz = { 4D 5A }
        $RedLine_Name = "Happy.exe"
        $geoip_url    = { 61 00 70 00 69 00 2E 00 69 00 70 00 2E 00 73 00 62 00 }
        $ipify_url    = { 61 00 70 00 69 00 2E 00 69 00 70 00 69 00 66 00 79 00 2E 00 6F 00 72 00 67 00 }
        $ipinfo_url   = { 69 00 70 00 69 00 6E 00 66 00 6F 00 2E 00 69 00 6F 00 }
        $C2_URL       = { 73 00 69 00 79 00 61 00 74 00 65 00 72 00 6D 00 69 00 2E 00 64 00 75 00 63 00 6B 00 64 00 6E 00 73 00 2E 00 6F 00 72 00 67 00 3A 00 31 00 37 00 30 00 34 00 34 00 }
        $Create_Directory = { 59 00 61 00 6E 00 64 00 65 00 78 00 5C 00 59 00 61 00 41 00 64 00 64 00 6F 00 6E 00 }
    condition:
        $mz at 0 and
        (
            $RedLine_Name or
            ( $geoip_url and $ipify_url and $ipinfo_url ) or
            ( $C2_URL and $Create_Directory )
        )
}
```

扫描命令：

```
yara64.exe -r RedLine.yara <样本目录>
```

原文验证：规则对目录内样本命中，输出 `RedLine <路径>\winlogon.exe`（样本被改名为 winlogon.exe，但特征字符串仍在）；同时目录中的正常文件未命中。

## 变体与关联

- **字符串变体**：C2 域名、IP 查询服务、落地目录随 RedLine 版本/构建器配置变化；同一规则思路可替换为新的 IOC 组合。
- **混淆变体**：字符串加密、压缩壳或 .NET 混淆后，十六进制片段可改用 `??` 通配与 `[n-m]` 跳转匹配，或先脱壳再扫描。
- **行为/流量关联**：静态命中只说明“像 RedLine”，可结合访问 `api.ip.sb/geoip`、`api.ipify.org`、`ipinfo.io` 后再外联 `*.duckdns.org` 的动态行为，以及 `Yandex\YaAddon` 目录落地痕迹交叉确认。
- **YARA 通用能力**：`nocase`、`wide`、`ascii`、正则、`#a` 计数、`$a at/in` 偏移约束、`filesize` 可用于构造更精确的文件级规则；同文还给出十六进制通配、跳转、字符串计数等语法示例。

## 检测与防御

- 在邮件网关、文件上传、终端 EDR 自定义规则、样本仓库落地环节部署 YARA 静态扫描；规则命中后隔离文件并提取哈希/C2 配置。
- 关注主机侧 `Yandex\YaAddon` 目录创建、进程访问 `api.ip.sb`/`api.ipify.org`/`ipinfo.io` 后随即外联 `*.duckdns.org:17044` 等组合行为。
- 对公共 IP 查询域名单独告警会产生大量误报，应以“查询域名 + C2/落地目录 + PE 头”组合作为告警条件，并定期更新 IOC。
- 规则需回归测试：正常软件（浏览器、下载器、VPN）常含 IP 查询域名，避免把 `api.ipify.org` 等单字符串规则直接上线。
