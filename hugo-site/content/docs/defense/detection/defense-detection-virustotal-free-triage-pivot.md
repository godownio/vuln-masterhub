---
id: defense-detection-virustotal-free-triage-pivot
title: VirusTotal 免费功能恶意样本初筛与关联拓线：Detection 规则解读、Behavior 十四段、Community IOC、VT Graph 与免费 API
type: scenario
domain: defense
path: defense/detection
technique: virustotal-free-tier-sample-triage-pivot
tags:
- threat-intelligence
- detection
- triage
- virustotal
- sandbox
- yara
- ids
- attack
- mbc
- ioc
- osint
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:42:52+08:00'
  notes: 已对照原文13687及43张图核对：六选项卡/十四段Behavior/YARA-IDS字段/免费API配额500次每日4次每分钟/Graph免费版限制均与原文一致；卡片Poc为按原文API章节整理的最小查询形式，未实际执行；属初筛拓线方法论单卡，非组件漏洞无版本
url: /docs/defense/detection/defense-detection-virustotal-free-triage-pivot/
draft: false
kb_aliases:
- VT 样本初筛
- VirusTotal 报告解读
- VT 免费功能
- VT Graph 拓线
- VT API v3
- 多引擎检出研判
- 沙箱行为标签
---

## 一句话结论

手上只有未知样本的哈希/URL/IP/域名、又没有付费沙箱时，可以用 VirusTotal 免费账号完成一轮可复用的初筛与拓线：基本信息栏看多引擎检出比与行为标签，Detection 页读 YARA/IDS/沙箱/厂商结论，Details 页取多类型哈希与 PE/签名信息，Behavior 页按十四段（ATT&CK、MBC、Capabilities、网络、文件、注册表、进程、互斥量、模块、可疑调用等）读动态行为，Community/Relations 页借 IOC 集合与 VT Graph 关联同源样本，最后用免费 API v3（每天 500 次、每分钟 4 次）做自动化查询；结论仍需回到本地逆向验证。

## 原理

- **三块拼合的情报面**：VT 把云沙箱（多引擎+动态沙箱）、社区（评论、评分、IOC Collection）与高级扩展（Graph、API、威胁狩猎）拼在一起。免费账号可用云沙箱报告与 community/Graph/API 的简化版；威胁情报与威胁狩猎需申请。
- **多引擎与沙箱互相补盲**：基本信息栏给出"69/72 引擎检出 + 6 个沙箱标记"这类总览；厂商标签格式通常是"样本类型 + 威胁类型 + 环境 + 名称"，沙箱结论（CAPE/腾讯哈勃/C2AE/Lastline/Zenbox 等）补充动态行为证据，社区评分反映人工研判。
- **Detection 页的三类规则**：YARA 规则来自开源情报（如 crime_wannacry、reversinglabs 规则集），可点开 View Ruleset 看 meta（描述/作者/参考/日期/哈希）、strings（字符串/十六进制/正则特征）与 condition（如 `uint16(0) == 0x5a4d`、`filesize`、字符串组合计数）；IDS 规则多为 Emerging Threats Open 等 Suricata 规则，字段包括 msg、sid、rev、classtype、reference、priority、metadata、target，能给出流量侧检测点与恶意域名（如 WannaCry 的 sinkhole 域名）；这些规则既用于确认家族，也可直接抽出 IOC 与检测思路。
- **Details 页的静态指纹**：基础属性同时给出 MD5/SHA-1/SHA-256/vhash/Authentihash/Imphash/Rich PE header hash/SSDEEP/TLSH 等多类型哈希，可用于跨库查询、相似样本聚类与家族关联；PE 结构、编译器、加壳信息（如 PEiD 识别 Microsoft Visual C++、Cyrén packer）和签名状态（未签名/签名者）补齐静态画像；History 给出首次出现、首次提交、最后提交时间，Names 给出样本用过的多个文件名。
- **Behavior 页的十四段**：Activity Summary 汇总 Detections、MITRE 签名、IDS 规则、Sigma 规则、Dropped Files、Network comms 的数量；往下依次是行为标签（checks-network-adapters、detect-debug-environment、long-sleeps 等）、检测标识（MALWARE/RANSOM/TROJAN）、ATT&CK 战术与技术（TAxxxx/Txxxx）、MBC 恶意行为目录树（OBxxxx/Bxxxx）、Capabilities 恶意功能分类（Communication/Anti-Analysis/Host-Interaction/Load-Code/Data-Manipulation/Persistence 等）、IDS 规则、网络通信（HTTP 请求、DNS 解析、内存中的 URL/IP，并可区分信息来源）、行为相似性哈希、文件/注册表/进程与服务/同步机制（互斥量）/模块加载/可疑调用。该页可勾选参与整合的沙箱，结果随选择实时变化；ATT&CK 与 MBC 互补，不必纠结用哪一个。
- **Community 与 Relations 的拓线素材**：Comment 常带其他平台的样本链接（MWDB、VirusShare、Triage）、YARA 标签与家族说明；Collection 是文件/URL/域名/IP 的 IOC 集合（含 trusted 标记），可用于批量取 IOC 与同源样本；Relations 页给出 contacted domains/IPs、dropped files、PE resource parents/children、execution parents 等关系。
- **VT Graph 的可视化关联**：免费版可新建空图或加载 WannaCry 示例，节点是文件/URL/域名/IP，边是 contacted domains、PE resource parents/children、dropped files、execution parents 等关系；节点侧栏显示 Basic Properties、Relations（Collections/Contacted domains/IPs/Dropped files/Detections/Comments），支持加标签、加节点、选父/子节点、导出 JSON/CSV/Collection，适合从一个样本扩到基础设施与同源样本。
- **免费 API v3 的边界**：注册社区账号即可拿到 API Key，免费配额为每天 500 次请求、每分钟最多 4 次，不得商用、不得用于不产生新文件的业务流、不得多账号绕过；API 以对象（object）、集合（collection）、关系（relationship）三个组件组织，支持按哈希取文件报告、按 URL/IP/域名查询、搜索与提交扫描，响应为 `{"data": ...}` JSON；错误码覆盖 400（参数/查询不支持）、401（未认证/账号未激活）、403、404、409、424、429（配额/频率）、503/504，可按错误类型重试或降速。官方提供 Python/Golang 库与 CLI。
- **为什么必须回本地验证**：沙箱只覆盖其环境下的行为，样本可做环境检测、延迟执行、加密通信；多引擎存在误报漏报；VT 报告是线索与初筛证据，不是最终结论。

## 触发条件

- 需要分析未知文件/URL/IP/域名，但只有免费账号或无法立即搭建沙箱；
- 样本非敏感/非隐私数据，可接受上传后被共享给安全厂商与社区（VT 默认把命中样本共享，上传前必须确认合规）；
- 目标是快速判断是否恶意、属于哪个家族、有哪些 IOC 与行为面，作为后续本地逆向/取证的起点；
- 查询量在免费配额内（500 次/天、4 次/分钟）。

## 利用步骤

1. 用哈希（MD5/SHA-1/SHA-256）或 URL/IP/域名在 VT 搜索框查询；未知文件上传前先确认不含敏感信息，文件上限 650MB。
2. 读基本信息栏：检出比、沙箱数量、社区评分、标签、文件大小/类型/修改时间，先形成"是否恶意、疑似家族"的判断。
3. 读 Detection：打开命中的 YARA 规则看 meta/strings/condition，确认家族特征；看 IDS 规则确认流量侧检测点与恶意域名/IP；对照安全厂商与沙箱结论。
4. 读 Details：记录全部哈希（尤其 SSDEEP/TLSH/Imphash）用于相似样本与家族关联，查看 PE 结构、编译器、加壳、签名与时间线、历史文件名。
5. 读 Behavior：按十四段提取可落地 IOC（HTTP/DNS/IP、落地文件路径、注册表键、互斥量、服务/进程）与 ATT&CK/MBC 技术点；勾选可信沙箱交叉验证。
6. 读 Community/Relations：从评论与其他平台链接取更多样本；从 Collection 批量取 IOC；从 Relations 的 contacted/dropped/PE resource/execution 关系找父样本与同源文件。
7. 用 VT Graph 把样本节点与域名/IP/落地文件/父样本连成图，按需加标签、导出 JSON/CSV/Collection，作为拓线底稿。
8. 需要自动化时用免费 API v3（先取 API Key），按对象/集合/关系组织请求，控制频率；失败按 429 退避、401 检查 Key 与账号激活状态。
9. 回到本地：对样本做静态/动态复核，确认 VT 线索（家族标签、C2、持久化行为）是否成立，再输出结论。

## PoC

原文为平台功能说明，无完整利用脚本；以下为按原文 API v3 章节与文档页整理的最小查询形式（未执行）：

```bash
# 按哈希取文件报告
curl -s --request GET \
  --url 'https://www.virustotal.com/api/v3/files/<sha256>' \
  --header 'x-apikey: <API_KEY>'

# 搜索（文档页示例端点）
curl -s --request GET \
  --url 'https://www.virustotal.com/api/v3/search?query=<keyword>' \
  --header 'x-apikey: <API_KEY>'
```

免费配额：500 次/天、4 次/分钟；429 时按分钟/每日配额退避。原文在免费账号下演示了样本报告各选项卡与 Graph，但未给出可复跑的查询脚本。

## 变体与关联

- 变体：用 `vt-py`/`vt-cli`/`vt-go` 替代手写 HTTP；用 Collection 的 IOC 列表批量查询；用 Graph 导出 JSON/CSV 接本地分析流程。
- 变体：先在本地的 YARA/沙箱/EDR 中取行为标签与可疑调用，再回到 VT 用相似性哈希/Imphash/TLSH 找同源样本，形成双向验证。
- 关联：[[defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois]]（从 IOC 做基础设施拓线，可与 VT Relations/Graph 互补）、[[defense-detection-redline-stealer-yara-pe-strings]]（YARA 规则与 PE 特征检测）、[[defense-forensics-silverfox-winos4-file-registry-artifact-dump]]（把沙箱行为落到主机取证）。
- 边界：上传即共享，敏感样本禁用公开 VT；免费 API 配额低且禁止商用/多账号绕过；沙箱可被反分析绕过；多引擎存在误报漏报。

## 检测与防御

- 使用侧：分析敏感样本时改用私有沙箱或企业版；上传前脱敏/去配置；对 API Key 做最小权限与泄露防护。
- 防御侧：把 VT 的 YARA/IDS 规则与行为标签转化为本地检测规则，但需在自有环境验证，避免直接照搬导致误报；对 VT 上已公开的 IOC 建立定期同步。
- 研判纪律：以"多引擎+多沙箱+行为+静态指纹"交叉验证，单一引擎或单一沙箱结论不作为定性依据；最终回到样本源码/内存证据。
