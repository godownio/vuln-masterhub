---
id: defense-incident-response-phishing-docm-oscti-threatfox-vt-pivot
title: 钓鱼宏样本 OSCTI 拓线：在线沙箱取云函数回连域名，ThreatFox 反查真实 C2 IP，VT Relations 关联样本 MD5
type: scenario
domain: defense
path: defense/incident-response
technique: phishing-docm-oscti-threatfox-vt-pivot
aliases:
- 钓鱼 docm 应急拓线
- ThreatFox 反查 C2
- VT Relations 关联样本
- 云函数网关 C2
- 回连域名反查 IP
- 样本 MD5 关联
tags:
- incident-response
- threat-intelligence
- oscti
- threatfox
- virustotal
- anyrun
- docm
- vba
- cobalt-strike
- ioc
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:48:39+08:00'
  notes: 已对照原文13671及16张图核对：docm SHA256 6ef475…、回连域名 service-ps16whvt-1304800271.sh.tencentapigw.com、ThreatFox botnet_cc CobaltStrike C2 122[.]51[.]7[.]163:80、VT Relations communicating files todesk.exe MD5 a831de…、首次提交2024-03-29 03:32:38 UTC与北京时间换算、微步/ANY.RUN环境选择与VBA十进制数组兜底均一致；Python解码片段未本机对原样本执行
---

## 一句话结论

应急/取证只拿到一个钓鱼 `.docm` 宏下载器（隐藏的 C2 样本没找到）、直接运行样本时 C2 IP 每次都不一样时，可由沙箱动态行为拿到稳定的回连域名（腾讯云函数网关 `service-<id>.sh.tencentapigw.com`，真实 C2 被网关隐藏），用 ThreatFox 按域名反查到真实 C2 `122.51.7.163`，再用 VirusTotal Relations 按域名找到通信样本 `todesk.exe` 及 MD5 `a831de33265fe368d7c2a6892857a232`；结合样本首次提交时间还能证明该样本不是赛时其他选手上传，排除污染。

## 原理

- **云函数网关做 C2 前置**：宏释放的 shellcode 通过 `rundll32.exe` 回连 `service-<随机串>.sh.tencentapigw.com` 这类腾讯云 API 网关域名，网关后面的真实 C2 IP 不直接暴露；每次执行看到的连接 IP 可能是网关的不同解析结果，因此"交 IP"式答案不稳定，域名才是稳定 IOC。
- **沙箱环境决定能否看到行为**：同一 `.docm` 在微步默认 Win10x64 环境首轮未解析出网络行为，VT Behavior 解析耗时且赛时只出现部分 URL；ANY.RUN 用 Win7x32 默认配置正确捕获到 WINWORD.EXE → rundll32.exe 及对网关的 `GET /vue.min.js`、`GET /api/x` 请求。赛后微步改用 Win7(32bit,Office2013) 也复现了同一 HTTP 请求。宏+rundll32 shellcode 类样本在较老 32 位 Office/Win7 环境更容易触发。
- **ThreatFox 反查**：ThreatFox 是按 IOC 组织的社区威胁情报库。用回连域名检索可命中 botnet_cc 记录（本例标为 Cobalt Strike、confidence 100%），社区提交的注释里直接给出 `C2: http://122[.]51[.]7[.]163:80`、`C2 Server: service-.../api/x`、`POST /api/y`，因此 Q1 的 C2 IP 可直接得到。
- **VT Relations 关联样本**：VT 域名报告的 Relations 页会列出 passive DNS、siblings 与 communicating files；本例在与网关域名通信的文件中同时出现 `授权书.docm`、`test1.exe` 与 `todesk.exe`。点开 `todesk.exe` 的 Details 即得 MD5 `a831de33265fe368d7c2a6892857a232`；History 的 First Submission 为 2024-03-29 03:32:38 UTC（北京时间 11:32），早于比赛提交时间，说明不是其他选手赛时上传，可放心作为答案。
- **VBA 数组兜底**：若沙箱迟迟不出 URL，宏里的 `myArray` 是十进制（含负数）字节数组，按 `byte = x & 0xff` 转成字节后直接以 ASCII/十六进制查看，就能在数组数据中看到网关域名；原文用 CyberChef 的十进制→ASCII 转换完成，转换结果与沙箱捕获的域名一致。
- **为什么这套流程可复用**：恶意基础设施常把稳定标识放在域名层（云函数、CDN、域前置），IP 层频繁变化；沙箱负责取行为，威胁情报库负责把域名映射到 IP/家族，VT Relations 负责从域名扩到关联样本。三者组合能在只掌握一个样本/一个 IOC 时补齐 C2 与样本哈希。

## 触发条件

- 事件/题目给出钓鱼文档（.docm/.doc 等）或单个回连域名，缺少隐藏载荷或 C2 样本。
- 样本运行时 C2 IP 不稳定（网关/云函数/负载均衡），无法直接以 IP 作答。
- 能使用在线沙箱（微步、VT、ANY.RUN 等）并选择合适环境（本例 Win7 32 位 + Office 2013）。
- 能访问 ThreatFox 与 VirusTotal；上传前确认样本可公开共享（VT 默认共享给厂商与社区）。

## 利用步骤

1. 计算 `.docm` 的 SHA-256 并上传沙箱；优先选择 Win7x32/Office2013 环境触发宏与 rundll32 行为。
2. 在沙箱 Behavior/Network 中记录 HTTP 请求的 Host/URI（本例 `service-...sh.tencentapigw.com` 的 `/vue.min.js`、`/api/x`），确认为回连域名。
3. 在 ThreatFox 搜索该域名，读取记录的 IOC 类型、Malware（Cobalt Strike）、confidence 与社区注释中的 C2 IP/端口、C2 Server 路径。
4. 在 VirusTotal 搜索该域名，进入 Relations → Communicating Files，筛出与域名通信的可执行样本；打开样本 Details 取 MD5/SHA-256，核对 History 的 First Submission 时间。
5. 若沙箱没有给出 URL，回到宏代码：提取 `myArray` 十进制数组，按 `x & 0xff` 转字节，用 ASCII/hex 视图定位内嵌域名；也可用 CyberChef 的"十进制→ASCII"。
6. 交叉验证域名、IP、样本哈希三者关系（ThreatFox 的 C2 Server 路径与沙箱 URI 是否一致、VT 样本家族标签是否一致），再输出结论。
7. 记录所有来源与查询时间，便于复查情报是否过期/被误报。

## PoC

原文用 CyberChef 做十进制→ASCII；等价的最小脚本（数组来自宏，实际需从样本提取）：

```python
arr = [-4, -24, -119, 0, 0, 0, 96, ...]   # VBA myArray 原样
data = bytes(b & 0xff for b in arr)
import re
print(re.findall(rb'[ -~]{6,}', data))    # 可读字符串
# 期望看到 service-ps16whvt-1304800271.sh.tencentapigw.com
```

情报查询（浏览器操作，无脚本）：

```text
ThreatFox: 搜索 service-ps16whvt-1304800271.sh.tencentapigw.com
  → Comment: C2: http://122[.]51[.]7[.]163:80 / POST /api/y
VirusTotal: 搜索同一域名 → Relations → Communicating Files
  → todesk.exe → Details → MD5 a831de33265fe368d7c2a6892857a232
```

## 变体与关联

- 变体：沙箱可用 ANY.RUN（Win7x32 默认配置）先跑出 HTTP 请求，再用微步/VT 复核；VT Behavior 解析慢时可先用 Relations 里的 Contacted URLs 作为线索。
- 变体：威胁情报库不限于 ThreatFox；VT 的 passive DNS/Graph 可补域名→IP，样本哈希可反查家族与同源样本。
- 变体：宏混淆不限于十进制数组；Base64+XOR、字符串拼接、Chr() 等还原后同样能得到回连域名，参见 [[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]。
- 关联：[[defense-detection-virustotal-free-triage-pivot]]（VT 免费功能样本初筛）、[[defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois]]（域名基础设施拓线）、[[defense-incident-response-attacker-ip-attribution-icp-aliyun-recovery-cross-validation]]（多源 IP 归属交叉验证）。
- 边界：公开沙箱/情报库存在解析延迟、情报过期与误报；云函数域名可能被正常业务使用，不能仅凭域名后缀定性；样本上传即共享，敏感样本需改用私有沙箱。

## 检测与防御

- 检测：Office 进程启动 `rundll32.exe` 并向云函数/API 网关域名发起 HTTP；宏文档中的 AutoOpen/Workbook_Open 调用 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread；网关域名短时间大量随机子域解析。
- 防御：禁用不受信任文档的宏（组策略/受保护视图）、ASR 规则拦截 Office 子进程创建、对云函数域名做信誉与业务白名单、EDR 监控 rundll32 网络行为；应急时按"域名→情报库→关联样本"顺序固定证据。
- 边界：云函数网关本身是合法云服务，检测需结合子域随机性、进程链与请求路径（/api/x、/api/y 等）综合判断。
