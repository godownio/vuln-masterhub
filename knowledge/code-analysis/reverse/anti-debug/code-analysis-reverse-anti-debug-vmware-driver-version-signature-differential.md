---
id: code-analysis-reverse-anti-debug-vmware-driver-version-signature-differential
title: VMware 宿主与虚拟机同名驱动文件的版本号/数字签名差异作为反虚拟机指纹
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: vmware-driver-version-signature-differential
aliases:
- VMware 驱动指纹
- 虚拟机驱动版本差异
- vmci.sys 版本检测
- VMware 签名差异
- 反虚拟机驱动检测
tags:
- anti-sandbox
- anti-vm
- vmware
- driver
- signature
- file-version
- windows
- evasion
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:47:26+08:00'
  notes: 已对照原文第四部分与图14-15核对：图14 左为宿主机（vmci.sys 9.8.18.0、vsock.sys 9.8.19.0 等）、右为虚拟机（vmci.sys 9.8.16.0、vsock.sys 9.8.17.0）；图15 vmci.sys 属性签名列表宿主为 Microsoft sha256、虚拟机为 VMware Inc. sha1/sha256 等，卡片签名结论一致。修正：原卡把宿主/来宾版本号写反（宿主 9.8.16.0/虚拟机 9.8.18.0），已按图14 更正为一句话结论、原理、利用步骤与 PoC 中的四处（库内卡片与 staging 草稿同步修正）；卡片按图15 证据表述，confidence medium 保持。affected_versions 原文未声明。未在本机复跑检测程序。
---

## 一句话结论

VMware 宿主机与虚拟机都可能存在 `C:\Program Files\Common Files\VMware\Drivers\...` 下的同名驱动文件（如 `vmci.sys`、`vsock.sys`、`vmkbd.sys`、`vmusb.sys`），但两者的文件版本号与数字签名列表不同（如 `vmci.sys` 宿主为 9.8.18.0、虚拟机为 9.8.16.0；宿主签名列表为 Microsoft sha256，虚拟机为 VMware Inc. 的 sha1/sha256）；样本读取这些驱动的版本与签名并与已知模式比对，可判定自身是否运行在 VMware 虚拟机内，避免仅按文件名判断时被宿主机误报。

## 原理

- **同名文件、不同来源**：VMware 在宿主机安装 Workstation/Player 等产品、在虚拟机安装 VMware Tools，二者都会在 `C:\Program Files\Common Files\VMware\Drivers`（或 `Drivers\vmci\device\Win8` 等子目录）放置 `vmci.sys`、`vsock.sys`、`vmkbd.sys`、`vmusb.sys`、`vmx86.sys` 等驱动；文件名相同，但打包版本不同。
- **可观测差异**：
  - 文件版本号（`GetFileVersionInfo` 读取 VS_FIXEDFILEINFO）不同，例如宿主 `vmci.sys` 9.8.18.0 vs 来宾 9.8.16.0；`vsock.sys` 宿主 9.8.19.0 vs 来宾 9.8.17.0；
  - 数字签名列表不同：宿主侧显示 Microsoft 的 sha256 签名，来宾侧显示 VMware, Inc. 的 sha1/sha256 签名；
  - 文件时间戳/签名时间不同（如 2021 年 vs 2019/2020 年）。
- **为什么能区分**：宿主与来宾安装的是不同 VMware 组件包（主机产品 vs Tools），版本与签名链自然不同；恶意样本读取这些字段后与已知宿主/来宾组合比对，即可判断当前环境类型。
- **为什么要结合多维**：仅检查“是否存在 VMware 驱动文件”会在宿主机上误报（宿主机同样有该目录）；结合版本号与签名可以降低误报，并区分宿主机、VMware 虚拟机、其它虚拟化环境。
- **边界**：VMware 版本更新会改变具体版本号/签名；不同产品组合、精简版 Tools、驱动被隐藏或目录被重定向时特征会变化，因此需要维护版本特征库并配合其它反 VM 检查。

## 触发条件

- 目标为 Windows + VMware 环境（宿主安装 VMware 产品，来宾安装 VMware Tools）。
- 样本可读取 `C:\Program Files\Common Files\VMware` 目录、获取文件版本信息与验证数字签名。
- 具备宿主/来宾驱动版本与签名的特征库（可通过实验环境采集）。
- 样本有权限调用 `GetFileVersionInfo`/`WinVerifyTrust` 或等价 API。

## 利用步骤

1. 在实验宿主与 VMware 虚拟机中分别枚举 `C:\Program Files\Common Files\VMware\Drivers` 下的驱动文件。
2. 读取每个文件的版本号、签名者、签名算法与时间戳，整理宿主/来宾差异表（如宿主 `vmci.sys` 9.8.18.0 vs 来宾 9.8.16.0）。
3. 样本中枚举同名驱动文件，读取版本与签名；与特征表比对。
4. 命中来宾特征则判定处于 VMware 虚拟机，结合其它反 VM 检查决定是否退出/延迟执行。
5. 验证：在宿主与虚拟机中运行检测程序，确认两者判定结果不同；更新 VMware 版本后复测并更新特征库。

## PoC

```c
// 读取文件版本与签名（示意，未在本机编译执行）
DWORD dummy;
DWORD size = GetFileVersionInfoSizeW(path, &dummy);
std::vector<BYTE> buf(size);
GetFileVersionInfoW(path, 0, size, buf.data());
VS_FIXEDFILEINFO* ffi = nullptr;
UINT len = 0;
VerQueryValueW(buf.data(), L"\\", (LPVOID*)&ffi, &len);
// ffi->dwFileVersionMS/dwFileVersionLS 得到版本号
// 再用 WinVerifyTrust + CryptQueryObject 取签名者信息
```

```text
宿主示例：vmci.sys  File Version 9.8.18.0  签名者 Microsoft (sha256)
来宾示例：vmci.sys  File Version 9.8.16.0  签名者 VMware, Inc. (sha1/sha256)
```

## 变体与关联

- [[code-analysis-reverse-anti-debug-sandbox-fingerprint-collect-dnslog]]：本卡是其“驱动文件采集”维度的深化。
- [[code-analysis-reverse-anti-debug-domain-join-vbox-driver-check]]：VirtualBox 驱动/域检查的同类思路。
- [[code-analysis-reverse-anti-debug-festi-vmware-backdoor-vpcext]]、[[code-analysis-reverse-anti-debug-cpuid-hypervisor-bit-intel-model-gate]]：VMware backdoor I/O 端口与 CPUID hypervisor bit 的其它 VMware 检测维度。
- [[code-analysis-reverse-anti-debug-silverfox-vmtools-mac-mouse-checks]]：VMware Tools 行为差异检测。
- 变体：其它虚拟化产品（VirtualBox/Hyper-V/Xen）的驱动版本/签名差异；文件时间戳、大小、目录结构；注册表服务项。
- 边界：VMware 版本/组件组合变化、驱动目录不可读、签名校验被绕过或伪造时需换维度。

## 检测与防御

- 检测（分析平台/EDR）：样本枚举 VMware 驱动目录、读取文件版本、调用签名验证 API；结合进程/网络行为判定反 VM 探测。
- 防御（沙箱/虚拟化环境）：隐藏或重命名虚拟化驱动特征、统一版本与签名、限制样本读取宿主机特征；分析报告将驱动/签名探测标为可疑行为。
- 防御（企业）：EDR 监控异常文件版本/签名枚举；对未知样本使用可控沙箱；更新虚拟化环境减少固定指纹。
