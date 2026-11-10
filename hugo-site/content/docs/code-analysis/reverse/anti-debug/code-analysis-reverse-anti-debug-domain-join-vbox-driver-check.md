---
id: code-analysis-reverse-anti-debug-domain-join-vbox-driver-check
title: 反沙箱组合：NetGetJoinInformation 判断是否域加入 + VirtualBox 驱动文件存在即退出
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: anti-sandbox-domain-join-vbox-driver
tags:
- anti-debug
- anti-sandbox
- anti-vm
- windows
- go
- loader
- evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:55:57+08:00'
  notes: 已对照 img20-22 与原文核对 NetGetJoinInformation/NetSetupDomainName 与 VBoxMouse.sys 存在即退出；dedup 的 likely_duplicate 候选 sandbox-environment-checks 检查项为时间加速/桌面/用户名/DebugPort，与本卡域加入+VBox 驱动不同，非同一利用链；PoC 未执行。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-domain-join-vbox-driver-check/
draft: false
kb_aliases:
- 反沙箱
- 域加入检测
- NetGetJoinInformation
- VBoxMouse.sys 检测
- VirtualBox 检测
- 沙箱环境识别
---

## 一句话结论

Loader 在执行真实载荷前做两项低成本环境检查：用 `NetGetJoinInformation` 判断机器是否加入 Active Directory 域，并检查 `C:\Windows\System32\drivers\VBoxGuest.sys`、`VBoxMouse.sys` 等 VirtualBox Guest Additions 驱动文件是否存在；真实企业主机通常已域加入且没有 VirtualBox 驱动，而沙箱/分析 VM 往往相反，命中“非域加入”或“存在 VBox 驱动”就直接退出，让沙箱看不到后续恶意行为。

## 原理

- **域加入状态是环境指纹**：`NetGetJoinInformation` 返回 `_NETSETUP_JOIN_STATUS` 枚举：`NetSetupUnknownStatus`、`NetSetupUnjoined`、`NetSetupWorkgroupName`、`NetSetupDomainName`。攻击者认为真实的企业内网主机大概率加入域（返回 `NetSetupDomainName`），而自动化沙箱/独立分析机通常在 workgroup 或未加入状态；若返回值不是 `NetSetupDomainName`，loader 直接退出。
- **VirtualBox 驱动是 VM 指纹**：安装 VirtualBox Guest Additions 后，系统驱动目录会存在 `VBoxGuest.sys`、`VBoxMouse.sys`、`VBoxVideo.sys` 等文件；真实物理机一般没有。loader 用 `os.Stat` 检查这些路径，存在即判定为分析虚拟机并停止执行。
- **为什么用文件检查而不是 API**：读文件属性比查询虚拟化 API 更低噪，不需要特殊权限，也不容易触发针对虚拟化检测 API 的 hook；缺点是文件名/路径可被沙箱伪造或隐藏。
- **组合降低误报**：单个检查可能误伤（真实主机也可能未加域、员工机器可能装过 VirtualBox），但“非域加入 + VBox 驱动存在”同时命中时，沙箱概率很高。原文还提到可检查 RAM 大小、CPU 核心数、磁盘剩余空间、虚拟化驱动等，作为同一类环境指纹的扩展。
- **双刃剑**：反沙箱检查本身就是恶意软件行为特征；如果 loader 被人工分析，这些 API/文件访问会暴露其规避意图。

## 触发条件

- Loader 在 Windows 主机上运行，具备普通用户权限即可执行文件检查与 `NetGetJoinInformation`。
- 分析环境是未加入域的沙箱/VM，或安装了 VirtualBox Guest Additions；真实目标企业主机已加入域且未装 VirtualBox。
- 攻击者愿意接受误杀风险：真实用户机器若未加域或装有 VirtualBox，loader 也会退出。
- 检查发生在解密/执行真实载荷之前，且 loader 没有其它更隐蔽的沙箱识别手段。

## 利用步骤

1. 调用 `NetGetJoinInformation(nil, &domain, &status)`，取得加入状态；用 `NetApiBufferFree` 释放返回的域名缓冲区。
2. 判断 `status == syscall.NetSetupDomainName`：是则继续，否则 `os.Exit(0)`。
3. 用 `os.Stat("C:\\Windows\\System32\\drivers\\VBoxMouse.sys")` 检查 VirtualBox 鼠标驱动；若文件存在则 `os.Exit(0)`。可同时检查 `VBoxGuest.sys`、`VBoxVideo.sys`。
4. 可选扩展：检查物理内存总量、CPU 核心数、磁盘剩余空间是否低于真实主机阈值；检查其它虚拟化驱动/进程。
5. 只有全部检查通过后才解密并执行真实 shellcode/载荷；退出路径不要留下明显错误信息。
6. 在真实域主机与沙箱中各跑一次，确认判定结果符合预期，并评估误杀率。

## PoC

```go
package main

import (
    "os"
    "syscall"
    "unsafe"
)

func checkDomain() (bool, error) {
    var domain *uint16
    var status uint32
    err := syscall.NetGetJoinInformation(nil, &domain, &status)
    if err != nil {
        return false, err
    }
    syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
    return status == syscall.NetSetupDomainName, nil
}

func main() {
    joined, err := checkDomain()
    if err != nil || !joined {
        os.Exit(0) // 非域加入，疑似沙箱
    }

    if _, err := os.Stat("C:\\Windows\\System32\\drivers\\VBoxMouse.sys"); err == nil {
        os.Exit(0) // 存在 VirtualBox 驱动，疑似分析 VM
    }

    // 环境检查通过，继续执行真实载荷
}
```

```text
# 判定逻辑（示意）
域加入状态 != NetSetupDomainName  -> 退出
C:\Windows\System32\drivers\VBoxMouse.sys 存在 -> 退出
否则 -> 执行载荷
```

## 变体与关联

- **时间加速/桌面文件/用户名/主机名/DebugPort**：另一组常见反沙箱检查，见 [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]。
- **Defender 模拟器检测**：进程名、`Mpclient` 导出哈希、无效句柄返回值、1GB 堆分配等更针对 Defender 模拟器的检查，见 [[code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks]]。
- **VMware 指纹组合**：VMware Tools 目录、VMware MAC OUI、鼠标位置轮询等，见 [[code-analysis-reverse-anti-debug-silverfox-vmtools-mac-mouse-checks]]。
- **Linux 沙箱环境探测**：容器/沙箱文件、进程与环境变量检查，见 [[code-analysis-reverse-anti-debug-linux-sandbox-environment-probes]]。
- **反反调试**：分析人员可 hook `NetGetJoinInformation`、伪造域状态或隐藏 VBox 驱动文件，让检查返回“真实主机”结果。

## 检测与防御

- **沙箱加固**：让分析 VM 加入测试域、隐藏或重命名 VirtualBox Guest Additions 驱动、模拟真实硬件资源（内存/CPU/磁盘），减少环境指纹差异。
- **API/文件监控**：监控 loader 进程对 `NetGetJoinInformation`、`NetApiBufferFree` 的调用，以及对 `System32\drivers\VBox*.sys` 的文件探测；这些是反沙箱行为的直接信号。
- **行为关联**：反沙箱检查本身可疑；结合进程来源、签名、父进程、网络行为综合判定。
- **误报处理**：企业真实主机也可能未加域或安装 VirtualBox，不能仅凭单一检查判定恶意。
- **纵深防御**：反沙箱只能拖延/跳过自动化分析，不能绕过人工分析与行为检测；关键检测应放在沙箱之外的内核/网络层。
