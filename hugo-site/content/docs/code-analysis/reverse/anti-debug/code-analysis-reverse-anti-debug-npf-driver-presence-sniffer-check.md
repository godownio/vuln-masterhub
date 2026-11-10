---
id: code-analysis-reverse-anti-debug-npf-driver-presence-sniffer-check
title: 驱动用 ObReferenceObjectByName 探测 \Driver\npf 判断 WinPcap/Npcap 抓包监控环境
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: kernel-driver-obreferenceobjectbyname-npf-sniffer-detection
tags:
- reverse
- anti-debug
- anti-analysis
- npf
- winpcap
- npcap
- kernel-driver
- festi
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V323
  verified_at: '2026-11-08T15:42:38+08:00'
  notes: 已对照 content.md 与 img/17-18 核对：img17 sub_105D0 使用 RtlInitUnicodeString(&DestinationString,&word_1B7B2) 后调用 ObReferenceObjectByName(&s,64,0,2032127,IoDriverObjectType,0,0,&Object)，失败返回 0、成功 ObfDereferenceObject 后返回 1；img18 字符串为 \Driver\npf（aDriverNpf）。卡内 0x1F01FF=2032127、OBJ_CASE_INSENSITIVE=64 与反编译一致。原子性：单一 npf 驱动对象存在性探测技术，合格。未验证点：命中后的具体动作原文未展开（卡已注明），未动态运行；原文说明该检查来自另一样本而非本文 Dropper。dedup 候选 direct-IRP 通信/文件标记检测等非同链。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-npf-driver-presence-sniffer-check/
draft: false
kb_aliases:
- npf.sys 检测
- WinPcap 检测
- Npcap 检测
- \Driver\npf
- 反抓包分析
- Festi 反监控
---

## 一句话结论

Festi 驱动通过 `RtlInitUnicodeString(L"\\Driver\\npf")` 构造驱动对象名，再调用 `ObReferenceObjectByName(..., IoDriverObjectType, ...)` 查询该对象是否存在：若成功取到对象（说明 WinPcap/Npcap 的包捕获驱动 `npf.sys` 已加载，Wireshark 等流量监控工具常依赖它），则判定系统可能处于抓包/分析环境，并据此改变行为。该检查直接查询对象管理器中的驱动对象，不依赖文件路径、服务名或进程名，改名/换目录无法绕过。

## 原理

- **npf.sys 与 `\Driver\npf`**：WinPcap/Npcap 的数据包捕获驱动是 `npf.sys`，加载后在内核对象管理器中注册驱动对象 `\Driver\npf`。Wireshark、dumpcap 等工具通过它访问数据链路层，因此该驱动存在通常意味着主机装有网络抓包/监控软件。
- **对象管理器查询**：`RtlInitUnicodeString(&s, L"\\Driver\\npf")` 初始化 UNICODE_STRING；`ObReferenceObjectByName(&s, 64, 0, 0x1F01FF, IoDriverObjectType, 0, 0, &Object)` 在对象命名空间中按类型 `IoDriverObjectType` 查找对象（`64` 为 `OBJ_CASE_INSENSITIVE`，`0x1F01FF` 为访问掩码）。成功返回 `STATUS_SUCCESS` 并给出对象指针，随后 `ObfDereferenceObject(Object)` 释放引用；失败返回非 0 表示驱动不存在。
- **为什么难以绕过**：文件可以改名、服务可以换名，但驱动对象名由驱动在 `IoCreateDriver`/`DriverEntry` 时注册；只要 `npf.sys` 的功能在，`\Driver\npf` 通常就存在。恶意软件用对象管理器查询而不是枚举进程/服务，规避了基于工具进程名的检测盲区。
- **行为影响**：原文只展示该检查函数（`sub_105D0`）与 `\Driver\npf` 字符串，未展开命中后的具体动作；从恶意软件常见逻辑推断是“检测到抓包工具则不执行恶意行为/改变通信”，用于规避流量分析与沙箱。
- **检测价值**：反向看，安全分析人员可以据此识别样本具备“反抓包/反沙箱”能力；动态分析时需要在反分析检查之后再加载 `npf.sys`，或 patch 该检查。

## 触发条件

- 样本为 Windows 内核驱动，`DriverEntry` 或初始化路径中调用该检查；原文样本为 Festi。
- 目标主机已安装并加载 WinPcap/Npcap（`npf.sys`），存在 `\Driver\npf` 驱动对象。
- 仅用于授权恶意样本分析，不运行驱动。

## 利用步骤

1. 在驱动中定位 `RtlInitUnicodeString` 调用及其字符串参数，确认是否为 `\Driver\npf`。
2. 跟进 `ObReferenceObjectByName` 调用：确认对象类型为 `IoDriverObjectType`、访问掩码与 `OBJ_CASE_INSENSITIVE` 标志，成功/失败分支的返回值。
3. 分析成功分支后的行为（跳过初始化、切换通信方式、退出等），判断该检查的实际影响。
4. 动态分析绕过：先让样本通过检查再加载 `npf.sys`，或 patch `sub_105D0` 恒返回“不存在”，或在对象管理器中临时重命名/隐藏该驱动对象（需谨慎，可能影响抓包工具）。
5. 将 `\Driver\npf` 字符串与 `ObReferenceObjectByName`+`IoDriverObjectType` 组合加入同族样本的识别特征。

## PoC

原文反编译对应的最小形态（伪代码，未执行）：

```c
char is_sniffer_present(void) {
    UNICODE_STRING name;
    PVOID obj = NULL;
    RtlInitUnicodeString(&name, L"\\Driver\\npf");
    if (ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE,
                                0, 0x1F01FF, IoDriverObjectType,
                                0, 0, &obj) != STATUS_SUCCESS)
        return 0;                 // npf 不存在
    ObfDereferenceObject(obj);
    return 1;                     // 存在抓包驱动
}
```

## 变体与关联

- 变体：探测其他监控驱动对象（如防火墙/杀软过滤驱动）、枚举 `\Device\NPF_*` 设备、枚举 `Wireshark`/`dumpcap`/`procmon` 进程、检查 WinPcap/Npcap 服务与注册表项。
- 关联：[[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]]（进程/文件标记类反分析）、[[code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks]]（沙箱环境检查）、[[code-analysis-reverse-windows-rootkit-direct-irp-tcp-udp-bypass-monitor]]（同族 Festi 绕过网络监控的通信实现）。
- 边界：主机未安装 WinPcap/Npcap 时不命中；分析环境可在检查后再加载驱动；某些安全产品可能已替换/重命名该驱动对象，导致检测失效。

## 检测与防御

- **样本检测**：搜索 `\Driver\npf` 宽字符串、`ObReferenceObjectByName` 与 `IoDriverObjectType` 的组合、`npf.sys`/WinPcap/Npcap 相关字符串。
- **分析环境**：先运行样本让反分析检查通过，再加载抓包驱动；或 patch 检查函数；也可在 hypervisor/内核层隐藏 `\Driver\npf` 对象（注意可能影响抓包工具）。
- **防御**：该检查属于恶意软件反分析行为；生产环境依靠 EDR 行为监控、驱动加载审计和网络流量异常检测，而不是仅依赖主机抓包工具；发现驱动包含此类探测时按可疑样本处置。
- **说明**：本卡是恶意样本反分析技术分析，severity 记为 low；仅用于授权样本分析。
