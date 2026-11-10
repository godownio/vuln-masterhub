---
id: code-analysis-reverse-windows-xmrig-monitor-tool-aware-mining-evasion
title: XMRig 注入 credwiz.exe 的监控规避：检测 taskmgr/autoruns/wireshark/tcpview 即停矿并退避 5 小时，线程与矿池按硬件动态调整
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: xmrig-monitor-aware-mining-evasion
aliases:
- 挖矿监控规避
- XMRig 注入 credwiz
- 检测任务管理器停矿
- GuptiMiner 挖矿
- 动态线程矿池选择
tags:
- xmrig
- cryptominer
- injection
- defense-evasion
- credwiz
- windows
- guptiminer
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444
  verified_at: '2026-11-09T23:13:20+08:00'
  notes: 已对照原文核对：注入挂起 credwiz.exe、每 5 秒枚举进程、命中 taskmgr/autoruns/wireshark/wireshark-gtk/tcpview 即终止 credwiz 并退避 5 小时、高版本扩展 Process Explorer/Monitor/OllyDbg/WinDbg/TeamViewer、max_cpu_usage=53、线程 1/2/3 按核心数、m./r. 矿池按 3GB 内存（p. 前缀部分版本）、创建电源方案、单核/互斥体退出、杀 msiexec/cmstp/credwiz、禁用 Defender、HKLM\SOFTWARE\AVC3 与 download.exe 定位 eScan，均与原文及图 29-31 一致。无组件版本。
---

## 一句话结论

GuptiMiner 的 Puppeteer 阶段把内置 XMRig 注入新创建的 `credwiz.exe` 进程挖矿，并每 5 秒枚举进程：一旦发现 `taskmgr.exe`、`autoruns.exe`、`wireshark.exe`、`wireshark-gtk.exe`、`tcpview.exe` 等监控工具，就终止 credwiz.exe 停止挖矿并退避 5 小时再重试；挖矿线程数与矿池子域按 CPU 核心数、物理内存动态选择，尽量保持低资源占用与隐蔽。

## 原理

- **注入链**：创建挂起状态的 `credwiz.exe`（系统凭证管理向导），`WriteProcessMemory` 写入 XMRig 镜像/配置，`CreateRemoteThread` 启动；挖矿进程名是合法的系统二进制，不显眼。
- **监控工具感知**：Puppeteer 每 5 秒枚举一次进程，命中 `taskmgr.exe`、`autoruns.exe`、`wireshark.exe`、`wireshark-gtk.exe`、`tcpview.exe` 时，杀掉整个 `credwiz.exe` 进程（停止挖矿），并通过“渐进式睡眠”把下一次注入推迟 5 小时；更高版本把监控列表扩展到 Process Explorer、Process Monitor、OllyDbg、WinDbg、TeamViewer 等。
- **硬件自适应**：XMRig 配置直接存在 Puppeteer 二进制中（标准 JSON），运行时按硬件打补丁：`max_cpu_usage=53`，线程数默认 `1`，CPU 核心 ≥6 用 `2`，≥8 用 `3`；矿池子域按内存选择——可用内存 ≥3GB 用 `m.domain.tld`（auto 模式、大页），<3GB 用 `r.domain.tld`（light 模式、禁大页），部分版本还用 `p.` 前缀。
- **系统级准备**：创建新电源方案防止休眠；若 CPU 单核或互斥体已存在则无限睡眠退出；终止已有的 `msiexec.exe`/`cmstp.exe`/`credwiz.exe` 进程后再注入；把 Windows Defender 服务启动类型改为禁用。
- **为什么有效**：CPU 占用上限 53% 与少线程让用户不易察觉；遇到常见分析/监控工具立即停矿并长时间退避，避免被抓现行；合法进程名与动态矿池降低静态/流量检测命中率。

## 触发条件

- 已获得 SYSTEM 权限并可创建进程/注入（Puppeteer 阶段已运行）；
- 目标 CPU 至少 2 核、内存满足挖矿最低要求（单核直接退出）；
- 可出站连接矿池（域名 `m./r./p.` 子域）；
- 系统存在 `credwiz.exe`（Windows 自带）。

## 利用步骤

1. 创建电源方案阻止休眠，检查 CPU 核心数/互斥体，单核或已运行则退出。
2. 杀死 `msiexec.exe`、`cmstp.exe`、`credwiz.exe` 进程；禁用 Windows Defender 服务。
3. 读取内置 XMRig 配置，按核心数修改 `threads`、设置 `max_cpu_usage=53`，按内存选择 `m.`/`r.` 矿池子域。
4. 挂起创建 `credwiz.exe`，写入 XMRig 并远程线程执行。
5. 每 5 秒枚举进程；发现监控工具则终止 credwiz.exe 并睡眠 5 小时后重试；持续监控 CPU 使用率调整核心分配。
6. 通过 `HKLM\SOFTWARE\AVC3` 或合法 `download.exe` 路径定位 eScan 目录，用于后续更新/自替换（见关联卡）。

## PoC

```text
伪代码（按原文行为归纳）:

while (true) {
    if (process_exists_any({"taskmgr.exe","autoruns.exe","wireshark.exe",
                            "wireshark-gtk.exe","tcpview.exe"})) {
        terminate(credwiz.exe);     // 停矿
        sleep(5 * 3600 * 1000);     // 退避 5 小时
        continue;
    }
    if (!credwiz_running) {
        p = create_suspended("credwiz.exe");
        patch_xmrig_config(p, max_cpu_usage=53,
            threads = cores >= 8 ? 3 : cores >= 6 ? 2 : 1,
            pool = ram >= 3GB ? "m.domain.tld" : "r.domain.tld");
        inject(p, xmrig_image);
        resume(p);
    }
    sleep(5000);
}
```

说明：原文未给出完整注入代码；线程/矿池规则来自配置补丁截图（`max_cpu_usage='53'`、`threads='1'/'2'/'3'` 与 `m.`/`r.` 子域说明）。

## 变体与关联

- 变体：监控列表可扩展（Process Explorer/Monitor、OllyDbg、WinDbg、TeamViewer）；退避时间可调整；矿池可换 NiceHash/RandomX 等。
- 变体：挖矿载荷可注入 `svchost.exe`/`dialer.exe`，或用服务方式运行（见 [[code-analysis-reverse-windows-silentcryptominer-service-injection-winring0]]、[[code-analysis-reverse-windows-silentcryptominer-340-svchost-powercfg-winring0]]）。
- 关联：XMRig 矿池地址静态提取与动态 `getaddrinfow` 断点见 [[code-analysis-dynamic-debugging-miner-pool-address-extraction-static-xmrig-config-dynamic-getaddrinfow-breakpoint]]；矿池支付 ID 追踪见 [[defense-forensics-xmrig-monero-payment-id-pool-tracking]]。
- 关联：本活动的模块化后门见 [[pentest-c2-modular-backdoor-wallet-scan-registry-modules]]。

## 检测与防御

- 检测 `credwiz.exe` 被挂起创建后远程线程注入、其子线程高 CPU；监控 `credwiz.exe` 的异常网络连接到矿池域名/端口。
- 监控进程终止与重新创建的时间规律（每 5 小时重启一次）；检测对 `taskmgr.exe` 等监控工具的进程枚举与随即自杀行为。
- 检测新电源方案创建、`WinDefend` 服务 Start 被改为 4、以及 `HKLM\SOFTWARE\AVC3` 被非 eScan 进程读取。
- 网络侧阻断已知矿池域名（`m./r./p.` 子域模式）与 NiceHash/RandomX 端口；主机侧设置 CPU/GPU 异常占用告警并排查 `credwiz.exe` 来源。
