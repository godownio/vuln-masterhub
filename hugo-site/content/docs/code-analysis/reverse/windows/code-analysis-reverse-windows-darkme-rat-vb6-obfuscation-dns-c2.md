---
id: code-analysis-reverse-windows-darkme-rat-vb6-obfuscation-dns-c2
title: DarkMe RAT：VB6 编译、时间条件与加密字符串混淆、隐藏窗口 socket 通信与 DNS C2
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: darkme-rat-vb6-obfuscation-dns-c2
tags:
- windows
- malware
- rat
- vb6
- obfuscation
- dns
- c2
- water-hydra
- darkme
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:59:44+08:00'
  notes: 已对照原文核对；VB6/GUI 2024-05-11 dump、Time=3282389 恒假分支与加密字符串解密函数、DNS 查询 unfawjelesst322.com、威胁情报 65.108.20.68 一致；原文未给完整 C2 协议，卡片已如实标无 PoC 且 confidence medium；未本机复现
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-darkme-rat-vb6-obfuscation-dns-c2/
draft: false
kb_aliases:
- DarkMe
- DarkMe RAT
- Water Hydra RAT
- VB6 RAT
- unfawjelesst322.com
- 隐藏窗口 socket RAT
---

## 一句话结论

Water Hydra 攻击链最终注入宿主进程运行的是 VB6 编译的 DarkMe RAT：样本用恒定的时间条件分支与加密字符串/解密函数做混淆，创建隐藏窗口并通过 socket 与 C2 通信；运行中解密出域名 `unfawjelesst322.com`（DNS 查询返回 `65.108.20.68`），支持文件/目录操作、注册表操作、主机信息采集、屏幕截取、Shell 命令执行与文件上传下载。

## 原理

- **VB6 载荷形态**：最终 RAT 由 Microsoft Visual Basic 6.0 编译（依赖 MSVBVM60 运行时，GUI 子系统），以隐藏窗口/消息循环方式驻留；网络通信使用 Winsock/socket，不弹出可见界面。
- **混淆手法**：
  - **恒定的时间条件**：反编译中反复出现 `If (Time = 3282389) Then ...` 之类恒假/恒真分支，把无意义代码与真实逻辑混在一起，干扰静态阅读与反编译器；
  - **加密字符串**：界面/配置字符串以十六进制块保存，运行时由专用解密函数（反编译中可见 `Proc_25_0_10...`、`Proc_0_0_46D764(...)` 与十六进制常量）还原，直接搜字符串看不到 C2、命令名等关键信息；
  - **控件/变量拆分**：通过多个 `Form1.TextXXXX` 控件与临时变量搬运数据，增加数据流追踪难度。
- **C2 通信**：Wireshark 中可见对 `unfawjelesst322.com` 的 A 记录查询，响应为 `65.108.20.68`；RAT 通过 socket 与该地址通信，域名作为 C2 便于更换 IP。
- **指令能力**：文件与目录操作、注册表操作、主机信息收集、屏幕截取、Shell 命令执行、文件上传/下载——属于典型远控功能集，可在受害主机上完成侦察、横向与数据窃取。
- **投递位置**：最终载荷不落盘为独立 EXE，而是由加载器释放的 `WMFile01.dll` 启动 `WINDBVERS.EXE` 后注入其进程内存（见关联的 OCX 加载链卡），因此需要从内存 DUMP 才能取得完整 RAT。
- **为什么难查**：恶意代码运行在合法命名/合法签名的宿主进程内，字符串与域名运行时解密，网络上是正常 DNS + socket；仅靠静态文件扫描容易漏掉。

## 触发条件

- 目标已被 Water Hydra 前序链感染（MSI → OCX 加载器 → 注入）。
- Windows 主机具备 VB6 运行时（或载荷自带/依赖 MSVBVM60），允许出站 DNS 与 TCP。
- C2 域名可解析、网络未被完全阻断；攻击者服务器在线。

## 利用步骤

（以下为分析/复现视角）

1. **定位载荷**：对 `WINDBVERS.EXE` 等宿主进程做内存 DUMP，识别 VB6 PE（MSVBVM60 导入、GUI 子系统、编译时间戳 2024-05-11）。
2. **识别混淆**：标记恒定的 `Time = ...` 条件分支与字符串解密函数；在调试器中于解密函数返回处下断，批量记录还原后的字符串。
3. **提取 C2**：从还原字符串/网络行为中得到域名 `unfawjelesst322.com`，DNS 查询得到 IP `65.108.20.68`；抓包确认端口与协议。
4. **梳理指令**：动态运行于隔离环境，模拟 C2 下发文件/注册表/Shell/截屏/上传下载等命令，记录协议格式与回包。
5. **取证与清除**：结合前序链清理 MSI 释放文件、COM 注册项、Run 键与注入宿主。

## PoC

无 PoC（恶意样本分析；原文未提供可执行载荷或 C2 协议细节）。

## 变体与关联

- **同链前置**：LNK/WebDAV/BAT/MSI 投递链、MSI Wrapper 安装动作、OCX CLSID 加载器与 `WINDBVERS.EXE` 注入。
- **同类 RAT**：Remcos、Quasar、njRAT 等 VB/.NET RAT 的配置提取与隐藏窗口通信分析。
- **混淆家族**：VB6 恒假时间条件、字符串解密函数、控件数据搬运。

## 检测与防御

- **网络 IOC**：封禁/告警 `unfawjelesst322.com`、`65.108.20.68`；监控异常 DNS 查询与随后同 IP 的 socket 连接。
- **主机检测**：VB6 进程隐藏窗口 + Winsock、内存中出现解密后的 C2 字符串、宿主进程被注入（跨进程内存写入/线程上下文修改）等行为。
- **内存取证**：对可疑宿主进程 dump 后扫描 VB6 RAT 特征与加密字符串解密结果；结合 EDR 的注入链告警。
- **加固**：限制出站 DNS/网络、应用白名单、禁用不必要的 VB6 运行时组件（视业务）、及时清除前序持久化项。
