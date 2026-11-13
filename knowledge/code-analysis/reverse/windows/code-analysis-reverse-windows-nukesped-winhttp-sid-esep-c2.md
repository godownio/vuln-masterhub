---
id: code-analysis-reverse-windows-nukesped-winhttp-sid-esep-c2
title: Lazarus NukeSped 远控样本分析：异或字符串解密、LoadLibraryA 动态加载与 WinHTTP sid/esep C2 命令分发
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: nukesped-winhttp-c2-command-dispatch
aliases:
- NukeSped
- Lazarus 远控木马
- FallChill 同源远控
- sid/esep C2 协议
- connection.lockscreen.kro.kr
- 海事研究组织供应链投毒样本
- NukeSped 样本分析
tags:
- windows
- malware-analysis
- nukesped
- lazarus
- apt
- remote-access-trojan
- c2
- http
- winhttp
- xor
- threat-hunting
- ioc
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:29:10+08:00'
  notes: '已对照原文及全部16张截图核对：攻击链示意图（图01：渗透供应商→SSH密钥→Web服务器→curl→Ngrok/Python下载器→SSH横向→TCPDump→员工凭据→安全经理邮箱→PMS→NukeSped）一致；异或解密伪代码（图02：v142[0]=1971092238、v29=14、strcpy(v142[1],"c!!:qz{")、v30=0x164、逐字节 ^= v29+(_BYTE)v30、v29=v142[0]）与卡片一致；LoadLibraryA 汇编（图03）、WSAStartup（图04）、wcsncpy C2 URL http://connection.lockscreen.kro.kr/index.php（图05）、sid=/uid 字符串构造（图06）、WinHttpAddRequestHeaders Cache-Control: no-cache（图07）、SendRequest Length:41（图08）、WriteData 请求串（图09）、ReceiveResponse（图10）、ReadData（图11）、源码 strcpy "sid="/"esep="（图12，10倍放大确认字面量为 esep=）、响应 switch case 3/4/5/6/7 分发（图13）均与卡片一致。已修正卡片中运行时串的错误引用：截图实际为 sep=M1tzfhP1OLa&uid=366323e5&sid=01cad597（原文卡片写作 sepm1itzfhP10L），并在网络特征/检测中同时保留源码字面量 esep= 与运行时 sep=。IOC核对：图15 SHA256 7a10c12b381b0e85d621700cfded5dc213b2b517915e2ab688831fd4f2d1a724、域名、URL 与卡片一致；图16 微步检出 9/21、Exe64、NukeSped 木马/恶意；图14 域名“可疑/动态域名”、注册者 hyon jin park、关联 NukeSped 家族，均一致。dedup：除自身外候选（WinHTTP 加密载荷、SideWinder/WarHawk TLS C2、Latrodectus、ETW WinHTTP beacon、Amadey、XOR shellcode 等）均 new，无同家族/同协议重复。affected_versions/cve
    空合理；confidence medium 合适（原文为二手情报+IDA 截图，未给完整命令字段）。未验证点：未运行样本，IOC 未在本机复核。'
---

## 一句话结论

Lazarus APT 在对海事研究组织的供应链攻击中借 PMS 补丁管理系统下发 NukeSped 远控样本（64 位 PE）；样本先用异或算法解密内置字符串，`LoadLibraryA` 动态加载解密出的 DLL，`WSAStartup` 初始化网络后经 WinHTTP 以 `http://connection.lockscreen.kro.kr/index.php` 为 C2，请求体携带 `sid`/`esep` 参数，按响应数据 `switch` 分发执行文件上传/下载/读写与进程操作，功能结构与同组织早期的 FallChill 恶意软件相似。

## 原理

原文对样本的行为链还原如下（均为 IDA 静态分析截图，未给出完整协议细节）：

- **字符串异或解密**：样本内加密字符串由一个自定义异或循环还原——起始 u32 常量 `1971092238`、初始密文 `c!!:qz{`，从偏移 `0x164` 起逐字节 `^= (v29 + 低8位计数器)`，每轮用首 4 字节更新 `v29`，解出 DLL 名、C2 URL 等字符串。这种逐字节异或 + 滚动状态的方式能隐藏所有敏感常量，静态字符串搜索失效。
- **动态模块加载**：解密出的 DLL 路径/名字交给 `LoadLibraryA` 动态加载（汇编中可见先循环解密缓冲区，再 `call rax` 进入 `LoadLibraryA`），核心网络功能放在外部 DLL 中，主样本只做引导。
- **网络初始化与 C2 地址**：调用 `WSAStartup(2.2)` 初始化 Winsock 后，把硬编码/拼接的 `http://connection.lockscreen.kro.kr/index.php` 作为 C2 地址（伪代码中 `wcsncpy` 写入宽字符缓冲）。
- **WinHTTP 通信**：依次调用 `httpWinHttpAddRequestHeaders`、`httpWinHttpSendRequest`、`httpWinHttpWriteData`、`httpWinHttpReceiveResponse`、`httpWinHttpReadData`（IDA 中已将 API 重命名）。请求头固定为：
  ```text
  Cache-Control: no-cache
  Accept: */*
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 41
  ```
- **会话与命令参数**：请求体由 `sprintf` 拼接，源码写入 `sid=` 与 `esep=` 字面量（格式串 `%s&%s&%s`），另含 `uid=`；调试截图栈上实际可见形如 `sep=M1tzfhP1OLa&uid=366323e5&sid=01cad597` 的请求串，以表单形式发给 C2。
- **命令分发**：拿到响应后按首字段 `switch` 分发（原文截图可见 case 3/4/5/6/7 分别进入不同处理函数），执行文件上传、下载、文件读写以及进程相关操作；该功能结构与 Lazarus 此前使用的 FallChill 非常相似，是归因依据之一。

## 触发条件

本卡是样本分析/威胁狩猎场景，不存在可主动触发的漏洞条件。适用前提：

- 拿到可疑 64 位 PE 样本（或内存镜像）需要判定是否为 NukeSped 家族；
- 或网络侧观察到符合上述特征（`sid`/`esep` 表单参数、固定 Content-Length 41、上述 C2 域名/URL）的 HTTP 外连；
- 分析环境需断网/隔离，样本只做静态或受控动态分析。

## 分析步骤

1. 识别字符串解密循环（u32 初始常量 `1971092238`、`c!!:qz{` 密文、偏移 `0x164`、滚动异或），写脚本批量还原字符串。
2. 跟踪 `LoadLibraryA` 调用，dump/提取被动态加载的 DLL 并单独分析其导出与网络函数。
3. 定位 `WSAStartup` 后的 WinHTTP 调用序列，提取 C2 URL、请求头、`sid`/`esep` 参数构造逻辑。
4. 分析响应分发的 `switch` 各分支，映射上传/下载/读写/进程操作等远控能力。
5. 用哈希、域名、URL、请求特征与威胁情报比对，完成家族归因（原文与微步情报的 NukeSped 关联样本一致）。

## PoC

无 PoC（本卡不提供可执行恶意样本；不执行文中样本）。

威胁情报与 IOC（原文图 15/16 与微步情报）：

```text
SHA256: 7a10c12b381b0e85d621700cfded5dc213b2b517915e2ab688831fd4f2d1a724
文件类型: EXE64（检出 9/21，标记 NukeSped 木马/恶意）
Domain: connection.lockscreen.kro.kr（微步标记“可疑”，注册者 hyon jin park，关联样本涉及 NukeSped 家族）
URL:    http://connection.lockscreen.kro.kr/index.php
```

网络特征：`application/x-www-form-urlencoded` 的 POST、`Content-Length: 41`、`Cache-Control: no-cache` + `Accept: */*`、请求体含 `sid=`/`uid=`（源码另有 `esep=` 字面量，截图运行时首字段显示为 `sep=`）。

## 变体与关联

- **同组织前代武器 FallChill**：2018 年 Operation AppleJeus 中 Lazarus 通过伪造交易软件网站 + 邮件投递 FallChill；本样本功能结构与其相似，域名/URL 特征也类似，是归因依据。
- **投递链背景**：攻击者先渗透海事研究组织的网站维护供应商，窃取 SSH 密钥进入 Web 服务器，用 curl 从 C2 下载 Ngrok 与 Base64 Python 下载器，SSH 横向移动并用 TCPDump 收集凭据，再用窃取的安全经理邮箱账号熟悉 PMS，最终请求 PMS 服务商下发带 NukeSped 的“补丁”。该活动链为二手情报概述，无可复现技术细节，仅作样本背景。
- **同类样本分析卡**：[[code-analysis-reverse-windows-latrodectus-loader-behavior-c2]]、[[code-analysis-reverse-windows-badnews-rat-double-base64-aes-heartbeat]]、[[code-analysis-reverse-windows-asyncrat-string-decrypt-mutex-tls-c2]] 可对比 C2 协议提取与命令分发的分析思路。

## 检测与防御

- **IOC 阻断**：封禁 `connection.lockscreen.kro.kr` 与上述 URL/哈希；在 EDR/AV 中按 NukeSped 家族规则查杀。
- **网络检测**：关注 `Content-Length: 41` 的 `application/x-www-form-urlencoded` POST、请求体 `sid=`/`uid=`/`esep=`（运行时亦见 `sep=`）组合、固定 `Cache-Control: no-cache` + `Accept: */*` 的 WinHTTP 特征；对非常规域名（如 `*.kro.kr` 动态域名）的出站 HTTP 告警。
- **主机检测**：监控 `LoadLibraryA` 加载非系统目录 DLL、`WSAStartup`/WinHTTP 调用与异常进程的文件/进程操作；排查 PMS 补丁包完整性（签名、哈希）与补丁下发来源。
- **供应链侧防御**：供应商 SSH 密钥最小权限与轮换、维护通道 MFA、补丁管理系统服务商侧审计、对邮箱账号异常登录与规则变更监控。
- **威胁狩猎**：用字符串解密算法与 C2 特征扫描内存镜像，结合微步等情报平台关联样本。
