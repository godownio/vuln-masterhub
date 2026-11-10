---
id: code-analysis-dynamic-debugging-miner-pool-address-extraction-static-xmrig-config-dynamic-getaddrinfow-breakpoint
title: 挖矿木马矿池地址提取：静态 IDA 字符串找 xmrig JSON 配置（algo/url 字段）+ 动态 x64dbg 对 ws2_32 网络 API 下断读 RCX
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: miner-pool-address-extraction
aliases:
- 矿池地址提取
- xmrig 配置字符串
- GetAddrInfoW 断点
- ws2_32 API 断点
tags:
- windows
- malware-analysis
- miner
- xmrig
- x64dbg
- ioc-extraction
- ws2_32
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-30
  verified_at: '2026-11-08T15:56:40+08:00'
  notes: 已对照原文核对：静态 IDA 字符串 xmrig JSON 配置含 algo cn/r 与 url 3.120.209.58:8080（img25 及原文代码块）、ws2_32 API 断点列表（img27）、GetAddrInfoW 断点 RCX=L"3.120.209.58"（img30）、GetAddrInfoW 原型与第一参数语义（img29）证据齐全；VT AlphaSOC 报 Miner（img26）佐证；矿池 IOC 与样本 SHA256 已在卡内以判别特征形式蒸馏
---

## 一句话结论

提取挖矿木马矿池/C2 地址有两条不运行样本的稳妥路径：静态上在 IDA 字符串窗口搜 xmrig 风格 JSON 配置，`pools[0].url` 即矿池地址（algo 字段如 cn/r 还可指认币种）；动态上在 x64dbg 对 ws2_32.dll 的 GetAddrInfoW 等网络 API 下断，x64 调用约定下 RCX 即待解析的矿池 IP/域名，二者交叉验证形成 IOC。

## 原理

xmrig 及其魔改版把完整 JSON 配置（api/http/randomx/cpu/pools 等字段）以内嵌常量字符串编译进 .rdata，连接前用该配置初始化，因此字符串窗口直接可见 `"algo": "cn/r"`（CryptoNightR 变种，常用于门罗币）、`"url": "IP:端口"`、`"user"`、`"pass"`、`"donate-level"` 等字段；搜索 invalid string/log 附近的 config JSON 或直接搜 `\"pools\"` 即可定位。动态路径：任何矿池连接都要先把主机名/IP 交给系统解析，Windows 下由 ws2_32.dll 的 GetAddrInfoW 完成，其原型第一个参数 pNodeName 是 NULL 结尾的 Unicode 主机名或点分十进制地址字符串，x64 fastcall 下放在 RCX——在 GetAddrInfoW 入口断下读 RCX 指向的宽字符串即得矿池地址；send/connect/WSASend 等同样可作为断点集交叉印证。相比"直接运行样本抓 wireshark"，断点法可在网络流量真正发出前拦截，风险更低且能拿到回显。

## 触发条件

分析视角：已定性样本为挖矿木马（VT 多引擎报 CoinMiner/XmrigMiner，或 IDA 中见 xmrig::App vtable），需要产出矿池 IOC 时。

## 利用步骤

1. 静态：IDA Strings/Shift+F12 搜索 `"algo"`、`pools`、`url` 或 xmrig 特征 JSON 片段，复制 .rdata 常量，读取 pools[0].url（如 3.120.209.58:8080）；
2. 交叉核验：把 IP 放 VT/微步，安全厂商命中 Miner 类标签（如 AlphaSOC: Miner）即确认矿池；
3. 动态：x64dbg 运行样本，在 ws2_32.dll 的 GetAddrInfoW、connect、send、WSASend、WSAConnect 等全部设断；
4. 断在 GetAddrInfoW 后读 RCX 指向字符串（或在 dump 窗口跟随），得到与静态一致的矿池地址；参数含义对照 MSDN 原型（pNodeName/pServiceName）。

## PoC

无独立 PoC（分析流程卡）。判别示例：某样本 .rdata 内嵌 xmrig 配置片段

```json
"pools": [
  {
    "algo": "cn/r",
    "url": "3.120.209.58:8080",
    "user": "x",
    "pass": "x",
    ...
```

配合 x64dbg 断 GetAddrInfoW 时 RCX 指向 "3.120.209.58"，双法互证。

## 变体与关联

- 配置被加密/混淆时，静态搜不到 JSON，只能走动态断点，或先还原解密函数再 dump 配置内存；
- 矿池走域名而非 IP 时 GetAddrInfoW 的 pNodeName 是域名，还可顺手记录 pServiceName 的端口；走 stratum+tcp 自定义解析时改断 connect/WSAConnect；
- 上游是挖矿木马 dropper 时先按载荷自嵌/自复制卡还原出二阶段，再对二阶段做本卡提取；
- 研判注意：微步等平台显示"安全"不等于不是矿池，多平台比对（VT 任一 Miner 标签）更可靠。

## 检测与防御

- 防御侧同思路可自动化：EDR/沙箱 hook GetAddrInfoW/connect 记录进程外联目标，对"进程首次外联即高频 TCP 长连接"的 host:port 做矿池特征匹配；
- 出口防火墙/威胁情报封禁已知矿池 IP:port 列表；
- 处置时将提取的 url/user（钱包或登录名）落成 IOC，用于关联同家族其他主机。
