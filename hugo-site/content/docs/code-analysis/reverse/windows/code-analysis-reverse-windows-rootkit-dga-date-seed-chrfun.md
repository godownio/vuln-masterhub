---
id: code-analysis-reverse-windows-rootkit-dga-date-seed-chrfun
title: Rootkit 日期种子 DGA 回退：主 C&C 域名不可用时用系统时间作种子，经 chrfun1..8 映射生成 .com 域名
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: rootkit-date-seeded-dga-chrfun-fallback
tags:
- reverse
- windows
- kernel
- rootkit
- dga
- c2
- malware-analysis
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:37:51+08:00'
  notes: 已对照原文 content.md 与 33 张图片逐项核对（Festi 样本分析）；六卡分别对应文件系统过滤隐藏/SSDT 注册表隐藏/直发 IRP 通信/.cdata XOR API 名/DR 寄存器反调试/日期种子 DGA，各自技术原子独立、判为原子粒度合格；与 dup-scan 中同文 related pair 并列保留（机制与触发不同）；未动态运行驱动/样本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-rootkit-dga-date-seed-chrfun/
draft: false
kb_aliases:
- DGA 域名生成算法
- 日期种子 DGA
- chrfun_X 映射
- .com 域名回退
- Festi DGA
- C&C 域名回退
---

## 一句话结论

Festi 的配置里有三种域名模式：`v2==1` 用固定域名 `ultrabukbuk.ru`，`v2==2` 走 DGA，否则用 `domain1.com`；当主 C&C 域名不可用时，代码把当前系统时间（`f_Get_current_system_time` 返回值，含日/时/分等字段）作为种子，经 `sub_11B2A`/`sub_11648` 等混合后，用 `chrfun1..chrfun8` 预定义映射把每个种子值转成字符，拼成短 `.com` 域名，使僵尸网络在主域名被 takedown 后仍能通过 DGA 找回控制端。

## 原理

- **DGA 的作用**：主 C&C 域名被注册商/执法查封后，bot 无法回连；DGA 按时间生成一批候选域名，攻击者只需注册当天可预测的域名即可恢复控制，bot 逐个尝试。
- **种子与映射**：`sub_1BDD5(v6, HIDWORD(v6), v6 - current_system_time)` 在协议处理失败/定时路径被调用；`sub_1A3AE` 接收时间结构（`this[0..2]` 为日期/时间字段）与 `BugCheckParameter2` 等参数，`v13 = v14 ^ BugCheckParameter2`，再调用 `sub_11B2A`（可能是哈希/混合）、`sub_11648`、`sub_11ACB` 产生 8 组索引；每组减 0x30（`- 48`）后查 `chrfun1..chrfun8` 映射表得到字符；最后 `a2[8] = 0` 结束。文章称生成 12 字符 `.com` 域名，但反编译片段显示 a2[0..8] 映射，实际长度/字符集应以样本与映射表为准。
- **配置分支**：`sub_1BCAE` 根据 `*(this + 156)`：1 → 复制 `ultrabukbuk.ru`；2 → 调 DGA（`sub_1A3AE`）；其他 → `domain1.com`。说明 DGA 是主域名/固定域名失败后的回退/备用通道。
- **可预测性**：种子是系统时间（日期/时间），攻击者和分析者可在已知时间窗口内复现候选域名；防御方可用时间窗口枚举 + sinkhole/域名注册监控。
- **局限**：DGA 依赖系统时间，时间被篡改/沙箱时间不同会生成不同域名；映射函数/字符集随样本版本变化，需逆向确认。

## 触发条件

- 样本为内核 rootkit/bot，配置中包含主域名/备用域名与 DGA 模式；主 C&C 不可达或配置指定 DGA。
- 目标系统时间可用（`KeQuerySystemTime`/`f_Get_current_system_time`），且 DGA 代码未加壳/可定位。
- 分析者需要复现 C&C 候选域名、做 sinkhole/流量检测；或防御方需要预测 DGA 域名。
- 仅用于授权恶意样本分析/防御研究。

## 利用步骤

1. 静态定位配置解析 `sub_1BCAE`：确认 `v2` 分支（1 固定域名、2 DGA、其他默认域名）与字符串 `ultrabukbuk.ru`、`domain1.com`。
2. 定位 DGA 入口 `sub_1BDD5`/`sub_1A3AE`：确认时间种子来源（`f_Get_current_system_time` 返回结构）、`BugCheckParameter2` 等常量。
3. 还原 `sub_11B2A`/`sub_11648`/`sub_11ACB` 的混合逻辑与 `chrfun1..8` 映射表（从 `.data`/`.cdata` 提取），实现等价 Python 生成器。
4. 用样本/沙箱的系统时间（注意时区/UTC）生成候选域名；在已知时间窗口内枚举前后若干天，得到 DGA 域名列表。
5. 验证：动态调试 `sub_1BDD5` 或解析出的域名字符串，确认与生成器一致；对域名做被动 DNS/证书透明查询，评估是否被注册/使用。
6. 防御：把候选域名加入 sinkhole/威胁情报，监控 DNS 请求；对内核驱动的 DGA 代码做 YARA 特征。

## PoC

无漏洞利用 PoC；以下为按文章逻辑重写的 DGA 生成骨架（未对样本实跑，混合函数/映射表需从样本提取）：

```python
# 伪代码：时间种子 -> 混合 -> chrfun 映射 -> .com
def dga(system_time, bugcheck_param2, mix, chrfun):
    v14 = system_time          # 含日期/时间字段
    v13 = v14 ^ bugcheck_param2
    idx = mix(v13)             # 对应 sub_11B2A/sub_11648/sub_11ACB
    out = ''.join(chrfun[i](idx[i] - 48) for i in range(8))
    return out + ".com"

# 配置分支
# mode == 1 -> "ultrabukbuk.ru"
# mode == 2 -> dga(...)
# else      -> "domain1.com"
```

## 变体与关联

- 变体：种子可换成 `KeQuerySystemTime`、`RDTSC`、PID/卷序列号等；映射可用字符表/模运算/哈希，而非 `chrfun` 函数数组。
- 变体：DGA 可生成多个 TLD/多级域名、按天/小时分桶；也可与 DGA 种子加密/签名结合，只有攻击者能预测。
- 变体：主域名可用时 DGA 不触发（文章配置分支），分析时需强制走 `v2==2` 或断网触发。
- 关联：[[code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file]]（同一样本的文件隐藏）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（注册表隐藏）、[[code-analysis-reverse-windows-driver-cdata-xor-api-resolution]]（同一样本的加密 API 名）。

## 检测与防御

- 检测：DNS 日志中检测时间相关的伪随机域名模式（长度/字符集/TLD 固定、按天变化）；用 DGA 分类器/时间窗口枚举匹配；对驱动/样本做 `chrfun`/时间种子特征 YARA。
- 防御：sinkhole 候选域名、注册监控、DNS 过滤；限制/监控未知域名解析；对失陷主机做内存/驱动取证，提取 DGA 种子与映射表。
- 说明：本文是 rootkit DGA 回退机制分析，severity 记为 low，confidence 记为 medium（文章称 12 字符，但反编译片段显示 a2[0..8] 映射，实际长度需按样本确认）；仅用于授权样本分析。
