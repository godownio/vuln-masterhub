---
id: mobile-gsm-fake-bts-downgrade-sms-injection
title: GSM 伪基站降级劫持：单向认证 + LAC 变化触发位置更新，明文 IMSI 与伪造短信下发
type: scenario
domain: mobile
path: mobile
technique: gsm-fake-bts-downgrade-sms-injection
tags:
- mobile
- gsm
- cellular
- fake-base-station
- imsi
- sms
- downgrade
- protocol
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:17:36+08:00'
  notes: 已对照原文与 8 张截图核对：GSM 单向认证、LAC 变化触发 Location Updating、明文 IMSI、跳过 Authentication/Ciphering、SMS-DELIVER 伪造 95588、Qhyst/信号差论述均一致；原文为综述无直接可执行 PoC，卡片已如实标注；未实际运行。
url: /docs/mobile/mobile-gsm-fake-bts-downgrade-sms-injection/
draft: false
kb_aliases:
- 伪基站
- IMSI Catcher
- Fake Base Station
- GSM 单向认证
- Location Updating Request
- SMS-DELIVER 伪造
- OsmoNITB
- 2G 降级
---

## 一句话结论

GSM 只做“网络认证终端”的单向认证，终端不认证基站；伪基站只要广播与目标运营商相同的 PLMN、不同的 LAC，就能让终端触发 Location Updating Request 并以明文送出 IMSI，随后跳过 Authentication/Ciphering，直接下发伪造发送号码的 SMS-DELIVER，实现短信钓鱼与身份采集。

## 原理

- GSM 鉴权使用 A3/A8 与预共享密钥 Ki：网络下发 RAND，SIM 计算 SRES 回送，网络比对后用 Kc 加密空口。整个流程只验证终端，终端没有任何机制验证基站是否合法；只要 BCCH 广播的系统信息看起来合规、频点/PLMN 合理，终端就会按 3GPP 小区选择流程驻留。
- 终端驻留后是否发起位置更新，取决于 LAC（Location Area Code）：伪基站把 LAC 设为与合法网络不同，终端发现“位置区变化”，就会发起 Location Updating Request；该消息中的 Mobile Identity 通常是 IMSI（或 TMSI，伪基站可用 Identity Request 强制要 IMSI），在空口明文传输。
- 伪基站可以选择不鉴权（GSM 标准允许）和不加密（A5/0）：终端无法拒绝一个不要求鉴权、不启用加密的网络，主动权完全在网络侧。
- 伪基站随后直接回 Location Updating Accept，并下发 SMS-DELIVER；`TP-Originating-Address` 可伪造成银行/运营商号码（如 95588），终端短信界面按该号码显示，形成“官方短信”钓鱼。
- 信号条件：合法宏站 46 dBm EIRP 在 300m 处约 -74 dBm；伪基站 10 dBm 在 10m 处约 -58 dBm，差值 +16 dB，远超小区重选滞后 Qhyst 的典型 2~4 dB，因此近距离裸 SDR 板卡即可让终端重选到伪基站。
- 硬件/协议栈：USRP B210、bladeRF 2.0、LimeSDR、HackRF 等 SDR；GSM 侧可用 Osmocom 的 OsmoNITB（BTS/BSC/MSC/HLR 集成）快速搭建完整网络。
- 根因是 GSM 空口信任模型的结构性缺陷：终端“先连接、后（且只被）认证”，且 2G 不强制加密；这不是某个实现的 bug，而是标准遗留问题。

## 触发条件

- 目标终端处于 GSM（2G）覆盖，且未锁定“仅 LTE/5G”，支持回落 2G。
- 攻击者能部署 SDR + GSM 协议栈，广播与目标运营商一致的 PLMN、不同 LAC，并在目标附近提供足够强的信号。
- 目标终端会执行小区重选/位置更新；伪基站能读取空口明文信令。
- 目标运营商 2G 网络仍在运行；终端基带未集成伪基站检测或检测被绕过。
- 仅限授权安全测试/研究环境；伪基站干扰通信在许多司法辖区属违法行为。

## 利用步骤

1. 环境侦察：用 `srsue` 的 cell_search、`kalibrate-rtl` 等扫描周边合法基站的频点、PLMN、LAC、PCI/BSIC、带宽，确定目标运营商参数。
2. 配置伪基站：PLMN 设为目标运营商（如 MCC=460、MNC=00），LAC 设为不同值以触发位置更新，选择不冲突的频点/BSIC；GSM 侧可用 OsmoNITB。
3. 广播 BCCH/系统信息，等待终端小区重选并驻留；监控 RACH/SDCCH 上的 Location Updating Request。
4. 从请求中提取 IMSI/IMEI（必要时发 Identity Request 强制 IMSI），记录终端身份。
5. 跳过 Authentication Request 与 Ciphering Mode Command（A5/0），直接回 Location Updating Accept。
6. 下发 SMS-DELIVER，伪造 `TP-Originating-Address` 与短信正文；终端显示为官方号码。
7. 释放信道/让终端超时回到合法网络；批量场景下每个终端交互仅几百毫秒到几秒。

## PoC

文章给出的是协议流程与 Wireshark gsmtap 解码特征，没有可直接执行的伪基站 PoC；关键信令序列：

```text
UE -> Fake BTS : Location Updating Request (IMSI 明文)
Fake BTS -> UE : Location Updating Accept   （无 Authentication Request）
Fake BTS -> UE : CP-DATA / RP-DATA / SMS-DELIVER
                  TP-Originating-Address: 95588
                  TP-User-Data: "【银行】..."
```

三个异常标记：

```text
1. 没有 Authentication Request/Response 交互
2. 没有 Ciphering Mode Command（A5/0）
3. 全程仅 2~3 秒
```

OsmoNITB/srsRAN 配置要点（示意，非完整可运行配置）：

```ini
# PLMN 与目标运营商一致，LAC 与合法网络不同
mcc = 460
mnc = 00
lac = 0x1A2F
# 不启用鉴权/加密（研究环境）
```

## 变体与关联

- **身份变体**：IMSI 明文、TMSI + Identity Request、IMEI 采集；3G 也可在认证前通过 Identity Request 获取 IMSI。
- **短信变体**：伪造银行/运营商号码、钓鱼链接、验证码拦截、USSD/闪信；短信内容可定制。
- **降级变体**：从 LTE 通过 RRC 重定向到 GSM（见关联卡）；3G 降级；5G NSA 继承 LTE 缺陷。
- **平台变体**：OsmoNITB、OpenBTS、srsRAN（LTE）、USRP/bladeRF/LimeSDR/HackRF。
- **关联**：[[mobile-lte-rrc-redirect-downgrade-gsm]]（LTE 侧把终端赶到 2G 的重定向）；[[mobile-alter-lte-user-plane-aes-ctr-dns-tamper]]（LTE 用户面篡改）；[[defense-detection-fake-bts-cell-risk-scoring]]（伪基站检测）。
- **边界**：目标锁定 LTE/5G only、运营商关闭 2G、终端基带具备伪基站检测并拦截、或攻击者信号不足以压过宏站时，本路径失效。

## 检测与防御

- **检测**：终端侧出现 4G→2G 异常回落、A5/0、未鉴权即收短信、LAC/PLMN/BSIC 突变、RSSI 阶跃；网络侧 MR 出现陌生 PCI、S1 释放尖峰、TDOA/AOA 定位。
- **防御**：加速 2G 退网；终端锁定“仅 LTE/5G”；运营商限制异频重定向到 GSM；部署伪基站检测与告警。
- **用户侧**：对来路不明的“官方短信”保持警惕，不点链接、不回验证码；通过官方 App/客服核实。
- **合规**：伪基站会干扰公共通信，仅可在授权实验室/屏蔽环境研究，遵守当地法律。
