---
id: mobile-lte-rrc-redirect-downgrade-gsm
title: LTE RRC 重定向降级：未完整性保护的 RRCConnectionRelease 携带 redirectedCarrierInfo 把终端赶到 2G
type: scenario
domain: mobile
path: mobile
technique: lte-rrc-redirect-downgrade
tags:
- mobile
- lte
- cellular
- rrc
- downgrade
- fake-base-station
- protocol
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:17:37+08:00'
  notes: '已对照原文与截图核对：预认证 RRC 明文窗口、RRCConnectionRelease redirectedCarrierInfo(geran/ARFCN 100/dcs1800/102,104)、TAU Reject EMM cause #7/#8、srsRAN rrc_conn_release_s 修改点均一致；原文为综述无直接可执行 PoC；未实际运行。'
url: /docs/mobile/mobile-lte-rrc-redirect-downgrade-gsm/
draft: false
kb_aliases:
- RRC Redirect
- redirectedCarrierInfo
- Fake eNodeB
- LTE 降级
- TAU Reject
- srsRAN
- RRCConnectionRelease
- EMM cause 7
---

## 一句话结论

LTE 的双向认证（EPS-AKA）发生在 NAS Attach，而之前的 RRC 连接建立/拒绝/释放信令既不加密也不做完整性保护；伪 eNodeB 可以在 `RRCConnectionRelease` 中携带 `redirectedCarrierInfo`（GERAN/GSM 频点），终端按规范重定向到攻击者的 2G 小区，完成降级劫持；也可以用带特定 EMM cause 的 TAU Reject 让终端拒绝服务。

## 原理

- LTE 的安全上下文在 AS/NAS Security Mode Command 之后才建立；在此之前，MIB/SIB、RRC Connection Request/Setup、RRC Reject/Release、NAS Attach Request 等消息都是明文且无完整性保护。
- 终端必须先完成 RRC 连接，才能进入 NAS Attach/EPS-AKA；这个“预认证窗口”是协议设计上的安全真空。攻击者可在窗口内嗅探 IMSI/IMEI、注入/篡改 RRC/NAS 消息、执行重定向或降级。
- `RRCConnectionRelease` 中的 `redirectedCarrierInfo` 是合法字段，运营商在负载均衡中日常使用；伪 eNodeB 只需把 `geran` 分支的 `startingARFCN`/`bandIndicator` 指向自己的 GSM 小区，终端会按规范执行重定向。
- 终端到达 GSM 后，由 GSM 伪基站完成“不鉴权、不加密、明文 IMSI、伪造短信”的后续攻击（见关联卡）。
- 另一条路径是 `TAU Reject`（Tracking Area Update Reject）携带 EMM cause #7/#8 等，使终端把 USIM 标记为无效、拒绝接入任何网络，形成拒绝服务。
- 根因是“终端先连接、后验证”的协议顺序，以及 RRC 层消息缺乏完整性保护；RRC Reject/Release 本身是合法行为，网络侧很难区分负载均衡与攻击。
- 5G NSA 的控制面锚定在 LTE，上述缺陷完全继承；5G SA 缩小了部分攻击面，但 SIB 仍无完整性保护。

## 触发条件

- 目标终端处于 LTE 覆盖，且支持 2G/3G 回落；未锁定“仅 LTE/5G”。
- 攻击者能部署伪 eNodeB（如 srsRAN + USRP B210）并广播目标 PLMN/TAC，信号强于合法小区。
- 终端会发起 RRC 连接并接受 Reject/Release 中的重定向；目标 GSM 频点由攻击者控制。
- 或者攻击者能发送伪造的 TAU Reject，目标终端/网络未做额外校验。
- 仅限授权安全测试/研究环境；伪基站干扰通信可能违法。

## 利用步骤

1. 侦察目标运营商 PLMN、TAC、频点/带宽、周边 PCI，配置伪 eNodeB（srsRAN 的 `enb.conf`）。
2. 广播 MIB/SIB，等待终端小区重选/驻留并发起 RRC Connection Request。
3. 回复 `RRCConnectionRelease`（或 Reject），在 `redirectedCarrierInfo` 中填入目标 GSM 的 `startingARFCN`、`bandIndicator` 与 ARFCN 列表。
4. 终端按规范重定向到 GSM 频点，驻留到攻击者的 GSM 伪基站；后续执行 GSM 侧的 IMSI 采集/短信伪造。
5. 若目标是拒绝服务，发送带 EMM cause #7/#8 的 TAU Reject，使终端标记 USIM 无效、脱离服务。
6. 释放/超时后终端可能回到合法网络；批量场景可循环。

## PoC

文章给出的是 ASN.1 结构与 srsRAN 配置思路，没有可直接执行的 PoC；关键消息片段：

```asn1
RRCConnectionRelease ::= SEQUENCE {
  rrc-TransactionIdentifier 0,
  criticalExtensions CHOICE {
    c1 CHOICE {
      rrcConnectionRelease-r8 SEQUENCE {
        releaseCause other,
        redirectedCarrierInfo CHOICE {
          geran SEQUENCE {
            startingARFCN 100,
            bandIndicator dcs1800,
            followingARFCNs CHOICE {
              explicitListOfARFCNs { 102, 104 }
            }
          }
        }
      }
    }
  }
}
```

srsRAN 侧只需修改 `rrc_conn_release_s` 的 `redirected_carrier_info` 字段，填入目标 GSM ARFCN 后编译运行；配置示意：

```ini
[enb]
mcc = 460
mnc = 00
n_prb = 25
[sib1]
tac = 0x0001
cell_barred = false
intra_freq_reselection = allowed
```

## 变体与关联

- **消息变体**：RRCConnectionRelease、RRCConnectionReject、TAU Reject、Detach Request、Identity Request（认证前可获取 IMSI）。
- **目标变体**：重定向到 GSM/GERAN、3G/UTRAN、其他 LTE 频点；TAU Reject 造成 DoS；SIB 伪造操纵小区参数。
- **平台变体**：srsRAN/srsENB、Osmocom、商用测试终端；5G NSA 继承 LTE 控制面缺陷。
- **关联**：[[mobile-gsm-fake-bts-downgrade-sms-injection]]（GSM 侧降级后的 IMSI/短信攻击）；[[mobile-alter-lte-user-plane-aes-ctr-dns-tamper]]（LTE 用户面篡改）；[[defense-detection-fake-bts-cell-risk-scoring]]（检测与评分）。
- **边界**：终端锁定 LTE/5G only、运营商禁用异频重定向到 GSM、终端基带检测到异常重定向并拒绝、或伪 eNodeB 信号不足时，本路径失效。

## 检测与防御

- **检测**：终端侧出现非弱覆盖区的 4G→2G 突变、RRC Release 携带异常 redirect、目标 ARFCN 不在邻居列表、PCI/TAC 突变、RSSI 阶跃；网络侧 MR 出现陌生 PCI、S1 释放尖峰。
- **防御**：运营商限制重定向目标（不把 GSM 纳入合法列表）；加速 2G 退网；终端锁定“仅 LTE/5G”；部署伪基站检测。
- **加固**：5G SA/SUCI/UPIP 逐步替代 NSA；对 RRC 消息做异常检测；终端基带集成伪基站识别。
- **合规**：仅可在授权实验室/屏蔽环境研究，遵守无线电管理与刑法规定。
