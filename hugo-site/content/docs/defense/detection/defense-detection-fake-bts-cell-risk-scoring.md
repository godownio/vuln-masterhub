---
id: defense-detection-fake-bts-cell-risk-scoring
title: 伪基站检测：终端侧多维评分（制式降级/未鉴权/A5-0/PCI 异常）与网络侧 MR/PCI 异常
type: scenario
domain: defense
path: defense/detection
technique: fake-bts-cell-risk-scoring
tags:
- detection
- mobile
- cellular
- fake-base-station
- imsi-catcher
- risk-scoring
- network-monitoring
- defense
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:17:41+08:00'
  notes: 已对照原文与截图核对：终端侧评分（+40/+35/+30/+25/+15~25/+20，阈值 70/40）、网络侧 S1 释放尖峰+陌生 PCI+TDOA/AOA 与 SQL 均一致；原文无图片；未实际运行。
url: /docs/defense/detection/defense-detection-fake-bts-cell-risk-scoring/
draft: false
kb_aliases:
- 伪基站检测
- IMSI Catcher 检测
- Cell Risk Score
- A5/0 检测
- 陌生 PCI
- MR 异常检测
- 2G 降级告警
- TDOA/AOA 定位
---

## 一句话结论

伪基站检测可以分终端侧与网络侧：终端侧对小区事件做多维加权评分（4G→2G 异常降级 +40、未鉴权 +35、A5/0 +30、RRC 重定向 +25、陌生 PCI/小区冲突 +15~25、RSSI 阶跃 +20），超过阈值告警；网络侧用 S1 释放尖峰 + MR 中不在网规库的 PCI 做时空聚合，再以 TDOA/AOA 精确定位。

## 原理

- 伪基站的核心异常不是单一信号，而是多个维度的组合：网络制式异常回落（4G 突降 2G 且非弱覆盖区）、加密缺失（A5/0）、鉴权异常（未鉴权即收短信）、小区参数突变（LAC/TAC/PCI/BSID）、信号强度阶跃式突变。
- 终端侧评分示例：
  ```text
  制式降级（4G→2G 非弱覆盖）        +40
  未鉴权（GSM 无 Auth）             +35
  未加密（A5/0）                    +30
  RRC 重定向指向 2G                 +25
  LAC/PCI 异常 / RSSI 突变          +15~20
  驻留时间 <5s / 落地即收短信       +10~15
  总分 >=70 高危告警；>=40 静默记录；<40 正常
  ```
- 终端侧数据来源：Android `TelephonyManager`/`CellInfo`（API 17+）可拿到制式、PCI、TAC、信号强度等；鉴权状态、加密算法等底层信令需要通过 Qualcomm DIAG 接口或 MTK Engineer Mode 获取；部分厂商在基带集成检测逻辑，准确率更高但算法不公开。
- 网络侧：运营商有全网视角。S1-MME 事件中某 eNodeB 的 `S1_RELEASE`/`UE_CTX_RELEASE` 在 5 分钟窗口内显著高于历史均值，可能是伪基站导致的批量脱网；MR（Measurement Report）中出现不在网规库中的 neighbor PCI 是强异常；把两者按时间/空间聚合，可区分车载/固定模式，再用 TDOA/AOA 定位到百米级。
- 网络侧 SQL 思路：
  ```sql
  -- 1) 异常脱网
  SELECT time_bucket, enb_id, count(distinct imsi) AS detach_count
  FROM s1mme_events
  WHERE event_type IN ('S1_RELEASE','UE_CTX_RELEASE')
  GROUP BY time_bucket(5min), enb_id
  HAVING detach_count > 3 * historical_avg(enb_id);
  -- 2) 陌生 PCI 关联
  SELECT mr.neighbor_pci, mr.neighbor_rsrp
  FROM measurement_reports mr
  WHERE mr.serving_enb_id IN (<上一步结果>)
    AND mr.neighbor_pci NOT IN (SELECT pci FROM network_plan);
  ```
- 局限性：检测滞后（攻击 5 分钟完成，出警链条数十分钟）；终端碎片化（高通/联发科暴露程度不同）；LTE RRC Reject/Release 携带重定向本身是合法负载均衡行为，难以区分；攻击者会跳频、功控、移动中短暂开启，对抗检测。
- 根因是“空口协议先连接后验证 + 2G 单向认证/不强制加密”，检测只能在行为层做概率判断，不能从协议上根除。

## 触发条件

- 终端侧：能获取 CellInfo/底层信令（应用权限、厂商 API、DIAG/Engineer Mode），并持续监控小区事件。
- 网络侧：运营商/企业拥有 S1-MME、MR、网规 PCI 库与 TDOA/AOA 定位能力。
- 已知合法邻居列表、弱覆盖区域、历史脱网基线，用于降低误报。
- 目标区域存在 2G/3G 回落或伪基站活动；检测策略需按地域/运营商调整。

## 利用步骤（检测侧）

1. 采集小区事件：制式、PCI、TAC/LAC、ARFCN、RSRP/RSSI、鉴权状态、加密算法、驻留时长、是否收到短信。
2. 维护合法邻居/PCI/弱覆盖基线；对每个事件计算加权分数。
3. 分数 >=70 触发高危告警（可能伪基站），>=40 静默记录并聚合；<40 正常。
4. 网络侧并行：检测 S1 释放尖峰、MR 陌生 PCI、同一区域批量脱网；按时间/空间聚合。
5. 对高危区域触发 TDOA/AOA 定位，输出坐标给执法/运维；保留信令证据。
6. 持续更新基线，避免把合法负载均衡/新站开通误判为伪基站。

## PoC

终端侧评分（文章核心逻辑）：

```python
def evaluate_cell_risk(cell_event):
    score = 0
    if cell_event.rat_changed and cell_event.new_rat == '2G':
        if not is_known_weak_coverage(cell_event.location):
            score += 40
        if cell_event.cause == 'redirect':
            score += 25
    if cell_event.rat == '2G':
        if not cell_event.auth_performed: score += 35
        if cell_event.cipher_algo == 'A5/0': score += 30
    if cell_event.pci not in known_neighbor_list: score += 15
    if cell_event.cell_id_conflict: score += 25
    if cell_event.rssi_jump > 15 and cell_event.speed < 5: score += 20
    if score >= 70: return 'ALERT_HIGH'
    if score >= 40: return 'ALERT_MEDIUM'
    return 'NORMAL'
```

网络侧 SQL 见“原理”部分；TDOA/AOA 定位由运营商/无线电监测站完成。

## 变体与关联

- **终端侧变体**：Android CellInfo、Qualcomm DIAG、MTK Engineer Mode、厂商基带检测、iOS 2G 降级告警。
- **网络侧变体**：S1-MME 脱网尖峰、MR 陌生 PCI、TDOA/AOA、路测/网格化 MR、SIM 侧鉴权失败统计。
- **攻击变体**：GSM 伪基站、LTE RRC 重定向、TAU Reject、SIB 伪造、跳频/功控/移动中短暂开启。
- **关联**：[[mobile-gsm-fake-bts-downgrade-sms-injection]]（GSM 侧攻击链）；[[mobile-lte-rrc-redirect-downgrade-gsm]]（LTE 重定向降级）；[[mobile-alter-lte-user-plane-aes-ctr-dns-tamper]]（用户面篡改）；[[defense-detection-sms-otp-flood-terminal-event-correlation]]（短信/终端事件关联检测）。
- **边界**：终端无法获取底层信令、网络无 MR/网规数据、合法重定向与新站开通造成误报、攻击者强对抗时，检测准确率下降。

## 检测与防御

- **检测**：上述评分与 SQL；关注“4G→2G 非弱覆盖 + 未鉴权 + A5/0 + 陌生 PCI + RSSI 阶跃”的组合，而不是单一指标。
- **防御**：加速 2G 退网；终端锁定“仅 LTE/5G”；运营商限制异频重定向到 GSM；5G SA 启用 SUCI/UPIP。
- **加固**：终端基带集成伪基站检测；网络侧建立 MR/PCI 基线；对高危区域做 TDOA/AOA 定位与执法联动。
- **局限**：检测是概率性的，不能替代协议层修复；需持续更新基线、降低误报，并与运营商/执法协同。
