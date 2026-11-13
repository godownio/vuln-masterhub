---
id: iot-vehicle-can-extended-frame-uds-ecu-discovery
title: CAN 扩展帧 UDS 诊断寻址与 ECU 枚举：遍历 18DAxxF1 发现 ECU 并用 ccplus 做服务扫描
type: scenario
domain: iot
path: iot/vehicle
technique: can-29bit-extended-frame-uds-discovery
aliases:
- 扩展帧 UDS
- 29 位诊断 ID
- 18DAxxF1
- 18DB33F1 功能寻址
- 18DAF1xx 响应
- caringcaribou 扩展帧
- ccplus
- UDS ECU 探测
tags:
- vehicle
- can-bus
- uds
- iso-15765-4
- extended-frame
- ecu
- discovery
- reconnaissance
- caringcaribou
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V524
  verified_at: '2026-11-11T14:44:55+08:00'
  notes: 已对照原文与7张截图核对：OSI 七层/ISO 14229-1/15765-4/11898 分层表、Table5 29位诊断ID(18DB33F1功能寻址/18DAxxF1物理请求/18DAF1xx物理响应)、constants.py 中 ARBITRATION_ID_MIN/MAX(0x700/0x7FF)与 MIN_EXTENDED/MAX_EXTENDED(0x18DA00F1~0x18DAFFF1)、uds.py argparse 的 discovery/auto -E 参数定义(arbitration ID Extend)、uds_discovery(E,...) 函数签名、candump 中 18DAF101 响应与“使用ccplus uds读取did数据”均与卡片一致；PoC 命令 cc.py uds discovery -E / uds auto -E 与原文一致，cansend 手工示例为通用 can-utils 语义。卡片为 UDS 诊断侦察/枚举手法（无漏洞利用声称），severity=medium、confidence=high 合理；原文无车型/版本信息，未设 affected_versions 合理。dedup：iot-vehicle-obd-can-bus-access（OBD物理接入/帧结构）、iot-protocol-uds-routinecontrol-can-injection-takeover（31 01 02 00 注入）、CAN arbitration ID discovery、bisection replay 均非同链；全库 dup-scan 无本卡 pair。关联链接目标均存在。卡片原子、无重复，保留并 verified。
---

## 一句话结论

使用 29 位扩展帧做 UDS 通信的车型，其诊断 ID 按 ISO 15765-4 编码了源/目标地址（`18DAxxF1` 为测试设备发往 ECU #xx 的物理请求，`18DAF1xx` 为 ECU #xx 的响应，`18DB33F1` 为功能寻址广播）；在 `18DA00F1`~`18DAFFF1` 范围遍历发送诊断请求，即可发现总线上响应扩展帧 UDS 的 ECU，再逐项探测服务/子服务展开安全测试。

## 原理

- **CAN 诊断的分层**：CAN 通信同样对应 OSI 模型——数据链路层 ISO 11898、传输/网络层 ISO 15765-4（ISO-TP）、会话层 ISO 14229-2、应用层 ISO 14229-1（UDS）；诊断报文在应用层是 UDS 服务（10/22/27/2E/31 等），由 ISO-TP 分段承载在 CAN 帧里。
- **标准帧与扩展帧的寻址差异**：标准帧 11 位 ID 空间里诊断常用 `0x7xx`（如 0x7E0 请求/0x7E8 响应，按 ECU 顺序 +8 对应），ID 本身不含完整地址语义；扩展帧用 29 位 ID，按 ISO 15765-4 把"测试设备地址 + 目标 ECU 地址"编进 ID。
- **扩展帧诊断 ID 规则**（29 bit，`18DAxxF1`/`18DAF1xx`）：
  - `18DB33F1`：功能寻址（functional），广播给所有 ECU，用于一次性询问；
  - `18DAxxF1`：物理请求，`xx` 为目标 ECU 地址（00~FF），`F1` 是外部测试设备地址；
  - `18DAF1xx`：物理响应，ECU #xx 回给测试设备；
  - 其余字段与标准帧一致，因此遍历 `xx` 即可覆盖所有可能的 ECU 地址。
- **为什么遍历可行**：ISO-TP/UDS 对每个物理请求只有目标地址匹配的 ECU 才回复（正响应或否定响应 `7F`）；测试者在 `18DA00F1`~`18DAFFF1` 上逐个发送诊断请求（如 TesterPresent `3E 00`/会话控制 `10 03`），有响应的 `xx` 即为在线 ECU。功能寻址广播则可在未知地址时快速确认总线是否有 UDS 服务。
- **探测后的测试面**：发现 ECU 后可按 UDS 服务逐步展开——读 DID（`22`）、安全访问种子/密钥（`27`，可爆破/逆向算法）、写数据（`2E`）、例程控制（`31`）、刷写相关服务等；caringcaribou 的 `uds` 模块（ccplus 分支增加 `-E` 扩展帧支持）提供 discovery/auto/services/security_seed/fuzz 等现成能力。

## 触发条件

- 能向车辆 CAN 总线注入帧（OBD-II 物理接入、网关透传或车载网络内其他节点）。
- 目标车型使用 29 位扩展帧进行 UDS 诊断（部分车型标准帧诊断无响应但扩展帧正常，需先用功能寻址或已知 ID 验证）。
- 总线未做诊断报文认证（SecOC）或网关未隔离诊断口；波特率与 CAN 参数已知（常见 500kbps/250kbps）。

## 利用步骤

1. 接入 CAN 总线（OBD 6/14 针 CANH/CANL 等），设置正确波特率，先监听确认总线上存在扩展帧诊断流量。
2. 发送功能寻址请求 `18DB33F1`（如 `3E 00`）确认是否有 ECU 响应；或直接用已知 ID 试探。
3. 遍历 `18DA00F1`~`18DAFFF1`，对每个地址发送诊断请求，记录有响应的 `xx`（响应表现为 `18DAF1xx`）；caringcaribou/ccplus 可用 `cc.py uds discovery -E` 自动化该过程，避免逐个手工发送。
4. 对发现的 ECU 做服务枚举：`cc.py uds auto -E` 自动扫描支持的服务；或手工发 `10 03`（扩展会话）、`22 F1 90`（读 VIN）等验证。
5. 针对感兴趣的服务深入：`27` 安全访问种子提取与密钥算法分析（必要时 fuzz/爆破）、`22` 读 DIDs、`2E`/`31` 写数据与例程控制等，评估能否影响车辆功能。
6. 记录完整的请求/响应 ID、服务与数据，用于复现与后续重放/注入测试。

## PoC

```bash
# caringcaribou 二次开发分支 ccplus：-E 表示 29 位扩展帧诊断
python cc.py uds discovery -E          # 遍历 18DA00F1~18DAFFF1 发现 ECU
python cc.py uds auto -E               # 对发现的 ECU 自动扫描 UDS 服务

# 手工验证（can-utils，扩展帧需要 -e 或接口支持 29bit）
cansend can0 18DB33F1#023E00            # 功能寻址 TesterPresent
cansend can0 18DA10F1#023E00            # 物理请求 ECU #0x10
# 期望响应形如: can0 18DAF110 [8] 02 7E 00 ...
```

关键 ID 对照（ISO 15765-4，29 bit）：

```text
18DB33F1  功能寻址请求（广播，所有 ECU）
18DAxxF1  物理请求：测试设备 -> ECU #xx
18DAF1xx  物理响应：ECU #xx -> 测试设备
遍历范围  18DA00F1 ~ 18DAFFF1
```

说明：原文在部分车型上用标准帧诊断无响应，改以扩展帧遍历后成功发现 ECU，并用改造后的工具读取 DID 数据；上述命令在通用 can-utils/caringcaribou 语义下给出，具体接口名与波特率按车辆调整。

## 变体与关联

- 变体：标准帧车型的诊断 ID 通常为 `0x7E0` 请求/`0x7E8` 响应（每 ECU +8），扩展帧规则不适用时按标准帧枚举。
- 变体：已知某 ECU 地址时可直接探测服务，无需全量遍历；功能寻址在线时可用广播减少请求量。
- 关联：[[iot-vehicle-obd-can-bus-access]]——本卡的前置：OBD 物理接入、CANH/CANL 接线与 11/29 位帧结构。
- 关联：CAN 帧无认证时的重放/注入（伪造车速、车门状态）与诊断协议 fuzz——发现 ECU 之后的攻击面。
- 边界：网关隔离诊断口、SecOC/MAC 认证、诊断会话需先解锁（`27` 服务）或车辆下电时，枚举可能受限；部分 ECU 需功能寻址先唤醒。

## 检测与防御

- 加固：网关隔离诊断口与安全关键总线；诊断报文启用 SecOC/认证；对 `27` 安全访问做密钥强度与尝试次数限制；限制诊断服务白名单。
- 检测：CAN ID 白名单与周期/长度异常检测（IDS）；短时间内对大量 `18DAxxF1` 地址遍历的特征流量；异常的 UDS 服务组合（如连续 `27` 种子请求、`2E`/`31` 写操作）。
- 响应：记录遍历源节点与时间窗，检查是否发生敏感 DID 读取或写操作；必要时物理隔离诊断口并取证。
