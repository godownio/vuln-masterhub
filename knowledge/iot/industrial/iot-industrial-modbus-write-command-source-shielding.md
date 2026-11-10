---
id: iot-industrial-modbus-write-command-source-shielding
title: Modbus/TCP 写命令按来源屏蔽：放行操作员写寄存器、阻断 PLC 自动逻辑，使温度失去自动调节
type: scenario
domain: iot
path: iot/industrial
technique: modbus-tcp-write-command-source-shielding
aliases:
- 自动逻辑屏蔽
- operator_shield
- 屏蔽 PLC 写命令
- Modbus 命令过滤
- 阻断自动温控
- 按 sender 过滤 Modbus
tags:
- iot
- industrial
- modbus
- mitm
- command-filtering
- plc
- scada
- safety-interlock
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T07:55:40+08:00'
  notes: 已对照原文1807行与37张图核对：task_3_3 operator_shield 按 message_get_sender 区分 sentinel：operator 写单/多寄存器置 mode，plc 自动逻辑写命令 illegal_cmd=mode；monitor_shield 的 monitor_route/operator_route 分支与原文一致。与同篇响应篡改卡是不同原子（写命令屏蔽 vs 读响应改写），dup-scan likely_duplicate 裁决保留两卡。原文无组件版本，未设versions。未运行文中服务/PoC。
---

## 一句话结论

在 Modbus/TCP 中间人位置按发送者区分写寄存器命令：操作员的写单寄存器/写多寄存器命令放行，PLC 自动逻辑发出的写命令在操作员操作后被标记为非法并丢弃；自动温控逻辑因此失效，温度只能靠手动调节，真实温度越限时不再自动纠正。

## 原理

- **同一条 Modbus 通道承载两类写命令**：操作员站会向 PLC 写 `set_T`（保持寄存器 40003）或 `heating_S`（线圈 2）等设定/开关；PLC 的自动逻辑也会根据当前温度写加热/停止命令。两者在协议层看起来都是 `0x06`（写单个寄存器/线圈）或 `0x10`（写多个寄存器），仅凭功能码无法区分来源。
- **为什么能按来源过滤**：Modbus/TCP 的 MBAP 头没有身份字段，但中间人能看到 TCP 连接的源 IP/端口、连接建立方向、请求方向，或（在代理/插件架构中）消息的 `sender`/路由信息。文章的实现用 `message_get_sender()` 比较 `operator_sender` 与 `plc_sender`，并用 `mode` 记录“操作员刚下发过写命令”的状态：
  ```c
  char *sender = message_get_sender(recv_msg);
  if (strcmp(sender, operator_sender) == 0) {
      subtype = message_get_subtype(recv_msg);
      if (subtype == SUBTYPE(MODBUS_CMD, WRITE_SINGLE_REGISTER) ||
          subtype == SUBTYPE(MODBUS_CMD, WRITE_MULTIPLE_REGISTERS)) {
          mode = 1;
      }
  } else if (strcmp(sender, plc_sender) == 0) {
      illegal_cmd = mode ? 1 : 0;
  }
  ```
  操作员写命令到达时置位 `mode`；随后 PLC 自动逻辑的写命令被判定为 `illegal_cmd` 并丢弃/拒绝。`monitor_shield` 同样处理监控端的 `ADJUST` 命令：允许操作员，屏蔽监控员的调节。
- **为什么危害大**：自动温控是防止过热的闭环；一旦 PLC 的写命令被持续屏蔽，温度只能靠人工发现并手动干预。若同时篡改读温度响应（见关联卡），操作员看到的还是“安全温度”，闭环和人工两条防线同时失效。
- **状态机细节**：文章用 `mode` 记录操作员是否刚操作；如果不维护这个状态，单纯“屏蔽所有 PLC 写命令”可能导致操作员自己的写命令也被误伤。实际攻击中可按连接、寄存器地址、时间窗或命令频率区分，例如只屏蔽 `heating_S` 线圈或 `set_T` 保持寄存器的自动写入。
- **前提**：攻击者能中间人（ARP 欺骗、控制交换机/网关、恶意协议插件/代理），能识别请求来源，并且 PLC 的自动逻辑与操作员命令共享同一 Modbus 路径。

## 触发条件

- 目标使用明文 Modbus/TCP，PLC 自动控制逻辑与操作员站共享同一网络/网关路径。
- 攻击者处于可拦截并转发 Modbus 请求的中间人位置，能区分“操作员站”和“PLC 逻辑”的来源（IP/端口/连接/消息 sender）。
- 自动安全逻辑依赖 PLC 发出的写寄存器/线圈命令；没有独立的硬接线联锁或 SIS。
- 目标没有对 Modbus 写命令做源认证/完整性校验（如 Modbus/TLS、IPsec、白名单）。

## 利用步骤

1. 摸清寄存器映射与命令流向：操作员写 `set_T`/`heating_S`，PLC 自动逻辑写哪些寄存器/线圈，功能码是 `0x06` 还是 `0x10`。
2. 在中间人位置解析 Modbus/TCP 请求（MBAP + PDU），识别功能码与目标地址。
3. 按来源标记：操作员的写命令放行并置 `mode`；PLC 自动逻辑的写命令在 `mode` 置位时丢弃/拒绝（或改写为无害值）。
4. 只屏蔽关键寄存器/线圈（如加热控制），保留其他业务写命令，降低被发现的概率。
5. 与响应篡改组合：让操作员看到安全温度，同时阻断自动降温/加热逻辑，使真实温度持续偏离。
6. 观察操作员是否手动干预；若没有，维持屏蔽直到目标状态达成（授权测试中应立即停止）。

## PoC

文章参考实现（框架内按 sender 过滤）：

```c
char *sender = message_get_sender(recv_msg);

if (strcmp(sender, operator_sender) == 0) {
    subtype = message_get_subtype(recv_msg);
    if (subtype == SUBTYPE(MODBUS_CMD, WRITE_SINGLE_REGISTER) ||
        subtype == SUBTYPE(MODBUS_CMD, WRITE_MULTIPLE_REGISTERS)) {
        mode = 1;
    }
} else if (strcmp(sender, plc_sender) == 0) {
    illegal_cmd = mode ? 1 : 0;
}
```

```c
// monitor_shield：允许操作员的 ADJUST，屏蔽监控员的 ADJUST
if (strcmp(monitor_route, msg_head->route) == 0) {
    if (plc_cmd->action == ACTION_ADJUST) {
        illegal_cmd = 0;
        mode = 1;
    }
} else if (strcmp(operator_route, msg_head->route) == 0) {
    illegal_cmd = (mode == 1) ? 1 : (mode == 0) ? 0 : illegal_cmd;
}
```

Python 伪代码（按源 IP/端口过滤写命令）：

```python
def forward_modbus(req: bytes, src_ip: str, operator_ips: set, plc_ips: set, state: dict):
    func = req[7]  # MBAP 头后的功能码
    is_write = func in (0x06, 0x10)
    if is_write and src_ip in operator_ips:
        state["operator_wrote"] = True
        return req                     # 放行操作员
    if is_write and src_ip in plc_ips and state.get("operator_wrote"):
        return None                    # 丢弃 PLC 自动逻辑写命令
    return req
```

## 变体与关联

- **过滤维度变体**：按源 IP/端口、TCP 连接方向、寄存器地址（只屏蔽加热线圈 2/`set_T` 40003）、命令频率或时间窗；也可只屏蔽“自动逻辑”特有的写序列。
- **动作变体**：丢弃、延迟、改写为无害值、重放旧的“停止加热”命令；与响应篡改组合可同时欺骗显示和执行。
- **位置变体**：交换机/网关 ACL、透明代理、恶意协议插件、工控防火墙规则；只要能解析 Modbus PDU 即可。
- **关联**：[[iot-industrial-modbus-read-input-register-response-tamper]]（同一 MITM 位置篡改温度读数，两者组合使显示与自动控制同时失效）、[[iot-industrial-scada-snapshot-mmap-state-forgery]]（状态文件层的传感器/执行器欺骗）、[[iot-industrial-s7comm-elevator-multi-db-state-forgery]]（PLC 状态伪造）。
- **边界**：PLC 使用独立硬接线安全联锁、SIS、Modbus/TLS 或写命令源认证时，单纯屏蔽不成立；若操作员频繁手动干预，攻击窗口会缩短。

## 检测与防御

- **协议层**：使用 Modbus/TLS、IPsec/VPN、工业防火墙白名单，限制哪些主站可以写哪些寄存器/线圈；不要把 Modbus/TCP 暴露在不可信网络。
- **监测**：对写命令的来源、频率、目标地址建立基线；检测“操作员写入后 PLC 自动写命令突然消失/被拒绝”的模式；监控温度与执行器动作的相关性。
- **架构**：安全联锁不依赖可被中间人篡改的 Modbus 写命令，使用独立硬接线/SIS；关键设定值双人复核；对操作员/监控员操作做审计。
- **检测**：同一 PLC 的自动调节写命令长期缺失，但温度持续偏离设定值；网络中出现拒绝/丢弃 Modbus 写请求的中间设备；操作员看到的显示值与现场仪表不一致。
