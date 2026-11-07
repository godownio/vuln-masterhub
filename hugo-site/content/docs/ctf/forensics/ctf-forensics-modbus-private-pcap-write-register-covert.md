---
id: ctf-forensics-modbus-private-pcap-write-register-covert
title: 私有封装 pcap 剥离与 Modbus 写寄存器隐蔽载荷：双重反转 Base64 还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: modbus-write-register-covert-payload
tags:
- ctf
- forensics
- modbus
- pcap
- ics
- covert-channel
- base64
- traffic-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:44:58+08:00'
  notes: 已对照原文核对；5View 头剥离、功能码 16 载荷与双重反转 Base64 还原一致，响应 Exception 2 不影响取证
url: /docs/ctf/forensics/ctf-forensics-modbus-private-pcap-write-register-covert/
draft: false
kb_aliases:
- 5View 私有封装
- pcap 魔数定位
- Modbus 功能码 16
- 写多个寄存器
- 双重反转 Base64
- 工控流量隐写
---

## 一句话结论

工控 CTF 流量题先看魔数：以 `aa aa aa aa 20 00 00 00` 开头的文件不是标准 pcap，定位内部 `d4 c3 b2 a1` 魔数并切掉封装头后才能用 tshark 解析；在均匀的读请求背景中，唯一的功能码 16 写多寄存器请求携带了“反序 + Base64 + 反序”的隐蔽载荷，按相反顺序剥三层即可还原 flag。

## 原理

- **私有封装遮蔽协议解析**：5View 等采集工具会在标准 pcap 前加自定义头；直接喂 tshark 会报未知格式，必须先定位 libpcap 魔数（小端 `d4 c3 b2 a1`、大端 `a1 b2 c3 d4`）并截取后续字节。
- **背景流量均匀，异常在写方向**：示例 2810 帧中功能码 1/2/3/4 各 702 帧，明显是脚本均匀轮询；功能码 16 仅 2 帧，载荷藏在写寄存器方向。
- **写多寄存器 PDU 结构固定**：功能码 16 后跟起始寄存器号、字计数、字节计数、数据区；示例 `Word Count=25, Byte Count=50`，数据区按字大端拼回 ASCII。
- **双重反转 + Base64**：数据区开头出现 `==`（标准 Base64 的等号只应在尾部），说明整串被反转；反转后得到规范 Base64，解码后再反转得到 flag。正向构造是 `NUL + reverse(base64(reverse(flag))) + 点填充`。
- **为什么成立**：协议允许写任意寄存器值，读写方向与功能码是明文；攻击者/出题人可利用合法字段承载任意字节，而背景流量足以掩盖少量异常帧。

## 触发条件

- 拿到工控协议抓包（pcap/pcapng），但文件头不是标准 libpcap 魔数。
- 协议为 Modbus/TCP 或类似“功能码 + 寄存器值”结构，存在写寄存器/写线圈操作。
- 流量中存在少量写操作，值域/可打印性与正常遥测不同。
- 载荷经过可逆编码（Base64、反转、填充）而非强加密。

## 利用步骤

1. 读前 16 字节确认魔数；若不是 `d4 c3 b2 a1`/`a1 b2 c3 d4`，在文件中搜索这两个魔数并截取到文件尾。
2. 用 tshark 过滤写类功能码（6 单寄存器、15 写线圈、16 写多寄存器），确认哪个方向有数据；示例只有功能码 16 命中。
3. 展开功能码 16 的 PDU：起始寄存器号、字计数、字节计数、数据区；按字大端拼回 ASCII。
4. 观察数据区特征：开头 `==` 说明反转；反转后按 Base64 解码，再反转解码结果。
5. 去掉 NUL 前缀与尾部点填充；检查 flag 格式。
6. 用第二条独立路径（直接在原始字节中搜 PDU 签名并切 MBAP 头）交叉验证；检查响应帧是否 Exception（写入可能被 PLC 拒绝，但载荷已在流量中）。

## PoC

```python
raw = open("modbus.pcap", "rb").read()
off = raw.find(b"\xd4\xc3\xb2\xa1")
if off < 0:
    off = raw.find(b"\xa1\xb2\xc3\xd4")
open("inner.pcap", "wb").write(raw[off:])
```

```bash
tshark -r inner.pcap -Y "modbus.func_code==6"  -T fields -e modbus.regval_uint16
tshark -r inner.pcap -Y "modbus.func_code==15" -T fields -e modbus.coil
tshark -r inner.pcap -Y "modbus.func_code==16" -T fields -e modbus.regval_uint16
```

```python
import base64
s = "==gZsF2Z7lHM19la1NHNfhWY2NzX0hWZfNGMkVWf"   # 50 字节数据区按字大端拼回
b64 = s[::-1]                                   # 反转后是规范 Base64
core = base64.b64decode(b64).decode()
flag = core[::-1]
print(flag)
```

原文实测：还原得到 `flag{y0u_jus4_hav3_the_c0de}`；响应帧 Exception Code 2（非法数据地址）说明 PLC 拒绝了写入，但数据仍在流量中。全流量 2810 帧，功能码 16 仅 2 帧，与均匀的读轮询形成鲜明对比。

## 变体与关联

- **封装变体**：5View、厂商私有头、pcapng 嵌套、压缩/加密容器；先找标准魔数或用 `file`/`binwalk`。
- **协议变体**：Modbus 功能码 6/15/16、DNP3、IEC 104、S7comm；写方向/控制方向优先。
- **编码变体**：Base64 变体、反转、异或、字序交换、点/NUL 填充；先看字符集与填充位置。
- **关联卡片**：[[ctf-forensics-iec104-unauthorized-master-telemetry-covert]]（同类工控隐蔽信道）、[[ctf-forensics-wsl-ext4-vhdx-offline-inspect]]（同篇 CTF 取证）。
- **边界**：若载荷强加密或压缩，需先识别算法；若写入帧极多，需先按值域/可打印性筛选；功能码枚举不全可能漏掉目标。

## 检测与防御

- **CTF 验证**：两条独立路径（tshark 过滤 vs 原始字节切 PDU）还原结果一致；检查响应帧是否 Exception，但不影响从流量还原。
- **工控防御**：对写寄存器/写线圈操作做白名单与审批；监控功能码 6/15/16 的异常频率与值域；部署工控流量审计（源/目的、功能码、寄存器范围）。
- **检测信号**：背景中出现少量写请求；写值超出正常遥测范围；数据区包含 Base64/反转特征；PLC 返回 Exception 但请求已到达。
- **复盘**：先魔数、后功能码、再值域/编码；不要直接相信文件扩展名。
