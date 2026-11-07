---
id: ctf-forensics-opcua-string-segmented-base64-c2-results
title: OPC UA 流量中分段 Base64 C2 结果重组：String 节点提取 + JSON 命令还原
type: scenario
domain: ctf
path: ctf/forensics
technique: opcua-string-segmented-base64-c2-reassembly
tags:
- ctf
- forensics
- opcua
- ics
- base64
- c2
- pcap
- traffic-analysis
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/ctf/forensics/ctf-forensics-opcua-string-segmented-base64-c2-results/
draft: false
kb_aliases:
- OPC UA 取证
- opcua.String
- RESULT-SEG
- 分段 Base64
- C2 命令结果
- tshark OPC UA
---

## 一句话结论

OPC UA 的 ReadResponse 可以在 `String` 类型的节点值里携带任意文本；当值呈现 `节点前缀-SEGxx-<Base64>` 形式时，说明命令输出被切成多段 Base64 外传。用 `tshark -Y "opcua.String" -T fields -e opcua.String` 提取所有字符串，按块前缀分组、按 SEG 序号拼接、Base64 解码，即可还原 JSON 格式的 `cmd/output/returncode/timestamp` 命令结果；若后续还有 `sed` 等修改命令，按时间顺序应用后得到最终内容。

## 原理

- **OPC UA String 变体**：DataValue 的 Variant 可以是 `String`，正常业务用它传设备名、状态文本；协议不限制内容，攻击者可把 C2 命令输出编码后塞进节点值，借合法 OPC UA 读/写流量外传。
- **分片原因**：单次读响应/节点值有长度限制，且长 Base64 更容易触发 DLP 规则；按固定大小切成 `SEG01`、`SEG02`… 并在每段前加统一前缀（如 `REACTOR-001-SEG01-`），接收端可按前缀和序号重组。
- **Base64 解码后是 JSON**：命令结果通常结构化（id、cmd、output、returncode、success、timestamp），Base64 只是传输编码；解码后可直接 JSON 解析，按 timestamp 排序即可还原攻击者执行命令的时间线。
- **噪声与损坏**：实际抓包里会混入 `运行中`、`NORMAL`、时间戳等状态字符串，分段之间可能被这些行打断；个别段可能因抓包截断/显示错误损坏（例如段值只剩一个字符），需要从上下文或日志补回。
- **为什么成立**：OPC UA 的节点值和字符串字段是明文的，tshark 能按字段导出；Base64 是自描述的 4→3 字节编码，按段拼接后解码即可恢复原始 JSON。

## 触发条件

- 有 OPC UA 抓包（端口 4840 或自定义），且节点值中包含长字符串/Base64。
- 字符串呈现统一前缀 + `SEG`/序号模式，或同一节点被多次读/写。
- 需要还原命令执行结果、C2 任务或外传数据。
- 分段可能被打断/损坏，需要容错解析。

## 利用步骤

1. 先确认 OPC UA 流量：`tshark -r ics_c2.pcap -Y "opcua" -T fields -e ip.src -e ip.dst -e opcua.String`。
2. 导出所有 String 字段：`tshark -r ics_c2.pcap -Y "opcua.String" -T fields -e opcua.String > output.txt`。
3. 观察模式：找出统一前缀（节点名/设备名）和 `SEG01`、`SEG02`… 序号；记录每段对应的块/命令 ID。
4. 按块分组，按 SEG 序号拼接 Base64（忽略 `运行中`、时间戳、`NORMAL` 等非段行）；对长度不足 4 的倍数补 `=`。
5. Base64 解码并尝试 JSON 解析；按 `timestamp` 排序，读取 `cmd` 与 `output`。
6. 若后续命令包含 `sed -i 's/.../.../'` 等修改，按时间顺序应用到已得到的内容，得到最终值。
7. 对疑似损坏的段，结合同块其它段、响应长度、抓包重传或设备日志补回；不要直接丢弃整块。

## PoC

```python
import base64, json, re

lines = open("output.txt", encoding="utf-8", errors="ignore").read().splitlines()

# 示例：REACTOR-001-SEG01-eyJpZCI6...
seg_re = re.compile(r"^(?P<prefix>.+?)-SEG(?P<seq>\d+)-(?P<data>[A-Za-z0-9+/=]+)$")
blocks = {}
for line in lines:
    m = seg_re.match(line.strip())
    if m:
        key = m.group("prefix")
        blocks.setdefault(key, []).append((int(m.group("seq")), m.group("data")))

for key, segs in blocks.items():
    b64 = "".join(data for _, data in sorted(segs))
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    try:
        obj = json.loads(base64.b64decode(b64).decode("utf-8"))
        print(key, obj)
    except Exception as exc:
        print(key, "decode failed:", exc)
```

说明：前缀和 SEG 格式以实际抓包为准；有的实现把块头单独放在另一条 String 里，需要按时间/请求 ID 关联。

## 变体与关联

- 变体：用 OPC UA Method Call 的参数/返回值承载 Base64，而非节点值；按 `opcua` 方法字段过滤。
- 变体：分片用十六进制、URL-safe Base64 或压缩后 Base64；解码前先反转/解压。
- 变体：同类分片外传也出现在 Modbus 寄存器、S7 DB、MMS 变量、DNS TXT 中，重组思路相同。
- 关联：[[ctf-forensics-modbus-private-pcap-write-register-covert]]（Modbus 写寄存器承载编码载荷）；[[ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb]]（pcap 中多协议 Base64 取口令）；[[iot-industrial-iec104-unauthorized-master-telemetry-covert-channel]]（遥测值隐蔽信道）。

## 检测与防御

- 检测：OPC UA 节点值出现长 Base64、统一前缀 + SEG 序号、异常高频读写；正常业务字符串通常短且可读。
- 检测：同一客户端对非业务节点做 Read/Write，或读响应大小与业务不符；结合会话时长、源 IP、证书变更。
- 防御：OPC UA 深度包检测与节点白名单；只允许业务需要的节点读写；对 String 长度/字符集做限制。
- 防御：启用 OPC UA 安全策略（签名/加密）并审计会话；对异常 Base64 外传做 DLP 与告警。
