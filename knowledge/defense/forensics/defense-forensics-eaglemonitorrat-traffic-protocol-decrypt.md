---
id: defense-forensics-eaglemonitorrat-traffic-protocol-decrypt
title: EagleMonitorRAT 通信协议逆向与批量解密：4+1 字节帧头 + BinaryFormatter/QuickLZ/PBKDF2/AES-CBC + 16 字节 GUID 前缀
type: scenario
domain: defense
path: defense/forensics
technique: eaglemonitorrat-traffic-frame-aes-quicklz-decrypt
aliases:
- EagleMonitorRAT 流量解密
- EM-RAT Reborn 协议
- PacketLib 通信解密
- QuickLZ AES CBC RAT 流量
- Rfc2898DeriveBytes 通信密钥
- .NET RAT 批量解密
tags:
- forensics
- traffic-analysis
- c2
- dotnet
- rat
- aes
- quicklz
- binaryformatter
- windows
cve: []
severity: high
confidence: high
affected_versions: EagleMonitorRAT 3.2.4.0（原文分析版本，PacketLib 3.2.4.0）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V402
  verified_at: '2026-11-09T13:13:06+08:00'
  notes: 已对照13951原文448行及19张图核对：图07/08确认4字节小端长度+1字节PacketType的5字节头与分两次send/循环recv，图09确认BinaryFormatter→QuickLZ(level1)→RSMEncrypt链，图10确认Rfc2898DeriveBytes(salt=8×0,iter=1)派生AES key/IV且GUID在前、整体加密，解密后丢弃前16字节再QuickLZ解压，图05确认GClass0 Base64配置(127.0.0.1:9875/7788、key 123456789、%MUTEX%)，图14-18确认BinaryFormatter类型名/成员名/字符串值及解密输出。核对时修正加密链一处措辞：GUID为拼接在待加密明文前整体加密，非'密文前'（已改卡）。affected_versions按原文3.2.4.0分析版本保留并标注非受影响区间。dedup候选为Winos4/BlackNET/Quasar/冰蝎等不同协议，独立卡成立。未验证点：未用真实pcap复跑PoC；QuickLZ库为第三方未验证。
---

## 一句话结论

EagleMonitorRAT（EM-RAT Reborn，C#/.NET 开源远控）的 TCP 通信帧为“4 字节小端载荷长度 + 1 字节 PacketType + AES 密文”；密文用样本配置中的 key 经 `Rfc2898DeriveBytes(password=key 的 UTF-16LE 字节, salt=8 个 0 字节, iterations=1, SHA1, 32 字节)` 派生 AES-128-CBC 的 key/IV 解密，明文为“16 字节随机 GUID + QuickLZ 压缩的 BinaryFormatter 序列化对象”，按此顺序逆向后即可对抓包中的多个会话批量解出上线包、命令与回传数据。

## 原理

- **配置存放**：去混淆后的样本在 `GClass0` 类中以 Base64 常量保存配置：C2 主机列表（如 `127.0.0.1:9875`、`127.0.0.1:7788`）、通信 key（如 `123456789`）、互斥体名（如 `%MUTEX%`），部分配置项以 `Encoding.UTF8.GetString(Convert.FromBase64String(...))` 还原。key 是后续解密的唯一入口，需从样本中提取。
- **功能 DLL**：运行后动态加载 `PacketLib.dll`（数据包封装与加解密）与 `Offline.dll`（离线/对抗功能）；远控功能通过 `Plugins` 目录下 Admin、FileManager、Keylogger、RemoteDesktop、RemoteShell、Stealer、Ransomware 等 DLL 插件动态反射加载，不同插件的包结构不同。
- **帧格式**：发送端先 `send` 5 字节头部再 `send` 载荷；头部前 4 字节为 `BitConverter.GetBytes(payloadLength)`（小端），第 5 字节为 `(byte)data.PacketType`。接收端先收 5 字节，用 `BitConverter.ToInt32(header[0..3])` 得到长度，再循环 `Receive` 直到收满该长度。
- **加密链**：`SerializePacket` = `BinaryFormatter.Serialize` → `QuickLZ.Compress(...,1)` → `RSMEncrypt(..., Encoding.Unicode.GetBytes(key))`。`RSMEncrypt` 用 `new Rfc2898DeriveBytes(key, new byte[8], 1)` 派生 32 字节（前 16 为 AES key、后 16 为 IV），`RijndaelManaged` CBC 加密，并在待加密明文前拼接 16 字节 `Guid.NewGuid().ToByteArray()` 后整体加密。
- **解密链**：`RSMDecrypt` 先对整个载荷做 AES-CBC 解密（含 GUID 块），丢弃解密结果前 16 字节，再 `QuickLZ.Decompress`，最后 `BinaryFormatter.Deserialize` 还原 `PacketLib.Packet.*` 对象。
- **为什么必须从样本取 key**：PBKDF2 的 password 是样本配置中的明文字符串（UTF-16LE），salt 固定 8 个 0、迭代仅 1 次，看似弱，但 key 本身是随机/自定义的；没有样本就无法从流量恢复。拿到 key 后同一家族不同样本仍需确认 key 与 PacketLib 版本。
- **序列化数据的可读性**：BinaryFormatter 流中直接含类型名（如 `PacketLib.Packet.ConnectedPacket`）与成员名（`<HWID>k__BackingField`、`<BaseIp>`、`<Plugin>`、`<PacketType>`、`<Status>`、`<RAM>`、`<Is64Bit>`、`<Privilege>`、`<OSName>`、`<Username>`、`<RegionName>`、`<RegionFlag>`、`<KeylogOffline>`、`<sigKey>` 等）以及字符串值（受控机内存、位数、权限、系统版本、用户名、地区等），因此解密后可直接读出受害者信息与命令内容。

## 触发条件

- 已捕获 EagleMonitorRAT（或同 PacketLib 血统的 .NET RAT）的 TCP 流量（pcap/原始流）。
- 已从样本中还原配置 key（去混淆后读 `GClass0`，Base64 解码）与 PacketLib 版本；不同版本/改版可能调整 KDF 参数或帧头。
- 流量未经过会改变字节流的代理/加密隧道；需要按 TCP 流方向重组出完整帧。

## 利用步骤

1. 去混淆样本，定位 `GClass0`，Base64 解码出 C2、key、互斥体等配置。
2. 从 pcap 按会话/方向提取 TCP 载荷，按“4 字节小端长度 + 1 字节类型 + 长度字节载荷”切帧；也可直接把抓包工具导出的 hex dump 交给脚本。
3. 对每帧载荷：PBKDF2(password=UTF-16LE(key), salt=8×0x00, iter=1, SHA1, 32B) → key=前16B、IV=后16B → AES-128-CBC 解密 → 丢弃前 16 字节 GUID。
4. QuickLZ（level 1）解压剩余数据，得到 BinaryFormatter 序列化流。
5. 用对应 `PacketLib.Packet.*` 类型反序列化（或按 BinaryFormatter 成员名/字符串长度规则手工解析），得到包类型、HWID、系统信息、命令与回传数据。
6. 可编写脚本批量处理目录下多个会话的 hex dump，输出原始帧、PacketType、解密后 hex 与字符串，便于取证与 IOC 提取。

## PoC

Python 解密骨架（QuickLZ 需第三方库；`payload` 为一帧去掉 5 字节头后的密文）：

```python
import hashlib, struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def derive(key_str: str):
    pw = b"".join(bytes([c, 0]) for c in key_str.encode())   # Encoding.Unicode
    dk = hashlib.pbkdf2_hmac("sha1", pw, b"\x00" * 8, 1, 32)
    return dk[:16], dk[16:]

def decrypt_frame(frame: bytes, key_str: str):
    length = struct.unpack("<I", frame[:4])[0]
    ptype = frame[4]
    payload = frame[5:5 + length]
    key, iv = derive(key_str)
    pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(payload), 16)
    guid, qlz = pt[:16], pt[16:]
    return ptype, guid, qlz   # qlz 再 QuickLZ level1 解压 -> BinaryFormatter 流
```

帧头示例（小端长度 + 类型）：`40 02 00 00` 表示载荷 0x240 字节，`02` 为 PacketType。

## 变体与关联

- 变体：同作者的 Xeno-RAT 及 HorusEyesRat 血统的 .NET 远控可能复用相同 `PacketLib`（BinaryFormatter+QuickLZ+PBKDF2+AES-CBC）结构，需核对 DLL 版本与 KDF 参数。
- 变体：不同插件（FileManager/Keylogger/RemoteDesktop/Stealer）对应不同 `PacketLib.Packet.*` 类型，字段不同，需逐个提取结构体再反序列化。
- 关联：其他 .NET RAT 流量解密思路见 [[defense-forensics-njrat-c2-traffic-base64-decode]]、[[code-analysis-reverse-windows-badnews-rat-double-base64-aes-heartbeat]]；同类 .NET 序列化风险见 [[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]。

## 检测与防御

- 流量侧：识别 TCP 会话中“5 字节头 + 高熵载荷”的分帧模式，载荷长度字段与后续数据严格吻合；结合 C2 域名/IP、端口（本例 9875/7788）与样本配置做匹配。
- 主机侧：排查 `PacketLib.dll`、`Offline.dll` 与 `Plugins` 目录（Admin/Stealer/Keylogger/RemoteShell 等 DLL 名称高度特征化）、`GClass0` 配置中的 Base64 字符串与互斥体。
- 取证：拿到样本后用本文流程批量解密历史流量，提取 HWID、用户名、系统版本与命令记录；无样本时难以解密，应优先保全样本与内存。
- 防御：封禁 C2、查杀该家族样本、限制不明 .NET 程序加载外部 DLL 与插件。
