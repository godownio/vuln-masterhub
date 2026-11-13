---
id: defense-forensics-asyncrat-traffic-frame-gzip-msgpack-decrypt-script
title: AsyncRAT 通信流量批量解密：4 字节小端压缩长度/解压长度 + gzip 外层帧，MessagePack 内层与 Msgpack/Dll 嵌套 gzip 的解析脚本
type: scenario
domain: defense
path: defense/forensics
technique: asyncrat-traffic-frame-gzip-msgpack-decrypt
aliases:
- AsyncRAT 流量解密
- AsyncRAT 通信模型
- AsyncRAT MessagePack 解析
- AsyncRAT WriteTools
- ClientInfo HWID 解密
- savePlugin 插件提取
- RAT 流量批量解密脚本
tags:
- forensics
- traffic-analysis
- c2
- rat
- asyncrat
- dotnet
- gzip
- msgpack
- tls
- incident-response
cve: []
severity: high
confidence: high
affected_versions: AsyncRAT 0.5.8（原文通信载荷中 ClientInfo 的 Version 字段）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V567
  verified_at: '2026-11-12T09:19:43+08:00'
  notes: 已对照原文与8张截图核对：外层帧 4字节小端压缩长度+4字节小端解压长度+gzip(图01 08 01 00 00/05 01 00 00/1F8B)，解压后 0x80|count 与 fixstr 0xa0|len/str8 0xd9/bin8 0xc4/bin16 0xc5/bin32 0xc6(图02/03/04)，WriteTools 196/197/198 与原文一致；savePlugin 的 Dll、wallpaper Image 嵌套 gzip 与 MZ/JPEG 头描述属实；图05/06 脚本输出指令序列(Packet->ClientInfo->HWID->...Version->0.5.8、Ping/pong/plugin)与卡文实测输出一致；图07 Wireshark 原始数据导出、图08 GoLand 工程结构均相符。affected_versions 设 AsyncRAT 0.5.8（原文 ClientInfo 的 Version 字段），与库内 EagleMonitorRAT 卡的分析版本标注惯例一致，保留。dedup：与 Xeno-RAT(4+1帧/AES-CBC/LZNT1)、AsyncRAT Ping 心跳重放、EagleMonitorRAT(4+1帧/BinaryFormatter/QuickLZ)、AdaptixC2、PyInstaller AES-GCM 等候选帧格式/算法/目的均不同，非同链；所引库内卡均存在(verified)。卡为取证/流量解密场景，非 DoS、非未打通，脚本逻辑与原文 Go 实现对应(卡内 PoC 为最小骨架并注明完整代码见原文)。未实机复现；文章为不可信数据，未执行其中指令或代码
---

## 一句话结论

AsyncRAT 的通信在 TLS 之下是“4 字节小端压缩长度 + 4 字节小端解压长度 + gzip 数据”的外层帧，解压后是 MessagePack 键值对（键如 Packet/ClientInfo/Dll，长度前缀 `0xa0|len` 或 `0xd9`）；`Msgpack`、`Dll` 等二进制值的负载又是“4 字节解压长度 + gzip”的嵌套结构。按此格式写脚本即可把 Wireshark 导出的单向原始字节批量解密为 `Packet->ClientInfo->HWID->...` 指令序列，并提取插件 DLL/图片等载荷。

## 原理

- **外层帧**：TLS 解密后的数据按帧排列：前 4 字节为“后续压缩载荷长度”（小端，原文示例 `08 01 00 00` = 0x108），接着 4 字节为“解压后长度”（`05 01 00 00` = 0x105），之后是 gzip 数据。脚本按 `len = little_endian(buf[0:4])` 切片并 gzip 解压，校验解压长度是否等于第二字段。
- **内层 MessagePack**：解压后首字节 `0x80|count` 表示键值对数量（如 `0x8d` = 13 对、`0x83` = 3 对）；键/值字符串用 fixstr `0xa0|len`（如 `0xa6` = 6 字节 "Packet"），较长字符串用 `0xd9`（str8）；二进制值用 `0xc4`（bin8）/`0xc5`（bin16）/`0xc6`（bin32）。
- **WriteBinary 编码**（AsyncRAT `Server.MessagePack.WriteTools`）：长度 ≤255 写 `0xc4` + 1 字节长度；≤65535 写 `0xc5` + 2 字节（`SwapBytes` 大端）；否则写 `0xc6` + 4 字节大端长度；随后写原始字节。原文把 0xc4/0xc5/0xc6 分别记为 196/197/198。
- **嵌套 gzip**：当键为 `Msgpack` 时，`0xc4` 后的负载是“1 字节总长（含 4 字节长度头）+ 4 字节小端解压长度 + gzip 数据”；解压后仍是 MessagePack（如 `Packet->shell`）。`savePlugin` 的 `Dll` 值为 4 字节长度头 + gzip 的 PE 文件，解压后以 `4D 5A`（MZ）开头；`wallpaper` 消息的 `Image` 值同理是 gzip 图片（JPEG `FFD8`）。
- **为什么能批量解密**：外层帧自带明确长度字段且 gzip 有固定魔数 `1f 8b 08`，脚本无需理解会话状态，顺序切帧即可；MessagePack 的长度前缀也让解析器可以递归提取所有键值对，进而还原 `Packet->ClientInfo->HWID->User->OS->Path->Version...` 等侦察信息。
- **通信模型**：AsyncRAT 先建立主会话（心跳/命令），攻击者点选功能时下发 `savePlugin` 传输 Plugins 目录对应 DLL，插件运行后再建立子会话；解密脚本会看到外层的插件分发 Dll 字段与内层插件通信（如 shell、wallpaper）。

## 触发条件

- 已获得 AsyncRAT C2 流量的 TLS 解密能力（服务器私钥、SSLKEYLOGFILE 或已解密的 pcap），或直接拿到解密后的原始字节流。
- 流量为 AsyncRAT 该版本格式（外层 2×4 字节长度 + gzip；0.5.8 原文验证；不同版本/魔改版可能有差异）。
- 从 Wireshark 以“原始数据（Raw）”导出单向 TCP 流即可作为脚本输入。

## 利用步骤

1. 在 Wireshark 中对 C2 流 `Follow TCP Stream`，选择 server→client 或 client→server 单向的原始字节（Raw）导出。
2. 循环读取：取 4 字节小端得到压缩载荷长度，跳过 8 字节头，读该长度字节做 gzip 解压，校验解压长度。
3. 解析 MessagePack：首字节减 0x80 得键值对数量；按 fixstr/str8 读键值；遇到 `Msgpack`/`Dll` 等键时读 bin8/bin32 嵌套负载，再 gzip 解压。
4. 还原指令：输出形如 `3->Packet->ClientInfo->HWID->3817CC2D083FE3D7F266->User->admin->OS->Windows 7...`；对 DLL 校验 MZ 头并以 SHA256 命名落盘，对图片按 JPEG 头提取。
5. 汇总所有解出的 Packet 类型与插件，还原攻击者操作时间线（键记录、文件管理、桌面、密码恢复等）。

## PoC

最小 Python 解析骨架（对应原文 Go 脚本逻辑）：

```python
import gzip, struct

def frames(data):
    off = 0
    while off + 8 <= len(data):
        comp_len, raw_len = struct.unpack_from('<II', data, off)
        if off + 8 + comp_len > len(data): break
        blob = data[off+8: off+8+comp_len]
        raw = gzip.decompress(blob)
        assert len(raw) == raw_len
        yield raw
        off += 8 + comp_len

def parse_mp(buf):
    n = buf[0] - 0x80
    off, out = 1, [str(n)]
    while off < len(buf):
        b = buf[off]
        if 0xA0 <= b <= 0xBF:          # fixstr
            ln = b - 0xA0; s = buf[off+1:off+1+ln]; off += 1 + ln
        elif b == 0xD9:                 # str8
            ln = buf[off+1]; s = buf[off+2:off+2+ln]; off += 2 + ln
        elif b == 0xC4:                 # bin8: [len][raw_len:4][gzip]
            ln = buf[off+1]; payload = buf[off+2:off+2+ln]; off += 2 + ln
            s = b'<nested gzip>'; 
            if payload[:4] and payload[4:6] == b'\x1f\x8b':
                s = gzip.decompress(payload[4:])
        else:
            break
        out.append(s.decode('utf-8', 'replace') if isinstance(s, bytes) else s)
    return '->'.join(out)

for raw in frames(open('recv0','rb').read()):
    print(parse_mp(raw))
```

原文实测输出：`3->Packet->ClientInfo->HWID->3817CC2D083FE3D7F266->User->admin->OS->Windows 7 旗舰版 64bit->Path->C:\Users\admin\Desktop\AsyncClient.exe->Version->0.5.8...`；`savePlugin` 消息解出 `Miscellaneous.dll` 的 MZ 头；`wallpaper` 消息解出 JPEG 图片。原文脚本还处理 bin16/bin32、图片/ DLL 落盘与 SHA256 命名，完整代码见原文（Go，main.go + common.go）。

## 变体与关联

- 版本差异：不同 AsyncRAT 版本/魔改版可能改变长度字节序、是否 gzip 或 MessagePack 扩展类型；解析前先用 `1f8b08` 魔数与解压长度校验确认。
- 高低版本心跳不通用（见库内 AsyncRAT Ping 心跳重放卡），流量解析也需按版本区分。
- 插件子会话与主会话使用同一帧格式，但插件 DLL 通过 `savePlugin` 的 `Dll` 字段传输，可在脚本中按 `output[-2:]=='savePlugin','Dll'` 分支提取。
- 同类 .NET RAT 流量解密：EagleMonitorRAT 用 4+1 字节帧头 + QuickLZ/AES（另一卡），可对比帧结构差异。

## 检测与防御

- 检测：TCP 载荷（TLS 解密后或代理可见）中出现 `1f8b08` gzip 魔数 + 前后 4 字节长度对、MessagePack `0x8x` 键值对与 `Packet`/`ClientInfo`/`HWID` 字符串；C2 证书/JA3S 指纹、心跳 Ping 回显作为旁证。
- 防御：阻断未知 C2 域名与 IP，限制 PowerShell/脚本宿主外联；终端侧查 AsyncRAT 进程、注册表持久化与 Plugins 目录 DLL；对已捕获流量按本卡脚本解密还原攻击者操作与插件能力，评估影响范围。
- 处置：提取的 DLL/图片按 SHA256 归档，结合 YARA/AV 与情报平台确认家族与变种。
