---
id: defense-forensics-ahmyth-android-rat-socketio-c2-traffic-parse
title: AhMyth Android RAT C2 流量识别与解析：Socket.IO 明文 order 指令、x0000ca/fm/lm 等远控码与二进制附件回传
type: scenario
domain: defense
path: defense/forensics
technique: ahmyth-android-rat-socketio-c2-traffic-parse
aliases:
- AhMyth 流量分析
- AhMyth RAT C2 解析
- Android RAT Socket.IO 通信
- x0000ca 指令
- x0000fm 文件管理
- Socket.IO 明文远控流量
- 移动端远控流量取证
tags:
- forensics
- traffic-analysis
- android
- c2
- ahmyth
- rat
- socket.io
- websocket
- incident-response
cve: []
severity: high
confidence: high
affected_versions: AhMyth v1.0-beta.1（唯一 Release，2017-07-08 发布；2021-09-04 仓库归档）
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:32:13+08:00'
  notes: 已对照原文与图01-22核对：/socket.io/ 轮询握手查询串 release/model/EIO=3/id/manf、sid 与 upgrades/pingInterval 25000/pingTimeout 60000、101 升级、42 order 帧与 451- 二进制附件、x0000ca/cl/cn/fm/lm/mc/sm 指令与回显、面板默认端口 42474 均与原文抓包/截图一致；Engine.IO v3 由 EIO=3 与帧格式推出。PoC 为离线解析脚本未执行；frontmatter 无 sources/source_url；affected_versions 保留原文明确唯一 Release v1.0-beta.1。dup-scan(19:10)早于本批建卡，无涉及 pair。
---

## 一句话结论

AhMyth Android RAT 使用 Socket.IO（Engine.IO v3，先 HTTP 轮询握手再升级为 WebSocket）与操控端通信且完全不加密：上线握手 URL 直接携带机型/厂商/系统版本/Android ID，操控指令为 `42["order",{"order":"x0000ca|cl|cn|fm|lm|mc|sm",...}]`，受害端以指令码为事件名回传 JSON，照片、录音、下载文件等二进制内容以 `451-` 二进制事件附件发送；在 Wireshark 中 Follow WebSocket Stream 即可逐条还原操控者的远控操作与窃取数据。

## 原理

- **协议分层**：样本内置 Socket.IO 客户端，连接 `/socket.io/` 路径。Engine.IO 包前缀：`0` open、`2` ping、`3` pong、`4` message、`5` upgrade；Socket.IO 包前缀：`2` EVENT、`5` BINARY_EVENT。因此 `42[...]` 是「Engine.IO message(4) + Socket.IO EVENT(2) + JSON 数组」的明文事件帧，数组为 `[事件名, 载荷]`；`451-[...]` 是「message(4) + BINARY_EVENT(5) + 附件数 1 + `-` + 含 `_placeholder` 的 JSON」，真正的二进制数据紧跟其后作为独立帧发送。
- **握手与上线信息**：样本先发 `GET /socket.io/?release=<系统版本>&model=<机型>&EIO=3&id=<android_id>&transport=polling&manf=<厂商>`，服务端回 `{"sid":...,"upgrades":["websocket"],"pingInterval":25000,"pingTimeout":60000}`，随后带 `sid` 以 `transport=websocket` 升级（101 Switching Protocols）。查询串里的四个字段就是受害设备身份：`model`=Build.MODEL、`manf`=Build.MANUFACTURER、`release`=Build.VERSION.RELEASE、`id`=Settings.Secure 的 android_id。Host 头直接暴露 C2 的 IP:端口。
- **指令通道**：操控端向受害端 emit `order` 事件，载荷是 `{"order":"x0000xx","extra":...,"path":...}`；受害端处理完后以「指令码本身」为事件名回传结果。指令码即功能路由：

  | 指令码 | 功能 | 请求示例（载荷要点） | 响应形态 |
  | --- | --- | --- | --- |
  | x0000ca | 摄像头 | `extra:"camList"` 列摄像头；`extra:1` 拍照 | `{"camList":true,"list":[...]}`；拍照为 `451-` 二进制附件 |
  | x0000cl | 通话记录 | 无 extra | `{"callsList":[...]}` |
  | x0000cn | 通讯录 | 无 extra | `{"contactsList":[...]}` |
  | x0000fm | 文件管理 | `extra:"ls","path":"/"` 列目录；`extra:"dl","path":"//sdcard/Download/2075.jpg"` 下载 | 目录数组；下载为 `451-` 二进制附件 |
  | x0000lm | 定位 | 无 extra | `{"enable":true,"lat":...,"lng":...}` |
  | x0000mc | 麦克风 | 录音后回传 | `{"file":true,"name":...}` + `451-` 二进制附件 |
  | x0000sm | 短信 | `extra:"ls"` 列短信 | `{"smsList":[...]}` |

- **为什么可离线还原**：Socket.IO 事件默认 JSON 序列化且样本未启用 TLS/自定义加密，指令码与字段名固定；二进制附件只是在 JSON 中用 `{"_placeholder":true,"num":N}` 占位，按序对齐即可提取文件。这使得仅凭一份 PCAP 就能重建攻击者执行过的每一条命令及被窃取的内容类型。

## 触发条件

- 已捕获受害 Android 设备与 C2 之间的完整双向流量（企业出口镜像、热点抓包、模拟器抓包或沙箱 PCAP），且中间无 TLS 解密障碍（该家族默认明文）。
- 会话包含 HTTP 轮询握手阶段，或在 WebSocket 阶段包含载荷帧；仅有 TCP 握手无法还原内容。
- 分析者能识别 Socket.IO/Engine.IO 帧格式，或直接使用 Wireshark 的 Follow WebSocket Stream。
- 若样本被改版为 wss/自定义加密，则需先从样本中提取密钥或 hook 发送函数，本卡的明文解析不再直接适用。

## 利用步骤

1. **定位会话**：PCAP 中过滤 `http.request.uri contains "/socket.io/"`，记录 Host（C2 IP:端口）与首个轮询请求的查询串；默认监听端口线索为 42474（面板默认），实际端口由生成样本时的 Source IP/Port 决定。
2. **提取上线身份**：从首个 `GET /socket.io/?...` 的 `model`/`manf`/`release`/`id` 字段读出机型、厂商、系统版本与 Android ID；用 android_id 关联同一设备的多条会话与多次重连。
3. **切到 WebSocket 载荷**：在 Wireshark 中对会话 Follow → WebSocket Stream（或对 `websocket` 过滤后导出载荷），看到 `42["order",...]` 即为明文指令帧。
4. **还原指令时间线**：`42["order",{"order":"x0000..."}]` 为操控端→受害端；`42["x0000...",...]` 为受害端→操控端回显。按指令码翻译功能（见上表），得到「列目录→下载文件→拍照→录音→拉通讯录/短信/通话记录/定位」的操作序列。
5. **提取二进制附件**：在 `451-[...]` 帧中读 `name` 与 `buffer._placeholder/num`，按 `num` 顺序把后续二进制帧拼回文件；照片可按 JPEG `FF D8 ... FF D9`、录音按 MP3/容器头校验。Wireshark 若把二进制帧显示为乱码，可导出原始 WebSocket 帧后按帧序切分。
6. **关联静态样本**：用包名、权限与 `IOSocket`/`ConnectionManager` 字符串确认 APK 家族，把握手字段（android_id、机型）与设备清单对应，评估受影响设备范围。

## PoC

从 Wireshark 导出的 WebSocket 文本载荷中离线解析事件（不连接任何 C2）：

```python
import json

decoder = json.JSONDecoder()

def parse_events(text):
    """从 Follow WebSocket Stream 导出的文本中提取 42[event, payload] 帧"""
    i = 0
    while True:
        i = text.find("42[", i)
        if i < 0:
            return
        try:
            arr, end = decoder.raw_decode(text, i + 2)
        except json.JSONDecodeError:
            i += 1
            continue
        yield arr
        i = end

for event, payload in parse_events(open("ws_payload.txt", encoding="utf-8", errors="replace").read()):
    if event == "order":
        print("C2 -> victim:", payload)
    elif isinstance(event, str) and event.startswith("x0000"):
        print("victim -> C2:", event, payload)
```

辅助命令：

```bash
# 列出所有 Socket.IO 握手请求（C2 地址与上线身份字段）
tshark -r ahmyth.pcap -Y 'http.request.uri contains "/socket.io/"' \
  -T fields -e frame.number -e ip.dst -e tcp.dstport -e http.request.full_uri

# 确认 WebSocket 升级与后续帧
tshark -r ahmyth.pcap -Y 'websocket or http.response.code == 101'
```

`451-` 二进制事件的附件内容不在 JSON 文本里，需按 Wireshark 帧序将 JSON 占位符 `num` 与后续二进制帧一一对应后另存。

## 变体与关联

- **变体（构建期）**：生成器可改 C2 IP/端口，并支持把恶意载荷捆绑进正常 APK；包名/类名在改版中可能被替换，流量特征比静态特征更稳定。
- **变体（协议期）**：改版可能启用 `wss://`、加自定义加密或更换事件名；判断要点仍是 `/socket.io/` 握手、Engine.IO 查询参数与固定指令码。
- **误报边界**：正常业务也会用 Socket.IO，但握手查询串同时携带 `model`/`manf`/`release`/`id` 且后续出现 `x0000xx` 指令码时基本可判定为该家族。
- 关联：[[mobile-android-ahmyth-rat-static-command-map]]（同一样本的静态结构与指令分派）、[[defense-forensics-njrat-c2-traffic-base64-decode]]（Windows 远控的明文分隔符协议）、[[defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt]]（XOR 混淆型远控流量）、[[mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2]]（Android RAT 的 gzip over TCP 通信）。

## 检测与防御

- **网络检测**：NDR/IDS 规则匹配 URI `/socket.io/` 且查询串同时含 `model=`、`manf=`、`release=`、`id=`；匹配 WebSocket 明文中的 `42["order"` 与 `x0000ca`/`x0000cl`/`x0000cn`/`x0000fm`/`x0000lm`/`x0000mc`/`x0000sm`；对“裸 IP + 非标准端口 + 长连接 WebSocket”告警。
- **主机检测**：核对应用包名 `ahmyth.mine.king.ahmyth`（未改包时）、MainService/BOOT_COMPLETED 接收器与高危权限组合；详见静态卡。
- **取证要点**：优先保全完整双向 PCAP 与设备镜像；把 android_id 与机型建立设备映射，便于批量识别同一操控端下的多台受害设备；导出的照片/录音/文件按时间排序即攻击者窃取时间线。
- **响应**：隔离设备、卸载样本、重置在该设备登录过的账号口令；按已回传的通讯录/短信/文件范围评估数据泄露并通知受害者；封锁 C2 地址与端口。
