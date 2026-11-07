---
id: defense-forensics-adaptixc2-beacon-http-rc4-session-key-traffic-decrypt
title: AdaptixC2 BeaconHTTP 流量解密：DB 取 Listener EncryptKey、RC4 解心跳提 SessionKey 再还原命令与回显
type: scenario
domain: defense
path: defense/forensics
technique: adaptixc2-beacon-http-rc4-session-key-traffic-decrypt
tags:
- adaptixc2
- c2
- forensics
- traffic-analysis
- rc4
- beacon
- http
- session-key
- pcap
- tls
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:18:23+08:00'
  notes: 已对照原文与全部 35 张图核对：Listener URI /api/dns、POST、Heartbeat Header x-nws-log-uuid；DB Listeners.CustomData 中 encrypt_key=kJiY+eNoaq/j8VvSHUOl0Q==（Base64/16B）；心跳 RC4 解出 Agent Type/ID、8×4B flags、Hostname DESKTOP-K196DPF、Administrator、agent.x64.exe；偏移 36 取 SessionKey（脚本实测 810a4121790771bda0069a13486ba747）；data 字段 JSON 原样嵌入、Content-Type octet-stream；用 SessionKey RC4 依次还原 C:\Windows\System32\cmd.exe /c whoami 与 desktop-k196dpf\administrator；短包长度 59/57、按 4B 大端分帧一致。卡内脚本未对真实包复跑。
url: /docs/defense/forensics/defense-forensics-adaptixc2-beacon-http-rc4-session-key-traffic-decrypt/
draft: false
kb_aliases:
- AdaptixC2 listener_beacon_http 流量解密
- AdaptixC2 心跳包 RC4 解密
- x-nws-log-uuid 解密
- AdaptixC2 SessionKey 提取
- AdaptixC2 data 字段解密
- AdaptixC2 HTTP Beacon 取证
---

## 一句话结论

AdaptixC2 的 `listener_beacon_http` 通信可用“Listener EncryptKey → 心跳包 → SessionKey”两级 RC4 还原：心跳包放在自定义请求头（默认 `x-nws-log-uuid`）中，值是 `Base64(RC4(EncryptKey, beat))`，`EncryptKey` 是创建 Listener 时随机生成的 16 字节密钥并明文存于服务端数据库；解出心跳后，在插件 beat 的偏移 36 处按 4 字节大端长度前缀取出 SessionKey，之后响应 JSON 的 `data` 字段与 Agent 上传的二进制请求体都用该 SessionKey 做 RC4，按 4 字节大端总长度分帧、解析任务/命令 ID 即可得到下发命令与执行回显（原文实测还原出 `C:\Windows\System32\cmd.exe /c whoami` 与 `desktop-k196dpf\administrator`）。

## 原理

- **Listener 密钥**：`listener_beacon_http` 创建 Listener 时用 `rand.Read` 生成 16 字节随机 `EncryptKey`，写入 `HTTPConfig.EncryptKey` 并随 Listener 配置持久化到 `adaptixserver.db` 的 `Listeners.CustomData`（JSON 中的 `encrypt_key`，Base64 编码）。该密钥只用于心跳头这一层。
- **心跳包结构**：Agent 以 `POST <uri>`（原文为 `/api/dns`）发送心跳，请求头名由 Listener 配置的 `ParameterName` 决定，原文默认 `x-nws-log-uuid`。服务端取该头值做 Base64 解码，再用 `EncryptKey` 做 RC4 解密：
  - 前 4 字节：Agent Type（大端 uint32）；
  - 次 4 字节：Agent ID（大端 uint32）；
  - 之后 32 字节：8 个 4 字节大端 Flags 字段，非零字段被记录；
  - 再往后：若干“4 字节大端长度 + 内容”的字符串，依次为 Hostname、Username、Executable。
- **SessionKey 的位置**：服务端把去掉前 8 字节（Agent Type/ID）后的数据交给 Agent 插件 `CreateAgent` 解析。插件按 `Packer` 顺序读取：Sleep(4)、Jitter(4)、KillDate(4)、WorkingTime(4)、ACP(2)、OemCP(2)、GmtOffset(1)、Pid(2)、Tid(2)、BuildNumber(4)、MajorVersion(1)、MinorVersion(1)、InternalIP(4)、Flag(1)，合计 36 字节；偏移 36 处紧接着是“4 字节大端长度 + SessionKey 字节”，其后才是 Domain、Computer、Username、Process 等长度前缀字符串。因此只要解开心跳，就能拿到后续通信的 SessionKey。
- **响应 `data` 字段**：C2 回包是一个形如 `{"status": "ok", "data": "<原始二进制>", "metrics": "sync"}` 的 JSON。`data` 来自 `TsAgentGetHostedAll` 返回的 `[]byte`，被 `string(responseData)` 直接拼进模板，未做 Base64 或 JSON 转义；`data` 非空时响应 `Content-Type` 变为 `application/octet-stream`。`data` 的生成链为：任务队列 → `ExAgentPackData` → Agent 插件 `AgentPackData` → `PackTasks` 序列化 → `AgentEncryptData`，而 `AgentEncryptData` 就是 `RC4Crypt(data, SessionKey)`。
- **上传包**：Agent 取得任务后，会用 SessionKey 加密命令请求体和执行结果请求体，放在 HTTP 请求体（二进制，`Content-Length` 与任务长度相关）中发送；同样按包长度前缀切分即可还原命令与回显。
- **分帧格式**：`PackTasks` 每个包以 4 字节大端总长度开头，随后是任务 ID（4 字节）与命令 ID（4 字节），其余为命令参数/结果数据；原文脚本观察到的 ID 字节序为小端（脚本按 `<I` 读取后再反转打印）。字符串内容可能带 UTF-16LE/UTF-8 与 NUL 填充，原文提到 `data` 左右的 `00` 或多字符填充可能是为规避流量审查。
- **为什么成立**：整条链路只用对称密钥，Listener Key 与 SessionKey 都不具备前向保密，Listener Key 还明文存在服务端数据库；只要拿到 pcap（并完成 TLS 解密）加上数据库或 Agent 静态配置中的 Listener Key，就能离线解密全部历史任务与回显。

## 触发条件

- 捕获到 AdaptixC2 BeaconHTTP Agent 的 HTTPS 回连流量（pcap / mitmproxy 转储），且已完成 TLS 解密（中间人代理或 SSLKEYLOGFILE）；
- 能读取 Teamserver 的 `adaptixserver.db`（拿到 `Listeners.CustomData` 中的 Base64 `encrypt_key`），或能从 Agent 样本静态提取同一个 Listener Key；
- 有 AdaptixC2 v0.8 源码用于确认字段顺序（原文分析环境为 `AdaptixC2_main_v0.8`，不作为受影响版本标记）；
- 运行环境具备 Python 与 pycryptodome（或自实现 RC4）。

## 利用步骤

1. 配置 TLS 解密：客户端运行 `mitmproxy --listen-port 8080 --ssl-insecure --set ssl_version_client=TLSv1_2 -w output.mitm`，Wireshark 配置 `sslkeys.log`，随后运行 Agent，使 HTTPS 流量变为可读的 HTTP 明文。
2. 打开 `adaptixserver.db`，在 `Listeners` 表的 `CustomData` JSON 中取 `encrypt_key`（Base64）；解码得到 16 字节 RC4 密钥。
3. 抓取心跳请求，复制 `x-nws-log-uuid` 头值，Base64 解码后用 Listener Key 做 RC4 解密；按前 8 字节解析 Agent Type/ID，再解析 8 个 Flag 和 Hostname/Username/Executable。
4. 去掉解密结果前 8 字节，从偏移 36 读取 4 字节大端长度并取出 SessionKey。
5. 找到 `data` 字段非空、`Content-Type: application/octet-stream` 的响应，取 `{"status": "ok", "data": "` 与 `", "metrics": "sync"}` 之间的原始字节，用 SessionKey 做 RC4；按 4 字节大端总长度逐包解析，读取任务 ID/命令 ID 与数据，得到下发命令。
6. 对 Agent 后续请求体（如 `Content-Length` 为 59/57 的二进制包）重复第 5 步，先还原“待执行命令”，再还原“执行结果”。
7. 将提取出的可打印字符串按 UTF-16LE/UTF-8 尝试解码，并忽略 NUL 填充。

## PoC

以下为按原文结构重写的最小脚本（未在本机对真实样本执行）：

```python
import base64, struct, re
from Crypto.Cipher import ARC4

def rc4(key: bytes, data: bytes) -> bytes:
    return ARC4.new(key).encrypt(data)

def parse_beat(header_b64: str, listener_key: bytes):
    beat = rc4(listener_key, base64.b64decode(header_b64))
    agent_type, agent_id = struct.unpack(">II", beat[:8])
    info = beat[8:]                      # 交给 Agent 插件的数据
    flags = [struct.unpack(">I", info[i:i+4])[0] for i in range(0, 32, 4)]
    off, strings = 32, []
    while off + 4 <= len(info):
        ln = struct.unpack(">I", info[off:off+4])[0]
        off += 4
        if ln == 0 or off + ln > len(info):
            break
        strings.append(info[off:off+ln].decode("utf-8", "ignore").strip("\x00"))
        off += ln
    return agent_type, agent_id, flags, strings, info

def get_session_key(info: bytes) -> bytes:
    ln = struct.unpack(">I", info[36:40])[0]   # 36 字节固定字段之后
    return info[40:40+ln]

def parse_packets(dec: bytes):
    off = 0
    while off + 4 <= len(dec):
        total = struct.unpack(">I", dec[off:off+4])[0]
        if total < 8 or off + total > len(dec):
            break
        payload = dec[off+4:off+total]
        task_id, cmd_id = struct.unpack("<II", payload[:8])
        readable = [s.decode("utf-8", "ignore") for s in re.findall(rb"[ -~]{4,}", payload)]
        print(f"task=0x{task_id:08x} cmd=0x{cmd_id:08x} strings={readable}")
        off += total

# 用法示例：
# lk = base64.b64decode("<Listeners.CustomData 中的 encrypt_key>")
# at, aid, flags, strings, info = parse_beat("<x-nws-log-uuid 头值>", lk)
# sk = get_session_key(info)
# parse_packets(rc4(sk, bytes.fromhex("<data 字段或请求体的十六进制>")))
```

## 变体与关联

- **密钥来源变体**：除从 `adaptixserver.db` 取 `encrypt_key` 外，也可从 Agent 样本的静态 Profile 中提取同一个 Listener Key，见 [[defense-forensics-adaptixc2-http-beacon-profile-rc4-extract]]；两卡一个针对二进制配置、一个针对在线流量，层级不同。
- **Listener 类型变体**：Gopher TCP 使用 `[16B Listener Key][12B nonce][AES-GCM(msgpack)]` 与 INIT_PACK 会话密钥，格式完全不同，见 [[defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt]]；不要套用本卡的 RC4 分帧脚本。
- **攻击侧配置**：AdaptixC2 HTTP Listener 可把心跳头名、URI、UA 改成业务流量样式，见 [[pentest-c2-adaptixc2-http-listener-router-traffic-masquerade]]；改的只是外层特征，不影响本卡的解密流程。
- **同类思路**：Cobalt Strike Beacon 的流量解密同样依赖从服务器/样本取得密钥后离线解元数据，见 [[defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt]]。

## 检测与防御

- **本卡性质**：这是 C2 取证与流量还原方法，不是攻击面；防御重点是检测与响应。
- **流量检测**：关注固定间隔的 `POST`（原文约数秒一次）、自定义可疑心跳头（如 `x-nws-log-uuid`）、`Content-Type: application/octet-stream` 的 JSON/二进制混合响应、以及请求体长度短且高熵的二进制 POST；结合 JA3/JA4 与 URI 频率做告警。
- **主机与服务器侧**：监控 AdaptixC2 Teamserver 的 `adaptixserver.db` 落地、Listener 配置写入与随机 16 字节 `encrypt_key`；对异常出站连接做阻断与狩猎。
- **取证加固**：完整保存 pcap 与 TLS 密钥日志；优先从数据库或 Agent 样本恢复 Listener Key，再按本卡步骤解出 SessionKey 与任务；对解出的命令/回显做时间线关联。
- **攻击面收敛**：该框架的密钥只做对称保护且 Listener Key 明文落库，防守方无法通过算法强度阻止取证，应把重点放在 C2 流量发现、样本捕获与基础设施溯源。
