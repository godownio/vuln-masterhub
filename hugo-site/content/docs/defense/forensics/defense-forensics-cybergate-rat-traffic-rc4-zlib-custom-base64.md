---
id: defense-forensics-cybergate-rat-traffic-rc4-zlib-custom-base64
title: CyberGate RAT 通信解密：7c0a 长度帧 + RC4 固定 key + zlib 魔标，与自定义字符集 Base64 的 0d0a 帧
type: scenario
domain: defense
path: defense/forensics
technique: cybergate-rat-traffic-rc4-zlib-custom-base64
tags:
- forensics
- traffic-analysis
- rat
- delphi
- rc4
- zlib
- base64
- c2
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:47:58+08:00'
  notes: '已对照原文与22张图核对：7c0a 前 ASCII 十进制长度帧（图19 34| 0x22）、RC4 key njgnjvejvorenwtrnionrionvironvrnvcg230、@@XXXXXXXXXX@@（4040+10×58+4040）魔标后 zlib 解压、Client→Server 自定义字符集 Base64（0123...+/ 无padding）+ ###@@@ + 0d0a 帧尾、maininfo|cybergate|1142332o10Ep4geFNmYWvy8Jx2ad3ws| 与 ping/pong 示例（图20）、C Arrays 导出流程（图21）均与原文一致；与 EagleMonitorRAT/Xeno/NjRAT 等帧格式与算法不同，dedup top 候选 related/new，非重复。原文未标受影响版本，affected_versions 留空正确。未验证点：Python PoC 未在本机 pcap 复跑（原文 Go 脚本仅展示输出）。frontmatter 无 sources/source_url。'
url: /docs/defense/forensics/defense-forensics-cybergate-rat-traffic-rc4-zlib-custom-base64/
draft: false
kb_aliases:
- CyberGate 流量解密
- CyberGate 通信协议
- 7c0a 帧
- '@@XXXXXXXXXX@@ 魔标'
- CyberGate 自定义 Base64
- '###@@@ 帧尾'
---

## 一句话结论

CyberGate RAT 不使用 TLS，而是裸 socket：服务端→客户端帧为「ASCII 十进制长度 + `7c0a` + RC4（固定 key）+zlib 密文」，解密后以 `@@XXXXXXXXXX@@` 魔标开头；客户端→服务端帧为「自定义字符集 Base64 + `###@@@` + `0d0a`」，所有包以 `0d0a` 结尾。按两个方向分别写解密器，即可批量还原 C2 指令、主机信息与外传数据。

## 原理

- **分帧规则**：Server→Client 方向，明文的十进制长度字符串（例 `"34"`，即 0x22 字节）后跟 `0x7c0a`，再接该长度的密文；长度表示密文字节数。Client→Server 方向，所有包以 `0x0d0a` 结尾；若末尾为 `###@@@` + `0d0a`，则 `###@@@` 之前是 Base64 密文，否则按明文处理。
- **Server→Client 加密**：RC4，key 为固定字符串 `njgnjvejvorenwtrnionrionvironvrnvcg230`；解密后先去掉魔标 `@@XXXXXXXXXX@@`（14 字节，十六进制 `4040` + 10 个 `58` + `4040`），剩余为 zlib 数据（以 `7801` 开头），解压得到文本，例如 `cybergate|Y|`。图片数据解压后以 `imgdesk|` 开头，后接图片字节。
- **Client→Server 编码**：Base64 变体，字符表为 `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/`（数字在前，`+` `/` 结尾），无 padding；按该字符表映射回标准 Base64 解码即得明文，例如 `maininfo|cybergate|1142332o10Ep4geFNmYWvy8Jx2ad3ws|`。
- **为什么可直接解**：密钥与字符表都硬编码在木马端/控制端，属于对称静态密钥，不依赖握手协商；解密时只需正确处理长度前缀与结束符。
- **离线批量处理**：在 Wireshark 中把 TCP 流按方向导出（Right-click → Show data as → C Arrays），再按 `7c0a`/`0d0a` 拼接切分，可批量解密整段会话；原文的 Go 脚本即按此流程实现，并额外把 `imgdesk|` 图片按 MD5 命名保存。
- **会话示例**：Client→Server 的 `maininfo|...`（上线信息）、`ping`；Server→Client 的 `pong|Program Manager###31294|`；配置串（C2、安装参数）也出现在会话内容中。

## 触发条件

- 取得 CyberGate RAT 的 pcap 或主机侧抓取的流量（明文 socket，非 TLS）；能把 TCP 流按方向导出为字节数组/十六进制。
- 样本使用默认通信模块：RC4 key、自定义 Base64 字符表、魔标与帧尾未被修改。
- 分析环境具备 RC4、zlib 与 Base64 解码能力（标准库即可）。

## 利用步骤

1. 在 Wireshark 中打开 pcap，按 TCP 流过滤，区分 server→client 与 client→server，导出 raw 或 C Arrays。
2. Server→Client：定位 `0x7c0a`，其前面的 ASCII 数字转十进制得到长度 L；取其后 L 字节作为密文。
3. 用 RC4 key `njgnjvejvorenwtrnionrionvironvrnvcg230` 解密；校验以 `@@XXXXXXXXXX@@` 开头，去掉后 zlib 解压。
4. Client→Server：检查包尾 `0x0d0a`；若前面 6 字节为 `###@@@`，取更前面的内容按自定义字符表做 Base64 解码；否则按明文输出。
5. 若解出 `imgdesk|` 数据，按 MD5 命名保存图片；其他内容按文本输出并归档。
6. 汇总解密出的 C2 地址、上线主机信息、指令序列与 FTP 凭据，用于取证、溯源与影响范围评估。

## PoC

最小 Python 解密片段：

```python
import base64, zlib
from Crypto.Cipher import ARC4

RC4_KEY = b"njgnjvejvorenwtrnionrionvironvrnvcg230"
MAGIC = b"@@XXXXXXXXXX@@"
CUSTOM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
STD    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TRANS  = str.maketrans(CUSTOM, STD)

def server_to_client(frame: bytes) -> bytes:
    i = frame.index(b"\x7c\x0a")
    n = int(frame[:i].decode())                 # ASCII 十进制长度
    ct = frame[i + 2:i + 2 + n]
    pt = ARC4.new(RC4_KEY).decrypt(ct)
    assert pt.startswith(MAGIC)
    return zlib.decompress(pt[len(MAGIC):])

def client_to_server(frame: bytes) -> bytes:
    assert frame.endswith(b"\r\n")
    body = frame[:-2]
    if body.endswith(b"###@@@"):
        body = body[:-6]
        s = body.decode().translate(TRANS)
        return base64.b64decode(s + "=" * (-len(s) % 4))
    return body                                 # 未加密的明文包
```

## 变体与关联

- **改版变种**：RC4 key、Base64 字符表、魔标或帧尾都可被重新编译修改；先在样本中定位字符串 `njgnjvejvorenwtrnionrionvironvrnvcg230` 与 `@@XXXXXXXXXX@@`，再套用对应解密。
- **解析细节**：长度字段是十进制 ASCII 而非二进制；跨 TCP 段时需先按长度缓存拼接再解密，不能按单包处理。
- **同模式家族**：Xeno-RAT、EagleMonitorRAT、NjRAT 等的流量解密同样是“分帧 + 对称解密 + 压缩”模式，可复用同一分析框架。
- 静态配置提取见 [[code-analysis-reverse-windows-cybergate-rat-config-resource-xor-extract]]。
- 边界：仅限授权事件响应与恶意样本分析；解出的图片/文件按证据规范保存。

## 检测与防御

- **网络检测**：TCP 载荷出现 `7c0a` 前导的十进制长度、`@@XXXXXXXXXX@@` 魔标、`###@@@` + `0d0a` 帧尾或固定 RC4 key 字符串，可作为 IDS/Suricata 规则特征。
- **主机关联**：结合配置中的 Mutex、安装注册表键与远程线程注入行为判断感染；解出的 C2/FTP 地址作为 IOC。
- **防御**：禁止不可信来源程序执行、限制出网；该协议为明文传输，TLS 检查不适用，需依赖协议特征与主机行为；确认感染后隔离主机并解密流量评估数据外传范围。
